#!/usr/bin/env python3
# coreutils-secdiff: security-semantics differential test, GNU coreutils vs uutils.
# SPDX-License-Identifier: Apache-2.0
# Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).
"""Run every scenario in scenarios.py against GNU coreutils and uutils coreutils on the
same machine (Ubuntu 26.10 ships both: uutils as the default, GNU as gnu-prefixed
binaries), each in a fresh fixture, and compare the resulting filesystem state, exit
status and (with strace) the order of permission-setting system calls.

Must run as root inside a throwaway container. Every path it touches is under
/tmp/secdiff and /dev/shm/secdiff. Usage: python3 secdiff.py --out /out
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analysis as A  # noqa: E402
import scenarios as SC  # noqa: E402

VERSION = "0.1.0"
USER = "secdiffuser"
BASE_ROOT = "/tmp/secdiff"
X_ROOT = "/dev/shm/secdiff"
TRACE_DIR = "/tmp/secdiff-traces"
TIMEOUT = 15
ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "HOME": "/tmp",
}
TRACE_SETS = [
    "open,openat,openat2,creat,mkdir,mkdirat,mknod,mknodat,chmod,fchmod,fchmodat,fchmodat2,"
    "chown,fchown,lchown,fchownat,umask,rename,renameat,renameat2",
    "openat,mkdirat,mknodat,chmod,fchmod,fchmodat,chown,fchown,lchown,fchownat,umask,renameat,renameat2",
    "openat,mkdirat,mknodat,fchmod,fchmodat,fchown,fchownat,umask,renameat",
]
TYPES = {stat.S_IFREG: "f", stat.S_IFDIR: "d", stat.S_IFLNK: "l", stat.S_IFIFO: "p",
         stat.S_IFCHR: "c", stat.S_IFBLK: "b", stat.S_IFSOCK: "s"}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def quick(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=ENV)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:  # noqa: BLE001
        return -1, "", repr(e)


# ------------------------------------------------------------------ environment
def ensure_user():
    import pwd
    try:
        pw = pwd.getpwnam(USER)
    except KeyError:
        for cmd in (["useradd", "-M", "-U", "-u", "1001", "-s", "/bin/sh", USER],
                    ["useradd", "-M", "-U", "-s", "/bin/sh", USER]):
            if quick(cmd)[0] == 0:
                break
        pw = pwd.getpwnam(USER)
    return pw.pw_uid, pw.pw_gid


def first_line(path):
    rc, out, _err = quick([path, "--version"], timeout=10)
    lines = out.strip().splitlines()
    return lines[0] if lines else ""


def dpkg_list(pkg):
    rc, out, _ = quick(["dpkg", "-L", pkg])
    return out.splitlines() if rc == 0 else []


def discover(tools):
    gnu_files = []
    for pkg in ("gnu-coreutils", "coreutils-from-gnu", "coreutils"):
        gnu_files += dpkg_list(pkg)
    paths, versions = {"gnu": {}, "uu": {}}, {"gnu": {}, "uu": {}}
    for t in tools:
        cands = ["/usr/bin/gnu" + t, "/bin/gnu" + t]
        cands += [f for f in gnu_files if os.path.basename(f) in ("gnu" + t, t)]
        for c in cands:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                v = first_line(c)
                if "GNU coreutils" in v:
                    paths["gnu"][t], versions["gnu"][t] = c, v
                    break
        c = "/usr/lib/cargo/bin/coreutils/" + t
        if os.path.exists(c):
            v = first_line(c)
            if "uutils" in v.lower():
                paths["uu"][t], versions["uu"][t] = c, v
    return paths, versions


def pick_trace_set():
    if shutil.which("strace", path=ENV["PATH"]) is None:
        return None, "strace not installed"
    last = ""
    for ts in TRACE_SETS:
        rc, _o, err = quick(["strace", "-f", "-qq", "-y", "-o", "/dev/null", "-e", "trace=" + ts, "--", "/bin/sh", "-c", ":"])
        if rc == 0:
            return ts, ""
        last = err.strip()[-300:]
    return None, last


# ------------------------------------------------------------------ fixture + snapshot
def build_fixture(base, xdir, uid, gid):
    for p in (base, xdir):
        if os.path.lexists(p):
            shutil.rmtree(p, ignore_errors=True)
    os.makedirs(base)
    os.makedirs(xdir)
    owner = {"U": uid, "R": 0}
    group = {"U": gid, "R": 0}
    for rel, kind, _mode, _o, _g, data in SC.FIXTURE:
        p = os.path.join(base, rel)
        if kind == "d":
            os.mkdir(p, 0o700)
        elif kind == "f":
            with open(p, "w") as fh:
                fh.write(data)
        elif kind == "h":
            os.link(os.path.join(base, data), p)
        elif kind == "l":
            os.symlink(data.replace("{B}", base), p)
        elif kind == "p":
            os.mkfifo(p, 0o600)
    for rel, kind, _mode, o, g, _data in SC.FIXTURE:
        if kind != "h":
            os.lchown(os.path.join(base, rel), owner[o], group[g])
    for rel, kind, mode, _o, _g, _data in reversed(SC.FIXTURE):
        if kind not in ("h", "l"):
            os.chmod(os.path.join(base, rel), mode)
    os.chmod(base, 0o755)
    os.chown(xdir, uid, gid)
    os.chmod(xdir, 0o755)


def snapshot(base, xdir, uid_map, gid_map, repl):
    snap, inodes = {}, {}
    for label, root in (("", base), ("<X>/", xdir)):
        if not os.path.isdir(root):
            snap[label + "<missing-root>"] = {"type": "missing"}
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            for name in sorted(dirnames + filenames):
                full = os.path.join(dirpath, name)
                rel = A.normalize_text(label + os.path.relpath(full, root), [])
                try:
                    st = os.lstat(full)
                except FileNotFoundError:
                    continue
                typ = TYPES.get(stat.S_IFMT(st.st_mode), "?")
                e = {"type": typ, "uid": uid_map.get(st.st_uid, str(st.st_uid)),
                     "gid": gid_map.get(st.st_gid, str(st.st_gid))}
                if typ != "l":
                    e["mode"] = stat.S_IMODE(st.st_mode)
                if typ == "f":
                    e["size"] = st.st_size
                    try:
                        with open(full, "rb") as fh:
                            e["sha"] = hashlib.sha256(fh.read()).hexdigest()[:16]
                    except OSError as ex:
                        e["sha"] = "unreadable:" + type(ex).__name__
                    if st.st_nlink > 1:
                        inodes.setdefault((st.st_dev, st.st_ino), []).append(rel)
                if typ == "l":
                    e["target"] = A.normalize_text(os.readlink(full), repl)
                snap[rel] = e
    for rels in inodes.values():
        canon = min(rels)
        for r in rels:
            snap[r]["hl"] = canon
    return snap


def abs_state(base, xdir):
    """(set of absolute paths, {abs path: permission bits}) for trace analysis."""
    paths, modes = set(), {}
    for root in (base, xdir):
        if not os.path.isdir(root):
            continue
        paths.add(root)
        for dirpath, dirnames, filenames in os.walk(root):
            for name in dirnames + filenames:
                full = os.path.join(dirpath, name)
                try:
                    st = os.lstat(full)
                except FileNotFoundError:
                    continue
                paths.add(full)
                if not stat.S_ISLNK(st.st_mode):
                    modes[full] = stat.S_IMODE(st.st_mode)
    return paths, modes


# ------------------------------------------------------------------ running
def run_cmd(argv, cwd, user, umask, stdin, uid, gid, trace_file=None, trace_set=None):
    full = list(argv)
    if user == "user":
        full = ["setpriv", "--reuid=%d" % uid, "--regid=%d" % gid, "--init-groups", "--"] + full
    if trace_file:
        full = ["strace", "-f", "-qq", "-y", "-s", "4096", "-o", trace_file,
                "-e", "trace=" + trace_set, "--"] + full
    old = os.umask(umask)
    try:
        p = subprocess.Popen(full, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=ENV, start_new_session=True)
    finally:
        os.umask(old)
    try:
        out, err = p.communicate((stdin or "").encode(), timeout=TIMEOUT)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = p.communicate()
        rc = "timeout"
    return rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def expand(args, base, xdir):
    return [a.replace("{X}", xdir).replace("{B}", base).replace("{USER}", USER) for a in args]


def one_side(sc, impl_label, tool_path, ids, trace_set, keep_trace):
    uid, gid = (0, 0) if sc["user"] == "root" else (ids["uid"], ids["gid"])
    uid_map = {0: "root", ids["uid"]: "user"}
    gid_map = {0: "root", ids["gid"]: "user"}
    tag = sc["id"].replace("@", "_")
    base = os.path.join(BASE_ROOT, impl_label, tag)
    xdir = os.path.join(X_ROOT, impl_label, tag)
    repl = [(base, "<B>"), (xdir, "<X>"), (tool_path, "<T>")]
    build_fixture(base, xdir, uid, gid)
    pre = snapshot(base, xdir, uid_map, gid_map, repl)
    argv = [tool_path] + expand(sc["args"], base, xdir)
    t0 = time.time()
    rc, out, err = run_cmd(argv, os.path.join(base, sc["cwd"]), sc["user"], sc["umask"],
                           sc["stdin"], uid, gid)
    secs = round(time.time() - t0, 3)
    post = snapshot(base, xdir, uid_map, gid_map, repl)
    side = {"rc": rc, "secs": secs,
            "stdout": A.normalize_text(out, repl)[:600],
            "stderr": A.normalize_text(err, repl)[:600]}
    shutil.rmtree(base, ignore_errors=True)
    shutil.rmtree(xdir, ignore_errors=True)

    if trace_set:
        tbase, txdir = base + "-t", xdir + "-t"
        trepl = [(tbase, "<B>"), (txdir, "<X>"), (tool_path, "<T>")]
        build_fixture(tbase, txdir, uid, gid)
        pre_paths, _ = abs_state(tbase, txdir)
        tfile = os.path.join(TRACE_DIR, "%s-%s.txt" % (impl_label, tag))
        targv = [tool_path] + expand(sc["args"], tbase, txdir)
        trc, _o, _e = run_cmd(targv, os.path.join(tbase, sc["cwd"]), sc["user"], sc["umask"],
                              sc["stdin"], uid, gid, trace_file=tfile, trace_set=trace_set)
        _, final_modes = abs_state(tbase, txdir)
        try:
            with open(tfile, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            lines = []
        tr = A.analyze_trace(lines, os.path.join(tbase, sc["cwd"]), sc["umask"],
                             pre_paths=pre_paths, final_modes=final_modes, roots=(tbase, txdir))
        side["trace"] = A.normalize_trace_result(tr, trepl)
        side["trace"]["rc"] = trc
        keep_trace[(impl_label, sc["id"])] = (tfile, trepl)
        shutil.rmtree(tbase, ignore_errors=True)
        shutil.rmtree(txdir, ignore_errors=True)
    return side, pre, post


def compare(sc, paths, ids, trace_set, keep_trace, left="gnu", right="uu", right_paths=None):
    right_paths = right_paths or paths[right]
    g, gpre, gpost = one_side(sc, left, paths[left][sc["tool"]], ids, trace_set, keep_trace)
    u, _upre, upost = one_side(sc, right, right_paths[sc["tool"]], ids, trace_set, keep_trace)
    diffs = A.snapshot_diff(gpost, upost)
    flags = A.classify(diffs, gpre)
    flags += A.exit_flags(g["rc"], u["rc"])
    flags += A.trace_flags(g.get("trace"), u.get("trace"))
    flags = sorted(set(flags))
    return {"id": sc["id"], "tool": sc["tool"], "user": sc["user"], "umask": oct(sc["umask"]),
            "cwd": sc["cwd"], "args": sc["args"], "gnu": g, "uu": u, "diffs": diffs,
            "flags": flags, "security": [f for f in flags if f in A.SECURITY_FLAGS]}


def short(e):
    if e is None:
        return "absent"
    s = e.get("type", "?")
    if "mode" in e:
        s += " " + oct(e["mode"])
    s += " %s:%s" % (e.get("uid"), e.get("gid"))
    if "target" in e:
        s += " -> " + e["target"]
    if "sha" in e:
        s += " sha=%s size=%s" % (e["sha"][:8], e.get("size"))
    if "hl" in e:
        s += " hl=" + e["hl"]
    return s


def write_summary(out_dir, env, results, controls):
    lines = ["# coreutils-secdiff results", "",
             "Harness %s. GNU coreutils vs uutils coreutils on the same system." % VERSION, ""]
    lines.append("## Environment")
    for k in ("os_release", "uname", "packages", "gnu_version", "uu_version", "trace_set",
              "trace_note", "setpriv_check", "cross_device", "missing_tools"):
        lines.append("- %s: %s" % (k, json.dumps(env.get(k))))
    lines.append("")
    done = [r for r in results if "flags" in r]
    lines.append("## Counts")
    lines.append("- scenarios: %d; compared: %d; skipped: %d; errors: %d" % (
        len(results), len(done), sum(1 for r in results if r.get("skipped")),
        sum(1 for r in results if r.get("error"))))
    lines.append("- identical (no flags): %d" % sum(1 for r in done if not r["flags"]))
    lines.append("- any divergence: %d" % sum(1 for r in done if r["flags"]))
    lines.append("- security-flagged: %d" % sum(1 for r in done if r["security"]))
    lines.append("")
    lines.append("## Harness control (GNU vs GNU, PREREG P1)")
    for c in controls:
        lines.append("- %s: flags=%s diffs=%d" % (c["id"], c.get("flags"), len(c.get("diffs", []))))
    lines.append("")
    lines.append("## Security-flagged scenarios")
    for r in done:
        if not r["security"]:
            continue
        lines.append("### %s" % r["id"])
        lines.append("- cmd: %s %s (user=%s, umask=%s, cwd=%s)" % (
            r["tool"], " ".join(r["args"]), r["user"], r["umask"], r["cwd"]))
        lines.append("- flags: %s" % ", ".join(r["flags"]))
        lines.append("- exit: gnu=%s uu=%s" % (r["gnu"]["rc"], r["uu"]["rc"]))
        lines.append("- gnu stderr: %r" % r["gnu"]["stderr"][:200])
        lines.append("- uu stderr: %r" % r["uu"]["stderr"][:200])
        for d in r["diffs"][:12]:
            lines.append("  - %s: gnu=[%s] uu=[%s]" % (d["path"], short(d["gnu"]), short(d["uu"])))
        for side in ("gnu", "uu"):
            tr = r[side].get("trace") or {}
            for w in tr.get("windows", []):
                lines.append("  - %s window: %s" % (side, json.dumps(w)))
            for w in tr.get("suid_before_chown", []):
                lines.append("  - %s suid-before-chown: %s" % (side, json.dumps(w)))
        lines.append("")
    lines.append("## All other divergences")
    for r in done:
        if r["flags"] and not r["security"]:
            lines.append("- %s: %s (exit gnu=%s uu=%s)" % (r["id"], ", ".join(r["flags"]),
                                                          r["gnu"]["rc"], r["uu"]["rc"]))
    lines.append("")
    lines.append("## Errors and skips")
    for r in results:
        if r.get("error") or r.get("skipped"):
            lines.append("- %s: %s" % (r["id"], r.get("error") or r.get("skipped")))
    with open(os.path.join(out_dir, "summary.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/out")
    ap.add_argument("--only", default="", help="comma-separated scenario ids")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    if os.geteuid() != 0:
        print("must run as root inside a throwaway container", file=sys.stderr)
        return 2
    for d in (BASE_ROOT, X_ROOT, TRACE_DIR):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        os.chmod(d, 0o755)
    for impl in ("gnu", "uu", "gnu2"):
        for root in (BASE_ROOT, X_ROOT):
            os.makedirs(os.path.join(root, impl), exist_ok=True)
            os.chmod(os.path.join(root, impl), 0o755)

    uid, gid = ensure_user()
    ids = {"uid": uid, "gid": gid}
    paths, versions = discover(SC.TOOLS)
    trace_set, trace_note = pick_trace_set()
    env = {
        "harness": VERSION,
        "os_release": quick(["sh", "-c", "grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release"])[1].strip(),
        "uname": {k: getattr(platform.uname(), k) for k in ("system", "release", "version", "machine")},
        "packages": quick(["dpkg-query", "-W", "-f", "${Package} ${Version}\\n", "rust-coreutils",
                           "gnu-coreutils", "coreutils", "coreutils-from-uutils", "coreutils-from-gnu",
                           "strace", "util-linux"])[1].strip().splitlines(),
        "gnu_version": sorted(set(versions["gnu"].values()))[:3],
        "uu_version": sorted(set(versions["uu"].values()))[:3],
        "paths": paths,
        "trace_set": trace_set,
        "trace_note": trace_note,
        "user": {"name": USER, "uid": uid, "gid": gid},
        "cross_device": os.stat(BASE_ROOT).st_dev != os.stat(X_ROOT).st_dev,
        "missing_tools": {"gnu": [t for t in SC.TOOLS if t not in paths["gnu"]],
                          "uu": [t for t in SC.TOOLS if t not in paths["uu"]]},
    }
    rc, out, err = run_cmd(["id", "-u"], "/tmp", "user", 0o022, None, uid, gid)
    env["setpriv_check"] = {"rc": rc, "out": out.strip(), "err": err.strip()[:200]}
    log("env", json.dumps(env)[:1500])
    with open(os.path.join(args.out, "env.json"), "w") as fh:
        json.dump(env, fh, indent=1, sort_keys=True)

    user_ok = env["setpriv_check"]["out"] == str(uid)
    only = set(x for x in args.only.split(",") if x)
    keep_trace = {}
    results = []
    for i, sc in enumerate(SC.SCENARIOS):
        if only and sc["id"] not in only:
            continue
        if sc["tool"] not in paths["gnu"] or sc["tool"] not in paths["uu"]:
            results.append({"id": sc["id"], "skipped": "tool missing"})
            continue
        if sc["user"] == "user" and not user_ok:
            results.append({"id": sc["id"], "skipped": "setpriv to unprivileged user failed"})
            continue
        try:
            r = compare(sc, paths, ids, trace_set, keep_trace)
            results.append(r)
            if r["flags"]:
                log("%3d %-40s %s" % (i, sc["id"], ",".join(r["flags"])))
        except Exception as ex:  # noqa: BLE001
            results.append({"id": sc["id"], "error": "%s: %s" % (type(ex).__name__, ex)})
            log("ERROR", sc["id"], repr(ex))

    controls = []
    for cid in SC.CONTROL_IDS:
        sc = next(s for s in SC.SCENARIOS if s["id"] == cid)
        if sc["tool"] not in paths["gnu"] or (sc["user"] == "user" and not user_ok):
            continue
        try:
            c = compare(sc, {"gnu": paths["gnu"], "gnu2": paths["gnu"]}, ids, trace_set, {},
                        left="gnu", right="gnu2")
            controls.append({"id": cid, "flags": c["flags"], "diffs": c["diffs"]})
        except Exception as ex:  # noqa: BLE001
            controls.append({"id": cid, "error": repr(ex)})

    # Keep traces only for scenarios with any trace-based or security flag.
    tdir = os.path.join(args.out, "traces")
    os.makedirs(tdir, exist_ok=True)
    for r in results:
        if not r.get("security"):
            continue
        for impl in ("gnu", "uu"):
            kt = keep_trace.get((impl, r["id"]))
            if kt and os.path.exists(kt[0]):
                with open(kt[0], encoding="utf-8", errors="replace") as fh:
                    text = A.normalize_text(fh.read(), kt[1])
                with open(os.path.join(tdir, "%s-%s.txt" % (r["id"].replace("@", "_"), impl)), "w") as fh:
                    fh.write(text[:400000])

    with open(os.path.join(args.out, "results.json"), "w") as fh:
        json.dump({"env": env, "results": results, "controls": controls}, fh, indent=1, sort_keys=True)
    write_summary(args.out, env, results, controls)
    done = [r for r in results if "flags" in r]
    log("done: %d compared, %d divergent, %d security-flagged" % (
        len(done), sum(1 for r in done if r["flags"]), sum(1 for r in done if r["security"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
