# coreutils-secdiff: pure analysis helpers (no filesystem access).
# SPDX-License-Identifier: Apache-2.0
# Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).
"""Parse strace output, find permission windows, and compare filesystem snapshots.

Everything here is plain Python with no OS-specific imports, so the unit tests run
anywhere. The harness that touches the filesystem is secdiff.py.
"""
import posixpath
import re

# Flags that mark a divergence as security-relevant (see PREREG.md, section 3).
SECURITY_FLAGS = (
    "outside_differs",        # a path under outside/ ends differently (followed a link differently)
    "uu_removed_or_missing",  # uutils removed a pre-existing path that GNU kept
    "uu_created_extra",       # uutils created a path GNU did not
    "special_bits",           # setuid/setgid/sticky bits differ
    "uu_more_permissive",     # uutils leaves group/other permission bits GNU does not
    "ownership",              # owner or group differs
    "uu_perm_window",         # uutils creates an object with bits it later removes; GNU does not
    "uu_suid_before_chown",   # uutils sets setuid/setgid before changing owner; GNU does not
)

CALL_RE = re.compile(r"^([a-z0-9_]+)\((.*)\)\s+=\s+(.*)$")
PID_RE = re.compile(r"^(\d+)\s+(.*)$")
RESUMED_RE = re.compile(r"^<\.\.\. ([a-z0-9_]+) resumed>(.*)$")
UNFINISHED = "<unfinished ...>"
FD_ANN_RE = re.compile(r"^(?:AT_FDCWD|-?\d+)<(.*)>$")
OCTAL_TAIL_RE = re.compile(r"(0[0-7]*)\s*$")
OPENAT2_MODE_RE = re.compile(r"mode=(0[0-7]*)")
OPENAT2_FLAGS_RE = re.compile(r"flags=([A-Z0-9_|]+)")
PROC_FD_RE = re.compile(r"^/proc/(?:self|\d+)/fd/(\d+)$")
TMP_RAND_RE = re.compile(r"tmp\.[A-Za-z0-9]{6,}")


# ---------------------------------------------------------------- strace parsing
def join_lines(lines):
    """Return [(pid, body)] with <unfinished ...>/<... resumed> pairs joined."""
    pending = {}
    out = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        m = PID_RE.match(line)
        if m:
            pid, body = int(m.group(1)), m.group(2)
        else:
            pid, body = 0, line
        body = body.strip()
        if body.endswith(UNFINISHED):
            pending[pid] = body[: -len(UNFINISHED)].rstrip()
            continue
        r = RESUMED_RE.match(body)
        if r:
            head = pending.pop(pid, None)
            if head is None:
                continue
            body = head + r.group(2)
        out.append((pid, body))
    return out


def split_args(s):
    """Split a strace argument list on top-level commas (quotes, brackets aware)."""
    args, cur = [], []
    depth, inq, esc = 0, False, False
    for ch in s:
        if inq:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                inq = False
            continue
        if ch == '"':
            inq = True
            cur.append(ch)
            continue
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail or args:
        args.append(tail)
    return args


def parse_ret(s):
    """'3</a/b>' -> ('3', '/a/b'); '-1 ENOENT (...)' -> ('-1', None)."""
    s = s.strip()
    m = re.match(r"^(-?\d+|\?)(?:<(.*?)>)?", s)
    if not m:
        return None, None
    return m.group(1), m.group(2)


def unquote(arg):
    arg = arg.strip()
    if arg.startswith('"'):
        end = arg.rfind('"')
        if end > 0:
            return arg[1:end].replace('\\"', '"').replace("\\\\", "\\")
    return arg


def fd_path(arg):
    if arg is None:
        return None
    m = FD_ANN_RE.match(arg.strip())
    return m.group(1) if m else None


def parse_mode(arg):
    if arg is None:
        return None
    m = OCTAL_TAIL_RE.search(arg.strip())
    if not m:
        return None
    return int(m.group(1), 8)


def resolve(dirarg, patharg, cwd, fdtable=None):
    """Absolute, normalized path for a (dirfd, path) pair. AT_EMPTY_PATH -> dirfd path."""
    p = unquote(patharg)
    if p == "":
        return fd_path(dirarg)
    pm = PROC_FD_RE.match(p)
    if pm and fdtable is not None and int(pm.group(1)) in fdtable:
        return fdtable[int(pm.group(1))]
    if p.startswith("/"):
        return posixpath.normpath(p)
    base = fd_path(dirarg) if dirarg is not None else None
    if base is None:
        base = cwd
    return posixpath.normpath(posixpath.join(base, p))


def _move_prefix(d, old, new):
    for k in list(d.keys()):
        if k == old or k.startswith(old + "/"):
            d[new + k[len(old):]] = d.pop(k)


def analyze_trace(lines, cwd, umask, pre_paths=(), final_modes=None, roots=()):
    """Find permission windows and setuid-before-chown orderings in one strace log.

    lines: strace -f -y output lines. cwd: absolute cwd of the traced command.
    umask: the umask the command started with. pre_paths: absolute paths that existed
    before the run (an O_CREAT open of those is not a creation). final_modes: absolute
    path -> final permission bits after the run. roots: only paths under these count.
    """
    final_modes = final_modes or {}
    pre = set(pre_paths)
    calls = join_lines(lines)
    created = {}   # path -> {"mode", "call", "seq"}
    chmods = {}    # path -> [(seq, mode, how)]
    chowns = {}    # path -> [seq]
    fdtable = {}
    cur_umask = umask
    n_calls = 0

    def in_roots(p):
        if not p:
            return False
        if not roots:
            return True
        return any(p == r or p.startswith(r.rstrip("/") + "/") for r in roots)

    for seq, (_pid, body) in enumerate(calls):
        m = CALL_RE.match(body)
        if not m:
            continue
        n_calls += 1
        name, argstr, retstr = m.groups()
        ret, ann = parse_ret(retstr)
        # Pad with empty strings so short/odd argument lists never raise IndexError;
        # an empty-string argument parses to "no mode" / "no path" below.
        args = split_args(argstr) + ['""'] * 6
        if name == "umask":
            mode = parse_mode(args[0]) if args else None
            if mode is not None:
                cur_umask = mode
            continue
        if ret is None or ret == "?" or ret.startswith("-"):
            continue  # failed call: nothing happened

        if name in ("open", "openat", "creat", "openat2"):
            if name == "open":
                dirarg, parg = None, args[0] if args else '""'
                flags = args[1] if len(args) > 1 else ""
                mode = parse_mode(args[2]) if len(args) > 2 else None
            elif name == "creat":
                dirarg, parg = None, args[0] if args else '""'
                flags = "O_CREAT"
                mode = parse_mode(args[1]) if len(args) > 1 else None
            elif name == "openat":
                dirarg = args[0] if args else None
                parg = args[1] if len(args) > 1 else '""'
                flags = args[2] if len(args) > 2 else ""
                mode = parse_mode(args[3]) if len(args) > 3 else None
            else:  # openat2(dirfd, path, {flags=..., mode=..., resolve=...}, size)
                dirarg = args[0] if args else None
                parg = args[1] if len(args) > 1 else '""'
                how = args[2] if len(args) > 2 else ""
                fm = OPENAT2_FLAGS_RE.search(how)
                flags = fm.group(1) if fm else ""
                mm = OPENAT2_MODE_RE.search(how)
                mode = int(mm.group(1), 8) if mm else None
            path = ann if ann else resolve(dirarg, parg, cwd, fdtable)
            if ret.isdigit() and path:
                fdtable[int(ret)] = path
            if "O_CREAT" not in flags or "O_TMPFILE" in flags:
                continue
            if mode is None or not in_roots(path) or path in pre or path in created:
                continue
            created[path] = {"mode": mode & ~cur_umask & 0o7777, "call": name, "seq": seq}
            continue

        if name in ("mkdir", "mkdirat", "mknod", "mknodat"):
            if name in ("mkdir", "mknod"):
                dirarg, parg, marg = None, args[0] if args else '""', args[1] if len(args) > 1 else None
            else:
                dirarg = args[0] if args else None
                parg = args[1] if len(args) > 1 else '""'
                marg = args[2] if len(args) > 2 else None
            path = resolve(dirarg, parg, cwd, fdtable)
            mode = parse_mode(marg)
            if mode is None or not in_roots(path) or path in pre or path in created:
                continue
            created[path] = {"mode": mode & ~cur_umask & 0o7777, "call": name, "seq": seq}
            continue

        if name in ("chmod", "fchmod", "fchmodat", "fchmodat2"):
            if name == "chmod":
                path, mode, how = resolve(None, args[0], cwd, fdtable), parse_mode(args[1]) if len(args) > 1 else None, "path"
            elif name == "fchmod":
                path = fd_path(args[0]) if args else None
                mode, how = parse_mode(args[1]) if len(args) > 1 else None, "fd"
            else:
                dirarg = args[0] if args else None
                parg = args[1] if len(args) > 1 else '""'
                mode = parse_mode(args[2]) if len(args) > 2 else None
                flags = args[3] if len(args) > 3 else ""
                if unquote(parg) == "" or PROC_FD_RE.match(unquote(parg)):
                    how = "fd"
                elif "AT_SYMLINK_NOFOLLOW" in flags:
                    how = "path_nofollow"
                else:
                    how = "path"
                path = resolve(dirarg, parg, cwd, fdtable)
            if path and mode is not None:
                chmods.setdefault(path, []).append((seq, mode, how))
            continue

        if name in ("chown", "lchown", "fchown", "fchownat"):
            if name in ("chown", "lchown"):
                path = resolve(None, args[0], cwd, fdtable) if args else None
            elif name == "fchown":
                path = fd_path(args[0]) if args else None
            else:
                path = resolve(args[0] if args else None, args[1] if len(args) > 1 else '""', cwd, fdtable)
            if path:
                chowns.setdefault(path, []).append(seq)
            continue

        if name in ("rename", "renameat", "renameat2"):
            if name == "rename":
                old = resolve(None, args[0], cwd, fdtable) if args else None
                new = resolve(None, args[1], cwd, fdtable) if len(args) > 1 else None
            else:
                old = resolve(args[0], args[1], cwd, fdtable) if len(args) > 1 else None
                new = resolve(args[2], args[3], cwd, fdtable) if len(args) > 3 else None
            if old and new:
                for d in (created, chmods, chowns):
                    _move_prefix(d, old, new)
            continue

    windows = []
    for path, info in sorted(created.items()):
        if path in final_modes:
            final = final_modes[path]
        elif path in chmods:
            final = chmods[path][-1][1]
        else:
            continue  # created then removed: not judged
        leaked = info["mode"] & 0o077 & ~final
        if leaked:
            later = [c for c in chmods.get(path, []) if c[0] > info["seq"]]
            windows.append({
                "path": path,
                "created_mode": oct(info["mode"]),
                "final_mode": oct(final),
                "leaked_bits": oct(leaked),
                "created_by": info["call"],
                "fixed_by": later[-1][2] if later else "unknown",
            })

    suid_first = []
    for path, events in sorted(chmods.items()):
        for seq, mode, how in events:
            if mode & 0o6000 and any(s > seq for s in chowns.get(path, [])):
                suid_first.append({"path": path, "mode": oct(mode), "how": how})
                break

    path_mutations = []
    for path, events in sorted(chmods.items()):
        if path in created:
            for _seq, mode, how in events:
                if how == "path":
                    path_mutations.append({"path": path, "mode": oct(mode)})
    return {
        "calls": n_calls,
        "created": len(created),
        "windows": windows,
        "suid_before_chown": suid_first,
        "path_chmods_on_created": path_mutations,
    }


def normalize_text(s, replacements):
    """Replace absolute fixture roots (longest first) and random mktemp names."""
    for old, new in sorted(replacements, key=lambda kv: -len(kv[0])):
        if old:
            s = s.replace(old, new)
    return TMP_RAND_RE.sub("tmp.RAND", s)


def normalize_trace_result(res, replacements):
    def fix(v):
        if isinstance(v, str):
            return normalize_text(v, replacements)
        if isinstance(v, list):
            return [fix(x) for x in v]
        if isinstance(v, dict):
            return {k: fix(x) for k, x in v.items()}
        return v
    return fix(res)


# ---------------------------------------------------------------- snapshot comparison
def snapshot_diff(gnu, uu):
    diffs = []
    for p in sorted(set(gnu) | set(uu)):
        g, u = gnu.get(p), uu.get(p)
        if g != u:
            diffs.append({"path": p, "gnu": g, "uu": u})
    return diffs


def classify(diffs, pre):
    """Flags for a list of snapshot diffs. pre: snapshot before the command."""
    flags = set()
    for d in diffs:
        p, g, u = d["path"], d["gnu"], d["uu"]
        if p.startswith("outside/"):
            flags.add("outside_differs")
        if g and not u:
            flags.add("uu_removed_or_missing" if p in pre else "uu_did_not_create")
        elif u and not g:
            flags.add("uu_kept_gnu_removed" if p in pre else "uu_created_extra")
        elif g and u:
            if g.get("type") != u.get("type") or g.get("target") != u.get("target"):
                flags.add("type_or_target")
            gm, um = g.get("mode", 0), u.get("mode", 0)
            if (gm ^ um) & 0o7000:
                flags.add("special_bits")
            if um & 0o077 & ~gm:
                flags.add("uu_more_permissive")
            if gm & 0o077 & ~um:
                flags.add("uu_less_permissive")
            if (gm ^ um) & 0o700:
                flags.add("owner_bits")
            if g.get("uid") != u.get("uid") or g.get("gid") != u.get("gid"):
                flags.add("ownership")
            if g.get("sha") != u.get("sha") or g.get("size") != u.get("size"):
                flags.add("content")
            if g.get("hl") != u.get("hl"):
                flags.add("hardlink")
    return sorted(flags)


def trace_flags(gnu_trace, uu_trace):
    """Trace-based flags: uutils-only windows / setuid-before-chown (matched by path)."""
    flags = []
    if not gnu_trace or not uu_trace:
        return flags
    gw = {w["path"] for w in gnu_trace.get("windows", [])}
    if any(w["path"] not in gw for w in uu_trace.get("windows", [])):
        flags.append("uu_perm_window")
    gs = {w["path"] for w in gnu_trace.get("suid_before_chown", [])}
    if any(w["path"] not in gs for w in uu_trace.get("suid_before_chown", [])):
        flags.append("uu_suid_before_chown")
    return flags


def exit_flags(gnu_rc, uu_rc):
    flags = []
    if gnu_rc == "timeout" or uu_rc == "timeout":
        if uu_rc == "timeout" and gnu_rc != "timeout":
            flags.append("uu_timeout")
        elif gnu_rc == "timeout" and uu_rc != "timeout":
            flags.append("gnu_timeout")
        return flags
    if (gnu_rc == 0) != (uu_rc == 0):
        flags.append("exit_status")
    return flags
