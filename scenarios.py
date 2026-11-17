# coreutils-secdiff: scenario list (frozen in PREREG.md before any result was seen).
# SPDX-License-Identifier: Apache-2.0
# Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).
"""Security-relevant command scenarios run against GNU coreutils and uutils.

Each scenario is one command run in a fresh copy of the fixture (see FIXTURE). Paths
are relative to the scenario cwd (default "w"); {X} is a directory on another
filesystem (tmpfs), {B} is the fixture root. "user" is "root" or "user" (an
unprivileged account). Nothing here ever names "/" or a path outside the fixture.
"""

# (relative path, kind, mode, owner, group, data)
#   kind: d=dir f=file l=symlink(data=target) h=hardlink(data=existing path) p=fifo
#   owner/group: "U" = the acting user, "R" = root
FIXTURE = [
    ("w", "d", 0o755, "U", "U", None),
    ("w/src", "d", 0o755, "U", "U", None),
    ("w/src/secret", "f", 0o600, "U", "U", "secret\n"),
    ("w/src/public", "f", 0o644, "U", "U", "public\n"),
    ("w/src/exec", "f", 0o755, "U", "U", "#!/bin/sh\necho hi\n"),
    ("w/src/ro", "f", 0o444, "U", "U", "ro\n"),
    ("w/src/suid", "f", 0o4755, "U", "U", "suid\n"),
    ("w/src/sgid", "f", 0o2755, "U", "U", "sgid\n"),
    ("w/src/suid_root", "f", 0o4755, "R", "R", "suidroot\n"),
    ("w/src/sgid_root", "f", 0o2755, "R", "R", "sgidroot\n"),
    ("w/src/grp_root", "f", 0o644, "U", "R", "grproot\n"),
    ("w/src/hard1", "f", 0o644, "U", "U", "hard\n"),
    ("w/src/hard2", "h", None, None, None, "w/src/hard1"),
    ("w/src/link_out", "l", None, "U", "U", "../../outside/target"),
    ("w/src/link_abs", "l", None, "U", "U", "{B}/outside/target"),
    ("w/src/link_dir", "l", None, "U", "U", "../../outside/dir"),
    ("w/src/dangling", "l", None, "U", "U", "../../outside/newfile"),
    ("w/src/fifo", "p", 0o644, "U", "U", None),
    ("w/src/sub", "d", 0o700, "U", "U", None),
    ("w/src/sub/inner", "f", 0o600, "U", "U", "inner\n"),
    ("w/src/sub/link_up", "l", None, "U", "U", "../../../outside/target"),
    ("w/dst", "d", 0o755, "U", "U", None),
    ("w/dst/existing", "f", 0o644, "U", "U", "old\n"),
    ("w/dst/ro_existing", "f", 0o444, "U", "U", "oldro\n"),
    ("w/dst/exists_link", "l", None, "U", "U", "../../outside/target"),
    ("w/dst/dangling", "l", None, "U", "U", "../../outside/newfile2"),
    ("w/dst/dir_link", "l", None, "U", "U", "../../outside/dir"),
    ("w/shared", "d", 0o2775, "U", "U", None),
    ("w/sticky", "d", 0o1777, "R", "R", None),
    ("w/sticky/rootfile", "f", 0o644, "R", "R", "r\n"),
    ("w/sticky/userfile", "f", 0o644, "U", "U", "u\n"),
    ("w/lock", "d", 0o555, "U", "U", None),
    ("w/lock/f", "f", 0o644, "U", "U", "f\n"),
    ("w/a", "d", 0o755, "U", "U", None),
    ("w/a/sentinel", "f", 0o644, "U", "U", "a\n"),
    ("w/a/b", "d", 0o755, "U", "U", None),
    ("w/a/b/f", "f", 0o644, "U", "U", "b\n"),
    ("outside", "d", 0o755, "U", "U", None),
    ("outside/target", "f", 0o644, "U", "U", "target\n"),
    ("outside/dir", "d", 0o755, "U", "U", None),
    ("outside/dir/keep", "f", 0o644, "U", "U", "keep\n"),
    ("outside/root_target", "f", 0o644, "R", "R", "rt\n"),
]

SCENARIOS = []
_IDS = set()


def S(sid, tool, args, user="root", umask=0o022, cwd="w", stdin=None):
    if sid in _IDS:
        raise ValueError("duplicate scenario id " + sid)
    _IDS.add(sid)
    SCENARIOS.append({"id": sid, "tool": tool, "args": list(args), "user": user,
                      "umask": umask, "cwd": cwd, "stdin": stdin})


def BOTH(sid, tool, args, **kw):
    S(sid + "@root", tool, args, user="root", **kw)
    S(sid + "@user", tool, args, user="user", **kw)


# ------------------------------------------------------------------ cp
BOTH("cp-secret", "cp", ["src/secret", "dst/"])
BOTH("cp-p-secret", "cp", ["-p", "src/secret", "dst/"])
BOTH("cp-suid", "cp", ["src/suid", "dst/"])
BOTH("cp-p-suid", "cp", ["-p", "src/suid", "dst/"])
BOTH("cp-p-suid-root", "cp", ["-p", "src/suid_root", "dst/"])
BOTH("cp-a-sgid-root", "cp", ["-a", "src/sgid_root", "dst/"])
BOTH("cp-preserve-mode-suid", "cp", ["--preserve=mode", "src/suid", "dst/"])
BOTH("cp-dangling-dest", "cp", ["src/public", "dst/dangling"])
BOTH("cp-dest-link", "cp", ["src/public", "dst/exists_link"])
BOTH("cp-remove-dest-link", "cp", ["--remove-destination", "src/public", "dst/exists_link"])
BOTH("cp-ro-dest", "cp", ["src/public", "dst/ro_existing"])
BOTH("cp-f-ro-dest", "cp", ["-f", "src/public", "dst/ro_existing"])
BOTH("cp-r-src", "cp", ["-r", "src", "dst/c"])
BOTH("cp-RL-src", "cp", ["-RL", "src", "dst/c"])
BOTH("cp-RH-linkdir", "cp", ["-RH", "src/link_dir", "dst/c"])
BOTH("cp-a-src", "cp", ["-a", "src", "dst/c"])
BOTH("cp-a-sub-shared", "cp", ["-a", "src/sub", "shared/"])
BOTH("cp-secret-shared", "cp", ["src/secret", "shared/"])
BOTH("cp-into-dirlink", "cp", ["src/public", "dst/dir_link/"])
BOTH("cp-l", "cp", ["-l", "src/public", "dst/"])
BOTH("cp-s-rel", "cp", ["-s", "src/public", "dst/sl"])
BOTH("cp-n", "cp", ["-n", "src/public", "dst/existing"])
BOTH("cp-b", "cp", ["-b", "src/public", "dst/existing"])
BOTH("cp-same", "cp", ["src/public", "src/public"])
BOTH("cp-a-hardpair", "cp", ["-a", "src/hard1", "src/hard2", "dst/"])
BOTH("cp-preserve-all", "cp", ["--preserve=all", "src/secret", "dst/"])
BOTH("cp-a-no-preserve-mode", "cp", ["-a", "--no-preserve=mode", "src/secret", "dst/"])
BOTH("cp-attributes-only", "cp", ["--attributes-only", "src/secret", "dst/existing"])
BOTH("cp-a-cross", "cp", ["-a", "src", "{X}/c"])
BOTH("cp-T-dest-link", "cp", ["-T", "src/public", "dst/exists_link"])
BOTH("cp-r-into-self", "cp", ["-r", "src", "src/sub/"])
BOTH("cp-parents", "cp", ["--parents", "src/sub/inner", "dst/"])
BOTH("cp-r-linkdir", "cp", ["-r", "src/link_dir", "dst/"])
BOTH("cp-r-dangling", "cp", ["-r", "src/dangling", "dst/"])
BOTH("cp-P-link", "cp", ["-P", "src/link_out", "dst/"])
BOTH("cp-follow-src-link", "cp", ["src/link_out", "dst/"])
BOTH("cp-r-fifo", "cp", ["-r", "src/fifo", "dst/"])
BOTH("cp-d-abs", "cp", ["-d", "src/link_abs", "dst/"])
BOTH("cp-u", "cp", ["-u", "src/public", "dst/existing"])
S("cp-sticky-rootfile@user", "cp", ["src/public", "sticky/rootfile"], user="user")
S("cp-secret-umask077@root", "cp", ["src/public", "dst/"], umask=0o077)
S("cp-secret-umask000@root", "cp", ["src/secret", "dst/"], umask=0o000)
S("cp-r-sub-umask000@root", "cp", ["-r", "src/sub", "dst/"], umask=0o000)
S("cp-r-sub-umask000@user", "cp", ["-r", "src/sub", "dst/"], user="user", umask=0o000)
S("cp-a-cross-suid-root@user", "cp", ["-a", "src/suid_root", "{X}/"], user="user")

# ------------------------------------------------------------------ mv
BOTH("mv-secret", "mv", ["src/secret", "dst/"])
BOTH("mv-onto-link", "mv", ["src/public", "dst/exists_link"])
BOTH("mv-into-dirlink", "mv", ["src/public", "dst/dir_link/"])
BOTH("mv-onto-dangling", "mv", ["src/public", "dst/dangling"])
BOTH("mv-cross-secret", "mv", ["src/secret", "{X}/"])
BOTH("mv-cross-suid", "mv", ["src/suid", "{X}/"])
BOTH("mv-cross-suid-root", "mv", ["src/suid_root", "{X}/"])
BOTH("mv-cross-sgid-root", "mv", ["src/sgid_root", "{X}/"])
BOTH("mv-cross-dir", "mv", ["src", "{X}/"])
BOTH("mv-cross-sub", "mv", ["src/sub", "{X}/"])
BOTH("mv-cross-link", "mv", ["src/link_out", "{X}/"])
BOTH("mv-cross-hardpair", "mv", ["src/hard1", "src/hard2", "{X}/"])
BOTH("mv-cross-fifo", "mv", ["src/fifo", "{X}/"])
BOTH("mv-n", "mv", ["-n", "src/public", "dst/existing"])
BOTH("mv-b", "mv", ["-b", "src/public", "dst/existing"])
BOTH("mv-into-self", "mv", ["src", "src/sub/"])
BOTH("mv-T-nonempty", "mv", ["-T", "src/sub", "dst"])
BOTH("mv-ro-dest", "mv", ["src/public", "dst/ro_existing"])
BOTH("mv-secret-shared", "mv", ["src/secret", "shared/"])
S("mv-sticky-rootfile@user", "mv", ["sticky/rootfile", "dst/"], user="user")
S("mv-cross-sticky-rootfile@user", "mv", ["sticky/rootfile", "{X}/"], user="user")
S("mv-cross-lock@user", "mv", ["lock", "{X}/"], user="user")

# ------------------------------------------------------------------ rm
BOTH("rm-r-src", "rm", ["-r", "src"])
BOTH("rm-rf-dirlink-slash", "rm", ["-rf", "dst/dir_link/"])
BOTH("rm-r-dirlink", "rm", ["-r", "dst/dir_link"])
BOTH("rm-r-linkdir-arg", "rm", ["-r", "src/link_dir"])
BOTH("rm-rf-dot", "rm", ["-rf", "."], cwd="w/a/b")
BOTH("rm-rf-dotdot", "rm", ["-rf", ".."], cwd="w/a/b")
BOTH("rm-rf-dot-slash", "rm", ["-rf", "./"], cwd="w/a/b")
BOTH("rm-rf-dotdot-slash", "rm", ["-rf", "../"], cwd="w/a/b")
BOTH("rm-rf-src-dot", "rm", ["-rf", "src/."])
BOTH("rm-rf-src-dotdot", "rm", ["-rf", "src/.."])
BOTH("rm-rf-src-dot-slash", "rm", ["-rf", "src/./"])
BOTH("rm-rf-sub-dotdot", "rm", ["-rf", "src/sub/.."])
BOTH("rm-rf-a-b-dotdot-slash", "rm", ["-rf", "a/b/../"])
BOTH("rm-rf-double-slash", "rm", ["-rf", "src//"])
BOTH("rm-ro", "rm", ["dst/ro_existing"])
BOTH("rm-d-nonempty", "rm", ["-d", "src/sub"])
BOTH("rm-dangling", "rm", ["dst/dangling"])
BOTH("rm-one-fs", "rm", ["-rf", "--one-file-system", "src"])
BOTH("rm-rf-lock", "rm", ["-rf", "lock"])
S("rm-sticky-rootfile@user", "rm", ["-f", "sticky/rootfile"], user="user")
S("rm-rf-sticky@user", "rm", ["-rf", "sticky"], user="user")

# ------------------------------------------------------------------ chmod
BOTH("chmod-R-700-src", "chmod", ["-R", "700", "src"])
BOTH("chmod-R-aw-src", "chmod", ["-R", "a+w", "src"])
BOTH("chmod-link-arg", "chmod", ["600", "src/link_out"])
BOTH("chmod-dangling", "chmod", ["600", "dst/dangling"])
BOTH("chmod-RL-src", "chmod", ["-R", "-L", "700", "src"])
BOTH("chmod-RH-linkdir", "chmod", ["-R", "-H", "700", "src/link_dir"])
BOTH("chmod-R-linkdir", "chmod", ["-R", "700", "src/link_dir"])
BOTH("chmod-sgid-dir-755", "chmod", ["755", "shared"])
BOTH("chmod-sgid-dir-0755", "chmod", ["0755", "shared"])
BOTH("chmod-sgid-dir-00755", "chmod", ["00755", "shared"])
BOTH("chmod-sgid-dir-g-s", "chmod", ["g-s", "shared"])
BOTH("chmod-sgid-dir-eq", "chmod", ["u=rwx,g=rx,o=rx", "shared"])
BOTH("chmod-plus-w", "chmod", ["+w", "src/ro"])
BOTH("chmod-plus-x", "chmod", ["+x", "src/public"])
BOTH("chmod-R-aX", "chmod", ["-R", "a+X", "src"])
BOTH("chmod-u+s", "chmod", ["u+s", "src/exec"])
BOTH("chmod-g+s-grp-root", "chmod", ["g+s", "src/grp_root"])
BOTH("chmod-ref", "chmod", ["--reference=src/secret", "src/public"])
BOTH("chmod-7777", "chmod", ["7777", "src/public"])
BOTH("chmod-minus-w", "chmod", ["-w", "src/public"])
BOTH("chmod-sticky-dir-1755", "chmod", ["755", "sticky"])
S("chmod-plus-w-umask077@root", "chmod", ["+w", "src/ro"], umask=0o077)
S("chmod-R-go-src-umask000@user", "chmod", ["-R", "go-rwx", "src"], user="user", umask=0o000)

# ------------------------------------------------------------------ chown / chgrp (root unless noted)
S("chown-R-user-src@root", "chown", ["-R", "{USER}", "src"])
S("chown-RL-user-src@root", "chown", ["-RL", "{USER}", "src"])
S("chown-RH-linkdir@root", "chown", ["-RH", "{USER}", "src/link_dir"])
S("chown-R-linkdir@root", "chown", ["-R", "{USER}", "src/link_dir"])
S("chown-link-arg@root", "chown", ["{USER}", "src/link_out"])
S("chown-h-link@root", "chown", ["-h", "{USER}", "src/link_out"])
S("chown-suid-root@root", "chown", ["{USER}", "src/suid_root"])
S("chown-suid-same-owner@root", "chown", ["root", "src/suid_root"])
S("chown-from@root", "chown", ["--from=root", "{USER}", "src/suid_root"])
S("chgrp-sgid-root@root", "chgrp", ["{USER}", "src/sgid_root"])
S("chown-dangling@root", "chown", ["{USER}", "dst/dangling"])
S("chown-colon-group@root", "chown", [":{USER}", "src/sgid_root"])
S("chown-user-colon@root", "chown", ["{USER}:", "src/suid_root"])
S("chown-R-sticky@root", "chown", ["-R", "{USER}", "sticky"])
S("chown-to-root@user", "chown", ["root", "src/public"], user="user")
S("chgrp-own-grp-root@user", "chgrp", ["{USER}", "src/grp_root"], user="user")
S("chgrp-root@user", "chgrp", ["root", "src/public"], user="user")
S("chown-R-noop@user", "chown", ["-R", "{USER}", "src"], user="user")

# ------------------------------------------------------------------ install
BOTH("install-m600", "install", ["-m", "600", "src/public", "dst/inst"])
BOTH("install-default-mode", "install", ["src/secret", "dst/inst"])
BOTH("install-d-m700", "install", ["-d", "-m", "700", "dst/n1/n2/n3"])
BOTH("install-D-m600", "install", ["-D", "-m", "600", "src/public", "dst/n1/n2/f"])
BOTH("install-onto-link", "install", ["src/public", "dst/exists_link"])
BOTH("install-onto-dangling", "install", ["src/public", "dst/dangling"])
BOTH("install-into-dirlink", "install", ["src/public", "dst/dir_link/"])
BOTH("install-C", "install", ["-C", "-m", "644", "src/public", "dst/existing"])
BOTH("install-m-sym", "install", ["-m", "u=rw,go=", "src/public", "dst/inst"])
BOTH("install-shared", "install", ["-m", "640", "src/public", "shared/inst"])
BOTH("install-b", "install", ["-b", "src/public", "dst/existing"])
BOTH("install-d-dirlink", "install", ["-d", "dst/dir_link"])
BOTH("install-t", "install", ["-t", "dst/", "src/secret", "src/exec"])
BOTH("install-p", "install", ["-p", "src/secret", "dst/inst"])
BOTH("install-m2755", "install", ["-m", "2755", "src/exec", "dst/inst"])
BOTH("install-m4755", "install", ["-m", "4755", "src/exec", "dst/inst"])
S("install-m4755-o-user@root", "install", ["-m", "4755", "-o", "{USER}", "src/exec", "dst/inst"])
S("install-o-g@root", "install", ["-o", "{USER}", "-g", "{USER}", "-m", "750", "src/secret", "dst/inst"])
S("install-umask000@root", "install", ["src/public", "dst/inst"], umask=0o000)
S("install-d-umask000@root", "install", ["-d", "dst/n1/n2"], umask=0o000)
S("install-D-umask077@user", "install", ["-D", "src/public", "dst/n1/f"], user="user", umask=0o077)

# ------------------------------------------------------------------ ln
BOTH("ln-s-into-dirlink", "ln", ["-s", "target", "dst/dir_link"])
BOTH("ln-sn-dirlink", "ln", ["-sn", "target", "dst/dir_link"])
BOTH("ln-sfn-dirlink", "ln", ["-sfn", "newtarget", "dst/dir_link"])
BOTH("ln-sf-dirlink", "ln", ["-sf", "newtarget", "dst/dir_link"])
BOTH("ln-f-onto-link", "ln", ["-f", "src/public", "dst/exists_link"])
BOTH("ln-hard-to-symlink", "ln", ["src/link_out", "dst/hl"])
BOTH("ln-L-hard", "ln", ["-L", "src/link_out", "dst/hl"])
BOTH("ln-sT-dirlink", "ln", ["-sT", "x", "dst/dir_link"])
BOTH("ln-sb", "ln", ["-sb", "x", "dst/existing"])
BOTH("ln-hard-dir", "ln", ["src/sub", "dst/sd"])
BOTH("ln-sr", "ln", ["-sr", "src/public", "dst/rel"])
BOTH("ln-sr-through-dirlink", "ln", ["-sr", "src/public", "dst/dir_link/rel"])
BOTH("ln-dangling-dest", "ln", ["src/public", "dst/dangling"])
S("ln-hard-rootfile@user", "ln", ["src/suid_root", "dst/h"], user="user")

# ------------------------------------------------------------------ mkdir / mkfifo / mknod
BOTH("mkdir-m700", "mkdir", ["-m", "700", "dst/m"])
BOTH("mkdir-p-m700", "mkdir", ["-p", "-m", "700", "dst/m1/m2/m3"])
BOTH("mkdir-m2775", "mkdir", ["-m", "2775", "dst/m"])
BOTH("mkdir-m-sym", "mkdir", ["-m", "u=rwx,g=,o=", "dst/m"])
BOTH("mkdir-shared", "mkdir", ["shared/m"])
BOTH("mkdir-p-shared", "mkdir", ["-p", "shared/m1/m2"])
BOTH("mkdir-m700-shared", "mkdir", ["-m", "700", "shared/m"])
BOTH("mkdir-m755-shared", "mkdir", ["-m", "755", "shared/m"])
BOTH("mkdir-p-dirlink", "mkdir", ["-p", "dst/dir_link/new"])
BOTH("mkdir-dangling", "mkdir", ["dst/dangling"])
BOTH("mkdir-p-dangling", "mkdir", ["-p", "dst/dangling/x"])
BOTH("mkdir-p-m1777", "mkdir", ["-p", "-m", "1777", "dst/m1/m2"])
BOTH("mkdir-existing-link", "mkdir", ["dst/exists_link"])
S("mkdir-umask077@root", "mkdir", ["dst/m"], umask=0o077)
S("mkdir-p-umask000@user", "mkdir", ["-p", "dst/m1/m2"], user="user", umask=0o000)
S("mkdir-m777-umask077@root", "mkdir", ["-m", "777", "dst/m"], umask=0o077)
BOTH("mkfifo-m600", "mkfifo", ["-m", "600", "dst/f"])
BOTH("mkfifo-dangling", "mkfifo", ["dst/dangling"])
BOTH("mkfifo-m-sym", "mkfifo", ["-m", "a=rw", "dst/f"])
BOTH("mkfifo-shared", "mkfifo", ["shared/f"])
S("mkfifo-umask077@user", "mkfifo", ["dst/f"], user="user", umask=0o077)
BOTH("mknod-p-m600", "mknod", ["-m", "600", "dst/f", "p"])
BOTH("mknod-p-dangling", "mknod", ["dst/dangling", "p"])

# ------------------------------------------------------------------ touch / truncate / dd / tee / sort / split
BOTH("touch-new", "touch", ["dst/new"])
BOTH("touch-dangling", "touch", ["dst/dangling"])
BOTH("touch-h-dangling", "touch", ["-h", "dst/dangling"])
BOTH("touch-c-dangling", "touch", ["-c", "dst/dangling"])
BOTH("touch-in-dirlink", "touch", ["dst/dir_link/new"])
BOTH("touch-shared", "touch", ["shared/new"])
S("touch-umask000@user", "touch", ["dst/new"], user="user", umask=0o000)
S("touch-umask077@root", "touch", ["dst/new"], umask=0o077)
BOTH("truncate-link", "truncate", ["-s", "0", "dst/exists_link"])
BOTH("truncate-dangling", "truncate", ["-s", "10", "dst/dangling"])
BOTH("truncate-c-dangling", "truncate", ["-c", "-s", "10", "dst/dangling"])
S("truncate-new-umask077@user", "truncate", ["-s", "5", "dst/new"], user="user", umask=0o077)
BOTH("dd-of-dangling", "dd", ["if=src/public", "of=dst/dangling", "status=none"])
BOTH("dd-of-link-notrunc", "dd", ["if=src/public", "of=dst/exists_link", "conv=notrunc", "status=none"])
BOTH("dd-excl-existing", "dd", ["if=src/public", "of=dst/existing", "conv=excl", "status=none"])
BOTH("dd-nocreat", "dd", ["if=src/public", "of=dst/new", "conv=nocreat", "status=none"])
S("dd-new-umask077@user", "dd", ["if=src/secret", "of=dst/new", "status=none"], user="user", umask=0o077)
BOTH("tee-dangling", "tee", ["dst/dangling"], stdin="x\n")
BOTH("tee-a-link", "tee", ["-a", "dst/exists_link"], stdin="x\n")
S("tee-new-umask077@user", "tee", ["dst/new"], user="user", umask=0o077, stdin="x\n")
BOTH("sort-o-dangling", "sort", ["-o", "dst/dangling", "src/public"])
S("sort-o-umask077@user", "sort", ["-o", "dst/new", "src/secret"], user="user", umask=0o077)
S("split-umask077@user", "split", ["-l", "1", "src/exec", "dst/part."], user="user", umask=0o077)

# ------------------------------------------------------------------ shred / mktemp / rmdir
BOTH("shred-z", "shred", ["-n", "0", "-z", "dst/existing"])
BOTH("shred-z-link", "shred", ["-n", "0", "-z", "dst/exists_link"])
BOTH("shred-zu-link", "shred", ["-n", "0", "-z", "-u", "dst/exists_link"])
BOTH("shred-zu", "shred", ["-n", "0", "-z", "-u", "dst/existing"])
BOTH("shred-zu-dangling", "shred", ["-n", "0", "-z", "-u", "dst/dangling"])
S("mktemp-file-umask000@user", "mktemp", ["-p", "dst", "tmp.XXXXXXXX"], user="user", umask=0o000)
S("mktemp-dir-umask000@user", "mktemp", ["-d", "-p", "dst", "tmp.XXXXXXXX"], user="user", umask=0o000)
S("mktemp-file-umask000@root", "mktemp", ["-p", "dst", "tmp.XXXXXXXX"], umask=0o000)
BOTH("mktemp-dirlink", "mktemp", ["-p", "dst/dir_link", "tmp.XXXXXXXX"])
BOTH("rmdir-dirlink", "rmdir", ["dst/dir_link"])
BOTH("rmdir-dirlink-slash", "rmdir", ["dst/dir_link/"])
BOTH("rmdir-p", "rmdir", ["-p", "a/b"])

TOOLS = sorted({s["tool"] for s in SCENARIOS})

# A small fixed set re-run GNU-vs-GNU to measure harness noise (PREREG P1).
CONTROL_IDS = [
    "cp-a-src@root", "cp-a-cross@user", "mv-cross-dir@root", "rm-r-src@user",
    "chmod-R-700-src@root", "chown-R-user-src@root", "install-D-m600@user",
    "mkdir-p-m700@root", "touch-new@user", "mktemp-dir-umask000@user",
    "shred-z@root", "ln-sr@user", "dd-of-dangling@root", "mv-cross-hardpair@root",
    "cp-r-sub-umask000@user",
]
