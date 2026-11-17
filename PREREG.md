# Pre-registration: do Ubuntu 26.10's new default coreutils keep GNU's security semantics?

Frozen 2026-11-17, before any result was seen. Author: MV2, Munim, Inc. (mv2@munimtech.com).
Made with AI agents working in MV2's name. Licence: Apache-2.0 (code), CC BY 4.0 (text).

## 1. Question

Ubuntu 26.10 (released 15 October 2026) is the first Ubuntu release in which every core
command on a default install, including `cp`, `mv` and `rm`, comes from uutils coreutils
(Rust, version 0.12.0 in 26.10) rather than GNU coreutils. Ubuntu 26.04 LTS had kept GNU
`cp`/`mv`/`rm` after a Zellic security audit for Canonical found 113 issues (about 44
CVEs, mostly TOCTOU races and filesystem edge cases). uutils 0.9.0 then rewrote much of
that code (a new TOCTOU-resistant copy module, `uucore::safe_copy`).

**When given the same security-relevant command in the same starting directory tree, does
uutils 0.12.0 leave the filesystem in the same state as GNU coreutils 9.x?** By "security-relevant"
we mean permission bits, setuid/setgid/sticky bits, ownership, which symlinks are
followed, what gets deleted, and whether a file briefly exists with wider permissions than
it ends with.

## 2. Why this is new

- The Zellic audit was a code review of specific code paths, done before the 0.9.0
  rewrite. The cp/mv/rm code that Ubuntu 26.10 now ships was largely written after it.
- The largest public behavioural comparison we found (devops-daily, October 2026: 162
  shell commands, GNU 9.10 vs uutils 0.12.0 on 26.10) compares stdout, stderr and exit
  status. Its authors state that it does not cover permissions, ownership, setuid or
  symlink-following.
- uutils runs the GNU test suite in CI and fuzzes some text utilities against GNU, but we
  found no systematic test that compares the resulting filesystem state, ownership and
  syscall ordering of the file-management utilities against GNU across users and umasks.

## 3. Method (fixed)

- Container `ubuntu:26.10` (amd64), run as root, with an unprivileged account
  (`secdiffuser`, entered with `setpriv --reuid --regid --init-groups`).
- GNU tools: the `gnu-coreutils` package's `gnu*` binaries (verified by `--version`
  containing "GNU coreutils"). uutils tools: `/usr/lib/cargo/bin/coreutils/<tool>`
  (verified by `--version` containing "uutils"). Exact package versions are logged.
- 393 scenarios over 20 tools (cp, mv, rm, chmod, chown, chgrp, install, ln, mkdir, mkfifo,
  mknod, touch, truncate, dd, tee, sort, split, shred, mktemp, rmdir), listed in
  `scenarios.py`. Most run both as root and as the unprivileged user; some vary the umask
  (000, 022, 077). Cross-filesystem moves go to tmpfs (`/dev/shm`).
- Each run starts from a fresh copy of one fixture tree (`scenarios.FIXTURE`): private and
  public files, setuid/setgid files owned by the user and by root, a hard-link pair, a
  FIFO, symlinks that point outside the working tree (relative, absolute, to a directory,
  dangling), a setgid directory, a sticky directory with a root-owned file, and a
  read-only directory.
- Compared per scenario: the full `lstat` state of every path afterwards (type, permission
  bits, owner, group, content hash, symlink target, hard-link grouping; not timestamps),
  and exit status (zero/non-zero).
- With strace (`-f -y`), a second fresh run records open/mkdir/mknod/chmod/chown/rename
  calls. A **permission window** is an object created with group/other permission bits
  that it does not have at the end (an attacker can open it during that window and keep
  the descriptor). **setuid-before-chown** is a chmod that sets setuid/setgid followed by
  a chown of the same path.
- Security flags: `outside_differs`, `uu_removed_or_missing`, `uu_created_extra`,
  `special_bits`, `uu_more_permissive`, `ownership`, `uu_perm_window`,
  `uu_suid_before_chown`. Everything else (exit status only, content, less permissive,
  link-target spelling) is a compatibility difference.
- Safety: no scenario names `/` or any path outside the fixture; `--preserve-root` is
  therefore *not* tested (testing it would mean pointing `rm -rf` at a real root).

## 4. Predictions (frozen)

| # | Prediction | Our confidence |
|---|---|---|
| P1 | GNU-vs-GNU control (15 scenarios) gives zero flags: the harness is deterministic. | 90% |
| P2 | At least one scenario carries a security flag from the state comparison (first six flags). | 65% |
| P3 | At least one scenario shows a uutils-only permission window (`uu_perm_window`). | 50% |
| P4 | `chmod 755 dir` and `chmod 0755 dir` on a setgid directory: uutils keeps the setgid bit, as GNU does. | 60% |
| P5 | `cp file dangling-symlink`: uutils refuses to write through the dangling link, as GNU does. | 75% |
| P6 | All 9 `rm` commands that use `.`/`..`/`./`/`../` forms (`rm-rf-dot*`, `rm-rf-*dot*`; 18 scenarios with both users) end in the same state as GNU. | 70% |
| P7 | Between 5% and 30% of compared scenarios show any divergence (security or compatibility). | 60% |

## 5. What counts as a finding

A security-flagged divergence becomes a finding only after all of:
1. a minimal hand-written reproduction confirms it in a second, separate run;
2. it is checked against uutils issues, security advisories and commits after 0.12.0, so
   that known or already-fixed issues are reported as such, not as new;
3. a written threat model: who the attacker is and what trust boundary is crossed. Where
   GNU is the less safe one, we say so.

## 6. Disclosure

Security-relevant findings go privately to uutils first, through the channel in its
SECURITY.md (GitHub private report or e-mail to the maintainer), and to Ubuntu security if
26.10 is affected. No public details until a fix is released or 90 days have passed.
Compatibility-only differences are reported publicly, a few at a time, with fixes where we
can write them.

## 7. Limits

One kernel and filesystem pair (Docker overlayfs on the test host, tmpfs for
cross-device moves); C.UTF-8 locale only; no ACLs, xattrs or SELinux; deterministic
single-run behaviour only, so races are seen only as permission windows in the syscall
order, never by actually racing; root inside a container has a reduced capability set.
