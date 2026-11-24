# coreutils-secdiff amendment A1: where it runs

Written 2026-11-24, **before any result exists**. The scenarios, the comparison and the
pre-registered analysis (`PREREG.md`, `scenarios.py`, `analysis.py`) are unchanged.
The harness `secdiff.py` 0.1.0 is also unchanged; only its container changes.

## Why

The job was filed for an `ubuntu:26.10` image. On the compute MV2 has, no job with a
non-Python/Node/R image has ever started, and this one waited seven days. The
containers there also run with no-new-privileges. That does not matter here,
because the harness only drops privileges (root to the test user with `setpriv`),
and dropping privileges still works.

## What changes

- Image `python:3.12` (Debian trixie). GNU coreutils is Debian's `coreutils`
  package; the harness already finds it through `dpkg -L coreutils` and checks that
  each tool's `--version` says "GNU coreutils".
- uutils is the **official uutils/coreutils 0.12.0 release binary**
  (`coreutils-0.12.0-x86_64-unknown-linux-gnu.tar.gz`). 0.12.0 is the upstream version
  that Ubuntu 26.10 ships (`rust-coreutils 0.12.0-1ubuntu2`). One symlink per
  utility is placed in `/usr/lib/cargo/bin/coreutils/`, the directory Ubuntu uses
  and the harness searches. The multicall binary picks the utility from the
  symlink's name. The tarball's SHA-256 is printed in the job log.
- `strace` comes from Debian.

## Limits added by A1

These are not the exact Ubuntu builds. Ubuntu may build uutils with different
feature flags (for example SELinux or ACL support) and carries its own patches.
GNU coreutils is Debian's version, not Ubuntu's; both versions are recorded in
`env.json`. Any security-relevant difference found this way will be reproduced on
a stock Ubuntu 26.10 system before it is reported.

MV2, Munim, Inc. (mv2@munimtech.com). Made with AI agents working in MV2's name;
not yet checked by a human expert. Text CC BY 4.0.
