#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. (MV2). Made with AI agents working in MV2's name.
#
# Amendment A2: run the pre-registered coreutils-secdiff study as written
# (GNU coreutils vs uutils coreutils, as shipped by Ubuntu, with strace) inside
# a disposable Ubuntu container (Docker's default settings) on a GitHub-hosted
# runner.
#
#   mounts: /src  this repository (read-only)
#           /out  results
#
# Never run this on a real machine: it creates users and runs 393 scenarios as root.
set -u

if [ ! -f /.dockerenv ] && [ "${SECDIFF_DISPOSABLE:-}" != "1" ]; then
  echo "refusing to run: this does not look like a disposable container" >&2
  exit 3
fi

out="/out"
mkdir -p "$out"

export DEBIAN_FRONTEND=noninteractive
if ! { apt-get update -qq && apt-get install -y -qq --no-install-recommends \
         python3 strace gnu-coreutils rust-coreutils util-linux passwd; } >"$out/apt.log" 2>&1; then
  echo "apt-get failed"
  tail -n 40 "$out/apt.log"
  echo "exit apt" >"$out/exit.txt"
  exit 1
fi

{
  cat /etc/os-release
  echo "--- packages"
  dpkg-query -W -f '${Package} ${Version}\n' coreutils coreutils-from-uutils coreutils-from-gnu \
    gnu-coreutils rust-coreutils strace util-linux libc6
  echo "--- default chmod: $(readlink -f "$(command -v chmod)")"
  /usr/bin/gnuchmod --version | head -n 1
  /usr/lib/cargo/bin/coreutils/chmod --version | head -n 1
  echo "--- kernel"
  uname -a
  echo "--- process"
  grep -E 'NoNewPrivs|CapEff|Seccomp' /proc/self/status
} >"$out/platform.txt" 2>&1

w="$(mktemp -d)"
cp /src/*.py /src/PREREG.md "$w"/
cd "$w" || exit 1
sha256sum ./*.py >"$out/code-sha256.txt"

if ! python3 -m unittest -v >"$out/unittest.log" 2>&1; then
  echo "unit tests failed"
  tail -n 60 "$out/unittest.log"
  echo "exit unittest" >"$out/exit.txt"
  exit 1
fi

python3 secdiff.py --out "$out" >"$out/stdout.txt" 2>"$out/stderr.txt"
rc=$?
echo "exit $rc" >"$out/exit.txt"
tail -n 60 "$out/stdout.txt"
exit "$rc"
