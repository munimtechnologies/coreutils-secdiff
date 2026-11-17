# coreutils-secdiff

A security-semantics differential test of **GNU coreutils vs uutils coreutils** (Rust),
built for Ubuntu 26.10, the first Ubuntu release where `cp`, `mv`, `rm` and every other
core command on a default install come from uutils.

It runs 393 security-relevant commands, as root and as an unprivileged user and under
different umasks, against both implementations. Each run starts from the same fresh
fixture tree (setuid files, setgid and sticky directories, symlinks pointing outside the
tree, dangling links, hard links, a FIFO). It then compares:

- the final filesystem state: permission bits, special bits, owner, group, content,
  symlink targets and hard links;
- exit status;
- with `strace`, the order of create/chmod/chown calls. This exposes **permission windows**,
  where a file is created with wider permissions than it ends with, and setuid bits that
  are set before an ownership change.

The question, the method and the predictions were frozen in [PREREG.md](PREREG.md)
before any result was seen.

## Run it

Needs Docker. Everything happens inside a throwaway container, under `/tmp/secdiff` and
`/dev/shm/secdiff`:

```sh
docker run --rm -v "$PWD":/work -v "$PWD/out":/out -w /work ubuntu:26.10 sh -c '
  apt-get update &&
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 strace gnu-coreutils &&
  python3 -m unittest -v && python3 secdiff.py --out /out'
```

Results go to `out/summary.md`, `out/results.json` and `out/env.json`. `--only id1,id2`
runs a subset of scenarios.

## Files

- `scenarios.py`: the fixture tree and the 393 scenarios (frozen).
- `secdiff.py`: the runner (fixture building, snapshots, strace).
- `analysis.py`: pure comparison and strace analysis, unit-tested in `test_*.py`.

## Status and disclosure

Results are not published here until they have been reproduced and triaged (PREREG §5).
Anything security-relevant goes privately to the uutils maintainers first, as their
SECURITY.md asks.

## Licence and credits

Apache-2.0. Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).
GNU coreutils is GPL-3.0-or-later; uutils coreutils is MIT. Neither is bundled here.
