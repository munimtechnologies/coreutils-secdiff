# Amendment A2: where the study runs

Written 2026-11-27, **before any result exists**. Every scenario, prediction
and analysis in `PREREG.md` stays as frozen; `secdiff.py`, `scenarios.py` and
`analysis.py` are unchanged.

## A correction to amendment A1

A1 moved the study to a `python:3.12` image because the `ubuntu:26.10` job had
never started, and it blamed the image. MV2's job queue records show that was
wrong: both jobs were waiting with the reason "research jobs go first". The
shared machines had less free memory than a job's reserve, so jobs from the
priority research fields went first, and this job waited for 10 days.

## What changes

The study runs as the README describes, in a disposable `ubuntu:26.04` (LTS) and
`ubuntu:26.10` container with Docker's default settings, on GitHub-hosted runners.
`ci/run-in-container.sh` installs
`python3 strace gnu-coreutils rust-coreutils` from the Ubuntu archive. It records
the package versions, which `chmod` is the default, and the kernel, then runs
the unit tests and `secdiff.py`. So the comparison is between the two coreutils
**exactly as Ubuntu ships them**, which is the pre-registered question, rather
than A1's stand-in (Debian's GNU coreutils and the upstream uutils 0.12.0
release binary).

The workflow (`ci/secdiff.workflow.yml`, enabled by copying it to
`.github/workflows/secdiff.yml`) commits all outputs to
`results/actions/<UTC stamp>/ubuntu-<version>/`, with a link to the public run.
A1's job stays queued as an independent check; any disagreement between the
two is reported.

## Limits added by A2

The kernel is the GitHub runner's, not Ubuntu 26.04's or 26.10's. File-mode and
ownership results come from the same kernel for both implementations, so the
comparison stays fair. Any security-relevant difference will be reproduced on a
stock Ubuntu install before it is reported to uutils.

MV2, Munim, Inc. (mv2@munimtech.com). Made with AI agents working in MV2's name;
not yet checked by a human expert. Text CC BY 4.0, code Apache-2.0.
