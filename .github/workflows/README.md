# GitHub Actions Tests

**Important Note:** GitHub Actions does *not* recommend self-hosted runners for public repos b/c a PR could trigger arbitrary code execution on the hosted server. However, our tests run in a temporary container that is removed after the test completes, so this mitigates *much* of the risk.


## Ideal Design:
On PR/push:
    If dockerfile unmodified and code (*.c, *.cpp, *.h, Makefile) changed: pull container from dockerhub, copy in source, rebuild with label `$UID` -> Kick off PR test suite
    If dockerfile modified: rebuild container from scratch with label `$UID` -> Kick off PR test suite
    If nothing modified: -> No tests

Test suite: Given `$UID` for a docker container with code built
    For each arch: qemu checks
    For each arch: taint unit tests

On push to `master`:
    Rebuild container, push to dockerhub


## Current Design:
On PR/push:
  Rebuild container from source. Once container is built, run all test suites in parallel

On push to `master`
  Rebuild container (again), push to dockerhub
