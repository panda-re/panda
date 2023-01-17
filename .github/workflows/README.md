# GitHub Actions Tests

## Current Design:
On PR/push:
  Rebuild container from source. Once container is built, run all test suites in parallel

On push to `master`
  Rebuild container (again), push to dockerhub


## Testing locally

We recommend using [act](https://github.com/nektos/act) to locally run CI tests.
This is much easier than repeatedly pushing to a branch/PR if you have a CI failure.

Running with the `-b` flag seems to be required, but then your directory will be owned by `root`:

```
act -b -j local_build_container; sudo chown -R $USER:$USER . .git
```
