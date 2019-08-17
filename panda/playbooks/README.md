# Ansible build scripts for PANDA

## MacOS

### Informational
For MacOS we currently rely on [Homebrew](https://www.brew.sh) for installing
PANDA pre-requisites. However, the main repository of Homebrew lacks some of the
pre-requisites we need for PANDA.
Since the main repository is very fast moving and doesn't focus on backward
compatibility, we'll have to rely on our own formulas. For now, this means
storing our formulas here in `resources/homebrew` and having them copied to the
local Homebrew repository mirror. This is a low effort approach to get us started.

As of August 2019, PANDA *builds* under OSX, but it probably won't *run*, at
least if you're running the latest version of MacOS (10.14–Mojave).
The reason is some changes introduced at some point to the Cocoa framework.
To make PANDA run again on the latest MacOS, further back-porting of changes
from the main QEMU tree are required. If you have the experience for this 
kind of backporting, please go ahead and give it a try.
Until then, the compiled version may (or may not) run correctly on older
versions of MacOS.

### Homebrew python versions

You will need Python 2 `pip` or `pip2` in your path for the ansible playbook
to work.

* Python 2 and Python 3 installed, Python 3 preferred:
  ```
  brew unlink python
  brew unlink python@2
  brew link python@2
  brew link --overwrite python
  ```
* Python 2 and Python 3 installed, Python 2 preferred:
  ```
  brew unlink python
  brew unlink python@2
  brew link python
  brew link --overwrite python@2
  ```
* System Python preferred: Make sure that the system Python comes first in
  your `PATH` and that `pip` is installed for it.

### TL;DR

* Install Ansible: `brew install ansible`
* Inspect the `panda-build-osx.yml` playbook if you want.
* Run the playbook: `ansible-playbook panda-build-osx.yml`.
  This should install all pre-requisites for you and create and run
  a configuration script for PANDA.
* Manually go to the build directory and run `make`
* **Don't expect the generated binaries to work.** (see above)
* Be happy that *at least compiles*.

