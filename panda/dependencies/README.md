This directory contains plaintext lists of build and runtime dependencies for PANDA on various architectures.
The files here are sourced by our Dockerfile as well as our install scripts.
By consolidating dependencies into a single location we're able to avoid things getting out of sync.

Files must be named `[base_image]_[base|build].txt` where `base_image` refers to the docker tag used (e.g., `ubuntu:20.04`). Build should describe build dependencies and base should describe runtime dependencies.

Files can contain comments usith `#`
