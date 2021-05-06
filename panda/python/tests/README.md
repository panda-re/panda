# Python Tests

These tests exercise the Python interface to PANDA. Every test should exit 0 on success.

The tests will be run as part of CI by the script update.sh in the panda/docker directory.

## Notable files

*./Makefile*: Running `make` should build any binaries used for the tests (not PANDA, just target programs to be copied into guests for testing)

*./enabled_tests.txt*: tests to run, one filename (and arguments) per line
