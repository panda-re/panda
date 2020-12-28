#!/bin/bash

PYTHON="python3"
PYENV="pyenv3"
PYENV_ACTIVATE="$PYENV/bin/activate"
PYENV_REQUIREMENTS="requirements2.txt"

function activate_pyenv() {
	if [ -f "$PYENV_ACTIVATE" ]; then
		. "$PYENV_ACTIVATE"
	else
		virtualenv -p "$PYTHON" "$PYENV"
		. "$PYENV_ACTIVATE"
		if [ -f "$PYENV_REQUIREMENTS" ]; then
			pip install -r "$PYENV_REQUIREMENTS"
		fi
	fi
}

# Note: GENERATED_FILES created by syscall_parser.py contain information from
#	    all architectures/operating systems. This means that we currently need
#		to run the script exactly once.
activate_pyenv
./syscall_parser.py --generate-info \
	--context-target ../generated-in/context_target.json \
	-t linux:arm -t linux:arm64 -t linux:x86 -t linux:x64 -t linux:mips \
	-t windows_2000:x86 -t windows_xpsp2:x86 -t windows_xpsp3:x86 -t windows_7:x86 \
	-t freebsd:x64

# vim: set tabstop=4 softtabstop=4 noexpandtab :
