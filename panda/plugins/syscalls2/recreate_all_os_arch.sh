#!/bin/bash

PYTHON="python2"
PYENV="pyenv2"
PYENV_ACTIVATE="$PYENV/bin/activate"

function activate_pyenv() {
	if [ -f "$PYENV_ACTIVATE" ]; then
		. "$PYENV_ACTIVATE"
	else
		virtualenv -p "$PYTHON" "$PYENV"
		. "$PYENV_ACTIVATE"
		pip install -r requirements2.txt
	fi
}

activate_pyenv
./syscall_parser.py --generate-info -o ./ -t linux:arm -t linux:x86 -t windows_7:x86 -t windows_xpsp2:x86 -t windows_xpsp3:x86 -t windows_2000:x86

