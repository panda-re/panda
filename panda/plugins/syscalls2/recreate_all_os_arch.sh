#!/bin/bash

PYTHON="python2"
PYENV="pyenv"
PYENV_ACTIVATE="$PYENV/bin/activate"

function activate_pyenv() {
	if [ -f "$PYENV_ACTIVATE" ]; then
		. "$PYENV_ACTIVATE"
	else
		virtualenv -p "$PYTHON" "$PYENV"
		. "$PYENV_ACTIVATE"
		pip install -r requirements.txt
	fi
}

if [ "$SYSCALL_PARSER_OLD" != "" ]; then
	./syscall_parser_old.py ./ linux arm linux x86 windows_7 x86 windows_xpsp2 x86 windows_xpsp3 x86 windows_2000 x86
else
	activate_pyenv
	./syscall_parser.py --generate-info -o ./ -t linux:arm -t linux:x86 -t windows_7:x86 -t windows_xpsp2:x86 -t windows_xpsp3:x86 -t windows_2000:x86
fi
