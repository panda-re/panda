#!/bin/bash

PYTHON="python2"
PYENV="pyenv"
PYENV_ACTIVATE="$PYENV/bin/activate"

function activate_pyenv() {
	if [ -f "$PYENV_ACTIVATE" ]; then
		. "$PYENV_ACTIVATE"
	else
		virtualenv -p "$PYTHON" pyenv
		. "$PYENV_ACTIVATE"
		pip install -r requirements.txt
	fi
}

if [ "$SYSCALL_PARSER_OLD" != "" ]; then
	./syscall_parser_old.py ./ linux arm linux x86 windows7 x86 windowsxp_sp2 x86 windowsxp_sp3 x86
else
	activate_pyenv
	./syscall_parser.py -o ./ -t linux:arm -t linux:x86 -t windows7:x86 -t windowsxp_sp2:x86 -t windowsxp_sp3:x86
fi
