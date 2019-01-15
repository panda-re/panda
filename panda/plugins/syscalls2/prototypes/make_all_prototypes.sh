#!/bin/bash


function activate_pyenv() {
	if [ -f "$PYENV_ACTIVATE" ]; then
		. "$PYENV_ACTIVATE"
	else
		virtualenv -p "$PYTHON" "$PYENV"
		. "$PYENV_ACTIVATE"
		pip install -r ../requirements3.txt
	fi
}

# linux - use python3 in a virtualenv
PYTHON="python3"
PYENV="../pyenv3"
PYENV_ACTIVATE="$PYENV/bin/activate"
activate_pyenv
./make_linux_prototypes.py -t linux:x86:ubuntu
./make_linux_prototypes.py -t linux:arm:ubuntu
deactivate

# windows - use system python2.7
./make_windows_prototypes.py all_windows_prototypes.txt

