#!/bin/bash

PYTHON="python3"
PYENV="pyenv3"
PYENV_ACTIVATE="$PYENV/bin/activate"
PYENV_REQUIREMENTS="requirements3.txt"

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

activate_pyenv
./prototype_parser.py -t linux:x64:generic
./prototype_parser.py -t linux:x86:ubuntu
./prototype_parser.py -t linux:arm:ubuntu
./prototype_parser.py -t linux:arm64:ubuntu
./prototype_parser.py -t linux:mips:generic
./prototype_parser.py -t win2000:x86:volatility
./prototype_parser.py -t xp_sp2:x86:volatility
./prototype_parser.py -t xp_sp3:x86:volatility
./prototype_parser.py -t win2003_sp0:x86:volatility
./prototype_parser.py -t win2003_sp12:x64:volatility
./prototype_parser.py -t win2003_sp12:x86:volatility
./prototype_parser.py -t vista_sp0:x64:volatility
./prototype_parser.py -t vista_sp0:x86:volatility
./prototype_parser.py -t vista_sp12:x64:volatility
./prototype_parser.py -t vista_sp12:x86:volatility
./prototype_parser.py -t win7_sp01:x64:volatility
./prototype_parser.py -t win7_sp01:x86:volatility
./prototype_parser.py -t win8_sp0:x64:volatility
./prototype_parser.py -t win8_sp0:x86:volatility
./prototype_parser.py -t win8_sp1:x64:volatility
./prototype_parser.py -t win8_sp1:x86:volatility

# vim: set tabstop=4 softtabstop=4 noexpandtab :
