#!/bin/bash
# Mirror windows system call overlays from the Volatility project.

svn_url="https://github.com/volatilityfoundation/volatility/branches/master"
svn_path="volatility/plugins/overlays/windows"
svn_tmp="volatility_tmp${RANDOM}"
volatility_local="volatility_local"

svn export "$svn_url"/"$svn_path" "$svn_tmp"
mv -f "$svn_tmp"/*_syscalls.py "$volatility_local"
chmod 644 "$volatility_local"/*.py
rm -rf "$svn_tmp"

# vim: set tabstop=4 softtabstop=4 noexpandtab :
