#!/bin/bash
if [ "$#" -ne 2 ]; then
   echo "run.sh [debuggable vmlinux file] [output file]"
   exit
fi

VMLINUX=$1
OUTPUT_FILE=$2
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gdb $VMLINUX -ex "source ${SCRIPTDIR}/gdb_prototype_parser.py" -ex "get_syscall_table $OUTPUT_FILE" -ex "q"
