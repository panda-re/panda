#!/usr/bin/env bash
#
# Script that checks plugins for missing symbols. The script must be run
# from the top of your PANDA build tree.
#
# ld does the heavy lifting here, looking for symbols in dynamic
# libraries. After several attempts, no way was found to convince ld to
# also lookup missing symbols in the PANDA binary. So, this script was
# created.
#
TARGETS="arm-softmmu i386-softmmu ppc-softmmu x86_64-softmmu"
scriptname=$(basename $0)
scriptdir=$(dirname $0)
errors=0
pandasyms="/tmp/pandasyms.$$.txt"
pluginsyms="/tmp/pluginsyms.$$.txt"

msg() {
    local fmt=$1
    shift
    printf "%s: $fmt\n" $scriptname $* >&2
}

get_undefined() {
    ld "$1" 2>&1 | grep 'undefined reference' | awk -F'[`'\'']' '{print $2}' | sort | uniq
}

get_pandasyms() {
    local panda_bin="$1"/panda-system-${1%%-*}
    if [ ! -x "$panda_bin" ]; then
        msg "Error. Could not find PANDA binary %s." "$panda_bin"
        return 1
    fi
    nm -C "$panda_bin"
}

check_undefined() {
    local lerrors=0
    while read sym; do
        if ! grep -q " [^U] ""$sym" "$3"; then
            if (( lerrors == 0 )); then
                msg "Missing symbol(s) in %s:" "$1"
            fi
            msg "\t%s" "$sym"
            (( lerrors++ ))
        fi
    done < "$2"
    return $lerrors
}

for t in $TARGETS; do
    msg "Processing plugins for %s." "$t"
    get_pandasyms "$t" > "$pandasyms"

    # Use process subsitution instead of pipe to avoid subshell and
    # allow incrementing global errors.
    while read p; do
        get_undefined "$p" > "$pluginsyms"
        check_undefined "$p" "$pluginsyms" "$pandasyms"
        lerrors=$?
        (( errors += lerrors ))
    done < <(find "$t" -iname '*.so')
done

rm -f "$pandasyms" "$pluginsyms"
if (( errors == 0 )); then
    msg "Success! No missing symbols in plugins."
    exit 0
else
    msg "Error! A total of %d (non unique) symbols were found missing from plugins." $errors
    exit 1
fi

