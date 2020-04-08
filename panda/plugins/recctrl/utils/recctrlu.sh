#!/bin/bash
# recctrlu wrapper script.
# Allows easier integration of the utility with pam.d.

RECCTRL=/usr/local/sbin/recctrlu
USERS=(panda)

# Check that PAM variables are set and PAM_USER matches.
[ "$PAM_USER" != "" ] || exit 1
[ "$PAM_TYPE" != "" ] || exit 1
[[ " ${USERS[@]} " =~ " ${PAM_USER} " ]] || exit 1

${RECCTRL} ${PAM_TYPE} ${PAM_USER}_session
