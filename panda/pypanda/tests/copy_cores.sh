#!/bin/bash
 COREFILE=$(find . -maxdepth 1 -name "core*" | head -n 1) # find core file
 if [[ -f "$COREFILE" ]]; then
   echo "Found corefile at $COREFILE"
   tar cvfz build.tar.gz ../../../build
   TIME=$(date +%s)
   curl -T $COREFILE ftp://travis:thisistravis@new.state.actor/core_${TIME}
   curl -T build.tar.gz ftp://travis:thisistravis@new.state.actor/build_${TIME}.tar.gz
   rm $COREFILE
 fi
