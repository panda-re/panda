#!/bin/bash
#$1 is the scratch dir
#$2 is the cache qcow
#$3 is the user qcow
#$4 is the system qcow
#$5 is the sdcard qcow

if [[ "$#" -lt 5 ]] ; then
    echo "Usage: runandroid.sh <dir> <cache> <user> <system> <sdcard> args..."
    exit 1
fi

# Is $1/ramdisk/ present?
use_ramdisk=0
if [ -d "$1/ramdisk" ]
then
    use_ramdisk=1
else
    echo "WARNING: not using temp directory. Please consider creating a ./ramdisk directory"
    echo "Continuing in 5 seconds"
    sleep 5
fi
# copy qcows to ramdisk
if [ $use_ramdisk -eq 1 ]
then
    cp "$1/$2" "$1/ramdisk"
    cache="$1/ramdisk/$2"
    cp "$1/$3" "$1/ramdisk"
    userdata="$1/ramdisk/$3"
    cp "$1/$4" "$1/ramdisk"
    system="$1/ramdisk/$4"
    cp "$1/$5" "$1/ramdisk"
    sdcard="$1/ramdisk/$5"
else
    cache="$1/$2"
    userdata="$1/$3"
    system="$1/$4"
    sdcard="$1/$5"
fi

CPU=""
# For Android > 3.1, use a cortex-a9 cpu
CPU="-cpu cortex-a9"

arm-softmmu/qemu-system-arm -M android_arm $CPU  -kernel "$1/kernel" -initrd "$1/ramdisk.img"  -global goldfish_nand.system_path="$system" -global goldfish_nand.user_data_path="$userdata"  -global goldfish_nand.cache_path="$cache" -append  "console=ttyS0 ndns=2 qemu=1 no_console_suspend=1 qemu.gles=0 android.qemud=ttyS1" -m 2G -no-reboot -monitor telnet:localhost:4321,server,nowait -show-cursor -serial stdio -serial telnet:localhost:4421,server,nowait -display sdl -net nic,vlan=1 -net user,vlan=1 -global goldfish_mmc.sd_path="$sdcard" -android 

# qemu exited, copy the files back if they are clean
function img_check {
    qemu-img check "$1"
    status=$?
    # 0 is good, 3 is leaks
    # 2 is errors, 1 is errors so bad qemu-img failed
    if [ $status -eq 1 -o $status -eq 2 ]; then
	echo "ERROR: Corrupt QCOW!!!! Not copying back...."
    fi
    return $status
}

function try_restore {
    if img_check "$1"
    then
	if [ $use_ramdisk -eq 1 ]
	then
	    cp "$1" "$2"
	fi
    else
	cp "$1" "$2.broken"
    fi
}

try_restore "$cache" "$1/$2"
try_restore "$userdata" "$1/$3"
try_restore "$system" "$1/$4"
try_restore "$sdcard" "$1/$5"

