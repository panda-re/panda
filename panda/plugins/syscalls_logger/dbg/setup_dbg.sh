#! /bin/bash

# TODO: replace this with a cleaner python script

TOGGLE_COLOR='\033[0m'
YELLOW='\033[0;33m'

if [ -z "$1" ]; then
    printf "\nUsage: $0 <target>"
    printf "\n\nValid options for <target>:"
    printf "\n\'arm\'"
    printf "\n\'arm-lite\'\n"
    exit 1
fi

# ----------------------------------------------------------------------------------------------------------------------
# PRE-REQS
# ----------------------------------------------------------------------------------------------------------------------

sudo apt-get install -y libguestfs-tools libncurses-dev flex \
    bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf

# Working dir
cd $(dirname "$0")
mkdir -p test_fw
cd test_fw

# ----------------------------------------------------------------------------------------------------------------------
# TEST FS
# ----------------------------------------------------------------------------------------------------------------------

echo -e "\n${YELLOW}DOWNLOADING AND CONVERTING TEST FILESYSTEM...${TOGGLE_COLOR}\n"

if [ "$1" == 'arm-lite' ]; then

    FS_TAR="ubuntu-base-18.04.5-base-armhf.tar.gz"
    FS_IMG="${FS_TAR%.*.*}.img"
    USERNAME="$(whoami)"

    wget -nc -q --show-progress http://cdimage.ubuntu.com/ubuntu-base/releases/18.04/release/$FS_TAR
    sudo virt-make-fs $FS_TAR $FS_IMG
    sudo chown $USERNAME:$USERNAME $FS_IMG
    file $FS_IMG

elif [ "$1" == 'arm' ]; then

    wget -nc -q --show-progress https://cloud-images.ubuntu.com/releases/bionic/release/ubuntu-18.04-server-cloudimg-armhf.squashfs

else

    printf "Invalid target option! No matching FS\n"
    exit 1

fi

# ----------------------------------------------------------------------------------------------------------------------
# KERNEL BUILD
# ----------------------------------------------------------------------------------------------------------------------

echo -e "\n${YELLOW}BUILDING KERNEL...${TOGGLE_COLOR}\n"

# Get kernel
KERNEL_TAR="linux-4.4.138.tar.gz"
KERNEL_DIR="${KERNEL_TAR%.*.*}"
wget -nc -q --show-progress https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/$KERNEL_TAR
tar xvzf $KERNEL_TAR

# Config kernel
cd $KERNEL_DIR

make ARCH=arm vexpress_defconfig        # QEMU's vexpress-a9
sed -i 's/=m/=y/g' .config              # Make everything built-in

cat <<EOF >> .config
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_EARLY_PRINTK=y
CONFIG_DEBUG_INFO=y

CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BALLOON=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_RING=y

CONFIG_BLK_DEV_LOOP=y
CONFIG_BLK_DEV_LOOP_MIN_COUNT=8
CONFIG_BLK_DEV_CRYPTOLOOP=n

CONFIG_BLK_DEV_RAM=y
CONFIG_BLK_DEV_RAM_COUNT=4
CONFIG_BLK_DEV_RAM_SIZE=4096

CONFIG_MODULES=y
CONFIG_ARM_MODULE_PLTS=y
CONFIG_MODULES_USE_ELF_REL=y
CONFIG_MODULE_UNLOAD=y
CONFIG_UEVENT_HELPER=y

CONFIG_SQUASHFS=y
CONFIG_XZ_DEC=y
CONFIG_SQUASHFS_XZ=y

EOF

time make ARCH=arm CROSS_COMPILE=arm-none-eabi- -j $(nproc) zImage dtbs
cd ..

# ----------------------------------------------------------------------------------------------------------------------
# KERNEL VMI
# ----------------------------------------------------------------------------------------------------------------------

echo -e "\n${YELLOW}GENERATING DWARF JSON...${TOGGLE_COLOR}\n"

# Install a local copy of the Go toolchain if missing
if ! [ -x "$(command -v go)" ]; then
    GO_TAR="go1.15.2.linux-amd64.tar.gz"
    GO_DIR=$(pwd)/go_toolchain
    wget -nc -q --show-progress https://golang.org/dl/$GO_TAR
    mkdir $GO_DIR
    tar -C $GO_DIR -xzf $GO_TAR
    export PATH=$PATH:$GO_DIR/go/bin
fi

# Create DWARF JSON
DWARF_JSON="dwarf_info.json"
git clone git@github.com:volatilityfoundation/dwarf2json.git
cd dwarf2json
go build
./dwarf2json linux --elf ../$KERNEL_DIR/vmlinux > ../$DWARF_JSON
cd ..

echo -e "\n"
file $DWARF_JSON

echo -e "\n${YELLOW}GENERATING OSI PROFILE...${TOGGLE_COLOR}\n"

# Create OSI config
OSI_INFO="kernel_info.conf"
KERN_INFO_GBD_DIR="../../../../plugins/osi_linux/utils/kernelinfo_gdb"

echo $KERN_INFO_OUT_DIR

$KERN_INFO_GBD_DIR/run.sh $KERNEL_DIR/vmlinux $OSI_INFO

file $OSI_INFO
sed -i '1s/^/[debian:4.4.138:32]\n/' $OSI_INFO