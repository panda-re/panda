# ~/workspace/qemu/build/qemu-system-x86_64 -m 4G \
#     -chardev socket,id=char0,reconnect=0,path=/tmp/vhost4.socket \
#     -device vhost-user-vsock-pci,chardev=char0 \
#     -drive file=~/.panda/ubuntu-22.04-server-cloudimg-amd64-disk-kvm.img,format=qcow2 \
#     -monitor stdio \ 
DEBUG=
echo $#
if [ "$#" -eq 1 ]; then
    echo "debug"
    DEBUG="gdb --args"
fi

QEMU=`realpath /home/luke/workspace/panda/build/x86_64-softmmu/panda-system-x86_64`
VMSOCK=/tmp/vhost4.socket
QCOW=`realpath /home/luke/.panda/ubuntu-22.04-server-cloudimg-amd64-disk-kvm.img`
# -mem-prealloc
#-object memory-backend-file,share=on,id=mem0,size=512M,mem-path="/tmp" \

$DEBUG $QEMU \
          -drive file=$QCOW,format=qcow2,if=virtio -m 4G  \
          -object memory-backend-file,share=on,id=mem0,size=4G,mem-path="mem.img" \
          -numa node,memdev=mem0 \
          -chardev socket,id=char0,reconnect=0,path=$VMSOCK \
          -device vhost-user-vsock-pci,chardev=char0 -nographic