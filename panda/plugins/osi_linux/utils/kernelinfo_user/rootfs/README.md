Minimal root filesystem for generating kernelinfo with a pyplugin. To use, copy in correct `busybox` and `user_prog` binaries.  If we decide to use this more often, we'll likely just provide all of them in the rootfs or initrd image.

Then generate the fs:
```bash
#cwd=rootfs!
cd find . | cpio -H newc -o > ../customfs.cpio
```

Then you can run pypanda with something like:
```python
args="--nographic \
  -kernel ./vmlinuz \
  -initrd customfs.cpio \
  -append 'console=ttyS0 earlyprintk=serial nokaslr init=/user_prog root=/dev/ram0'"

#... other stuff

panda.pyplugins.load_all('/path/to/panda/plugins/osi_linux/utils/kernelinfo_user/kernelinfo_plugin.py', args=dict({'kallsyms':kallsyms}))
```

If you would like to extract kallsyms statically, use `kallsyms-finder` from [vmlinux-to-elf](https://github.com/zestrada/vmlinux-to-elf)
