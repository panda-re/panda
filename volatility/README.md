QemuMemoryAccess Volatility address space
===
This address space allows volatility to read a VM's memory while it is running.

It uses the request structure format defined in
[memory-access.c](../qemu/memory-access.c),
and communicates through a UNIX socket.

Installation
---
Copy or symlink [pmemaddressspace.py](pmemaddressspace.py) into `$VOLATILITY/volatility/plugins/addrspaces`

Usage
---
Run qemu as you normally would, and send `pmemaccess /path/to/socket` to the
qemu monitor. This will create the UNIX socket for use by volatility.

Then run volatility:
`
python vol.py [plugin] -f [/path/to/socket] --profile=[profile]
`
