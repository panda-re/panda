Plugin: serial_taint
===========

Summary
-------
This plugin labels incoming serial port data as tainted and reports when a
serial port transmits tainted data.

When the pandalog is enabled, tainted transmit reports are written to the PANDA log file instead of `stderr`.

Arguments
---------

| Name                | Default    | Description                                             |
| ------------------- | ---------- | ------------------------------------------------------- |
| `input_label`       | `0xC0FFEE42` | The default value used to label incoming data.        |
| `positional_labels` | `false` | Incoming serial port data is labled in a monotonic fashion starting with zero. Each receive increments the label by one.|
| `disable_taint_input` | `false` | Disables labeling of incoming serial port data. |
| `disable_taint_reports` | `false` | Disables reporting of tainted transmits. |

Dependencies
------------
* Taint 2

APIs and Callbacks
------------------
None

Example
-------
```
qemu-system-i386 -m 2048 \
  -chardev pipe,id=com1,path=/tmp/com1 -device pci-serial,chardev=com1 \
  -replay serialwrite -panda stringsearch:str="hello world" \
  -panda tstringsearch -panda serial_taint
```
