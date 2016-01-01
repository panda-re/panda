Plugin: network
===========

Summary
-------

The `network` plugin produces a PCAP file containing network traffic seen during the replay. This is handy if you forgot to enable QEMU's native PCAP logging when making the initial recording. You can then analyze the resulting PCAP in Wireshark.

This is only currently supported for the E1000 network card, which is the default for x86 guests.

Arguments
---------

* `file`: string, no default. The filename to save the network traffic to.

Dependencies
------------

None.

APIs and Callbacks
------------------

None.

Example
-------

To save traffic to `foo.pcap`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda network:file=foo.pcap
