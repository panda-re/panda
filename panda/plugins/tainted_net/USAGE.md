Plugin: tainted_net
===========

Summary
-------

The `tainted_net` plugin allows the user to apply taint to packets that arrive over the network, or to query taint on packets about to be sent out over the network.

Note that the `tainted_net` plugin replaces the network related options in the original `taint` plugin, allowing them to be used with the new and improved `taint2` plugin.

Arguments
---------

* `label_incoming_network`: boolean. Whether to apply taint labels to incoming network traffic.
* `query_outgoing_network`: boolean. Whether to display taint on outgoing network traffic.
* `positional_taint`: boolean. Whether to apply a different label to each tainted byte in the incoming packet.
* `file`: string, defaults to "tainted_net_query.csv". The name of the file to which outgoing network traffic taint information will be written.

At least one of `label_incoming_network` or `query_outgoing_network` must be true.

Dependencies
------------

The `tainted_net` plugin uses `taint2` to enable and propagate taint.

APIs and Callbacks
------------------

None

Example
-------

To taint incoming network data and then find out what instructions depend on data from the network:

    $PANDA_PATH/i386-softmmu/qemu-system-i386 -net nic -net user \
        -replay foo \
        -panda tainted_net:label_incoming_network=true \
        -panda tainted_instr

Note that the `taint2` plugin is not explicitly listed here because it is automatically loaded by the `tainted_net` plugin. If you wanted to pass custom options to `taint2`, such as disabling tainted pointers, you could instead do:

    $PANDA_PATH/i386-softmmu/qemu-system-i386 -net nic -net user \
        -replay foo \
        -panda taint2:no_tp=y \
        -panda tainted_net:label_incoming_network=true \
        -panda tainted_instr

To taint the string `quick` and then see if it is sent out over the network, writing the outgoing taint information to quick_tnss.csv, do:

    $PANDA_PATH/i386-softmmu/qemu-system-i386 -net nic -net user \
        -replay foo \
        -panda stringsearch:str="quick" -panda tstringsearch \
        -panda tainted_net:query_outgoing_network=true,file=quick_tnss.csv
        