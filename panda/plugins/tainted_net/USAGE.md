Plugin: tainted\_net
===========

Summary
-------

The `tainted_net` plugin allows the user to apply taint to packets that arrive over the network, or to query taint on packets about to be sent out over the network.

Note that the `tainted_net` plugin replaces the network related options in the original `taint` plugin, allowing them to be used with the new and improved `taint2` plugin.

Arguments
---------

* `label_incoming_network`: boolean. Whether to apply taint labels to incoming network traffic.
* `query_outgoing_network`: boolean. Whether to display taint on outgoing network traffic.
* `semantic`: boolean. Whether to apply a different label to each tainted byte in the incoming packet.  An additional file will be generated for ida taint so semantic labels can be displayed in IDA Pro.
* `pos`: boolean. Whether to apply a different label to each tainted byte in the incoming packet.  The packet number will be represented by the high order bits in the taint label.  The byte offset in the packet will be represented by the low order bits in the taint label.  See `maximum_packet_size`.
* `maximum_packet_size`: integer.  The maximum number of bytes expected in received TCP packets.  This parameter is only used when positional tainting is enabled.  This value should be one of 65535, 32767, 16383, 8191, 4095, or 2047.  The taint labels when positional tainting are a combination of the packet number and the byte offset in the packet.  Both of these values are combined in a single unsigned 32-bit integer.  Reserving more bits for the packet size reduces the number of bits available for the packet count.  To ensure that taint labels aren't reused, pick the lowest possible value for TCP packet size that will work with your specific recording.  The default value for TCP packet size is 65535.
* `packets`: string. List of packet numbers or ranges to taint.  Values should be separated by colons.  Example: 1-3:5
* `ip_proto`: string.  List of IPV4 protocol numbers or ranges to taint.
* `bytes`: string.  List of byte offsets or ranges in each packet to taint.
* `ip_src`: string.  If specified, only packets received from the specified IPV4 address will be considered for tainting.
* `ip_dst`: string.  If specified, only packets destined for the specified IPV4 address will be considered for tainting.
* `eth_type`: string.  Type of packet encapulated in the received ethernet packet.
* `file`: string, defaults to "tainted\_net\_query.csv". The name of the file to which outgoing network traffic taint information will be written.

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

To taint the string `quick` and then see if it is sent out over the network, writing the outgoing taint information to quick\_tnss.csv, do:

    $PANDA_PATH/i386-softmmu/qemu-system-i386 -net nic -net user \
        -replay foo \
        -panda stringsearch:str="quick" -panda tstringsearch \
        -panda tainted_net:query_outgoing_network=true,file=quick_tnss.csv

