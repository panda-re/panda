#!/usr/bin/env python3
'''
example_network.py

This example implements the networks same functionality as the network plugin in
panda. It registers replay_handle_packet callback, converts the buffer, and
writes the buffer out to a pcap.

Run with: python3 example_network.py i386 out.pcap /path/to/recording
'''
from pypanda import *
from time import sleep
from sys import argv
from scapy.all import Ether, wrpcap

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

packets = [] # keep all the packets
@panda.cb_replay_handle_packet()
def handle_packet(cpustate,buf,size,direction,old_buf_addr):
    buf_int8 = ffi.cast("uint8_t*", buf)
    packets.append(Ether([buf_int8[i] for i in range(size)]))
    return 0

panda.begin_replay(argv[2])
panda.run()
wrpcap(argv[3],packets) # write output to pcap
