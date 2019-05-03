from pypanda import *
from time import sleep
from sys import argv
from scapy.all import Ether, wrpcap

out_file = argv[2]
panda = Panda(qcow=argv[1])
recording = "/path/to/recording"

@panda.callback.init
def init(handle):
	panda.register_callback(handle, panda.callback.replay_handle_packet, handle_packet)
	return True

packets = [] # keep all the packets
@panda.callback.replay_handle_packet
def handle_packet(cpustate,buf,size,direction,old_buf_addr):
	packets.append(Ether("".join([chr(buf[i]) for i in range(size)])))
	return 0

panda.load_python_plugin(init,"network_to_pcap")
panda.begin_replay(recording)
panda.run()
wrpcap(out_file,packets) # write output to pcap
