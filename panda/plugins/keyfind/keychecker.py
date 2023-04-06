from pandare import Panda
import binascii
from OpenSSL import SSL
import sys
import os
import pyshark
import itertools
import time




key_candidates = set()
hooked_ret_addrs = set()

#get the list of valid tls 1.3 ciphers
#ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
#ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
#conn = SSL.Connection(ctx)
#ciphers = conn.get_cipher_list()
#ciphers = list(filter(lambda cipher: cipher[0:4] == "TLS_", ciphers))

secret_size = 0
client_random = None
selected_cipher = None
#selected_cipher = "TLS_CHACHA20_POLY1305_SHA256"        #TODO delete this
selected_cipher = "TLS_AES_128_GCM_SHA256"        #TODO delete this
#selected_cipher = "TLS_AES_256_GCM_SHA384"        #TODO delete this


pcap_filename = sys.argv[1]

def get_client_random():
    capture = pyshark.FileCapture(pcap_filename,
                        debug=False)

    global client_random

    for packet in capture:
        #packets sent from the client have a high source port and 443 as dest port
        if 'tls' in packet and packet['tcp'].dstport.hex_value == 443 and packet['tls'].has_field("handshake_random"):
            client_random = "".join(packet['tls'].handshake_random.get_default_value().split(":"))
            print(f"client random: {client_random}")
            capture.close()
            return True

    capture.close()
    return False
 




def pyshark_decrypt():
#    capture = pyshark.FileCapture('./hooks_test.pcap',
#                        override_prefs={'tls.keylog_file': os.path.abspath('./test_keyfile.txt')},
#                        debug=True)
    capture = pyshark.FileCapture(pcap_filename,
                        override_prefs={'tls.keylog_file': os.path.abspath('./test_keyfile.txt')},
                        debug=False)

    count = 0
    for packet in capture:
        if 'http' in packet:
            count += 1

    capture.close()

    return count

def find_client_handshake_key():
    pass

def find_server_handshake_key():
    #for each pair in heap_pairs.txt  
    #set first buf = client_app_traffic_secret, second buf = server_app_traffic_secret
        #check against every entry in heap_writes.txt, set to server_handshake_traffic_secret
        #write to a tmp file
        #get number of decrypted packets
    
    #sanity check, there should only be one correct answer

    names = ["CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "SERVER_HANDSHAKE_TRAFFIC_SECRET"]

    f = open("heap_pairs.txt", "r")
    all_pairs = f.read().strip().split("\n")
    f.close()
    print(f"all pairs: {len(all_pairs)}")

    f = open("heap_writes.txt", "r")
    heap_writes = f.read().strip().split("\n")
    f.close()
    print(f"len heap writes: {len(heap_writes)}")

    file_data = None

    for pair in all_pairs:
        p = pair.split(":")
        client_traffic_secret = p[0]
        server_traffic_secret = p[1]

        for server_handshake_secret in heap_writes:
            file_data = f"{names[2]} {client_random} {server_handshake_secret}\n{names[1]} {client_random} {server_traffic_secret}\n{names[0]} {client_random} {client_traffic_secret}\n"
            #print("file data")
            #print(file_data)

            f = open("test_keyfile.txt", "w")
            f.write(file_data)
            f.close()

            decrypted_packets = pyshark_decrypt()
            print(f"decrypted {decrypted_packets} packets")
        break


        



    pass


if not get_client_random():
    print("couldn't get the client_random from the pcap")
    exit(1)

find_server_handshake_key()

