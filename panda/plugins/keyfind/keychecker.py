from pandare import Panda
import binascii
from OpenSSL import SSL
import sys
import os
import pyshark
import itertools
import time




#key_candidates = set()
#hooked_ret_addrs = set()

#get the list of valid tls 1.3 ciphers
#ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
#ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
#conn = SSL.Connection(ctx)
#ciphers = conn.get_cipher_list()
#ciphers = list(filter(lambda cipher: cipher[0:4] == "TLS_", ciphers))

client_random = None


SERVER_HANDSHAKE_SECRET = 0
SERVER_TRAFFIC_SECRET_0 = 0
CLIENT_HANDSHAKE_SECRET = 0
CLIENT_TRAFFIC_SECRET_0 = 0

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

def write_keyfile():
    print("writing keys to verified_keys.txt")

    names = ["SERVER_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_0", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0"]

    file_data  = f"{names[0]} {client_random} {SERVER_HANDSHAKE_SECRET}\n"
    file_data += f"{names[1]} {client_random} {SERVER_TRAFFIC_SECRET_0}\n"
    file_data += f"{names[2]} {client_random} {CLIENT_HANDSHAKE_SECRET}\n"
    file_data += f"{names[3]} {client_random} {CLIENT_TRAFFIC_SECRET_0}\n"

    f = open("verified_keys.txt", "w")
    f.write(file_data)
    f.close()



 
def pyshark_find_client_handshake_secret():

    capture = pyshark.FileCapture(pcap_filename,
                        override_prefs={'tls.keylog_file': os.path.abspath('./test_keyfile.txt')},
                        debug=False)

    count = 0
    for packet in capture:
#        if 'tls' in packet:# and packet['tls'].has_field("record"):
#            print(packet)

        if 'tls' in packet and packet['tls'].has_field("handshake"):
            if packet['tls'].handshake == "Handshake Protocol: Finished":       #this is encrypted with the client handshake secret
                capture.close()
                return True
                #print(packet['tls'].handshake)

    capture.close()

    return False

def pyshark_find_server_traffic_secret():
    capture = pyshark.FileCapture(pcap_filename,
                        override_prefs={'tls.keylog_file': os.path.abspath('./test_keyfile.txt')},
                        debug=False)

    count = 0
    for packet in capture:
        if 'tls' in packet:# and packet['tls'].has_field("record"):
            pass
            #print(packet)

        if 'tls' in packet and packet.highest_layer != "TLS" and packet['tcp'].srcport.hex_value == 443:
            capture.close()
            return True


    capture.close()
    return False


def pyshark_find_client_traffic_secret():
    capture = pyshark.FileCapture(pcap_filename,
                        override_prefs={'tls.keylog_file': os.path.abspath('./test_keyfile.txt')},
                        debug=False)

    count = 0
    for packet in capture:
        #if 'tls' in packet:# and packet['tls'].has_field("record"):
        #    pass
        #    #print(packet)

        #packets sent from the client have a high source port and 443 as dest port
        if 'tls' in packet and packet.highest_layer != "TLS" and packet['tcp'].dstport.hex_value == 443:
            capture.close()
            return True


    capture.close()
    return False




def pyshark_find_server_handshake_secret():
#    capture = pyshark.FileCapture('./hooks_test.pcap',
#                        override_prefs={'tls.keylog_file': os.path.abspath('./test_keyfile.txt')},
#                        debug=True)
    capture = pyshark.FileCapture(pcap_filename,
                        override_prefs={'tls.keylog_file': os.path.abspath('./test_keyfile.txt')},
                        debug=False)

    count = 0
    for packet in capture:
#        if 'tls' in packet:# and packet['tls'].has_field("record"):
#            print(packet)
        if 'tls' in packet and packet['tls'].has_field("handshake"):
            if packet['tls'].handshake == "Handshake Protocol: Certificate":        #this part is encrypted with the server handshake key in TLS 1.3
                capture.close()
                return True

    capture.close()

    return False


def find_server_handshake_key():
    #for each pair in heap_pairs.txt  
    #set first buf = client_app_traffic_secret, second buf = server_app_traffic_secret
        #check against every entry in heap_writes.txt, set to server_handshake_traffic_secret
        #write to a tmp file
        #get number of decrypted packets
    
    #sanity check, there should only be one correct answer

    names = ["CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_HANDSHAKE_TRAFFIC_SECRET"]

    f = open("/home/becker/panda_ssl/heap_writes_debug.txt", "r")
    heap_writes = f.read().strip().split("\n")
    f.close()

    file_data = None

    print("\nsearching for server handshake key...")
    count = 0
    for server_handshake_secret in heap_writes:
        file_data = f"{names[2]} {client_random} {server_handshake_secret}\n"

        f = open("test_keyfile.txt", "w")
        f.write(file_data)
        f.close()

        #print(f"trying server_handshake_secret: {server_handshake_secret}")
        #print(f"trying client_traffic_secret: {client_traffic_secret}")
        #print(f"trying server_traffic_secret: {server_traffic_secret}")

        if pyshark_find_server_handshake_secret():
            print(f"found server handshake secret: {server_handshake_secret}")
            return server_handshake_secret

        count += 1
        if count % 100 == 0:
            print(f"tried {count} keys...")



def find_client_handshake_key():
    names = ["CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_HANDSHAKE_TRAFFIC_SECRET"]

    f = open("/home/becker/panda_ssl/heap_pairs.txt", "r")
    all_pairs = f.read().strip().split("\n")
    f.close()

    f = open("/home/becker/panda_ssl/heap_writes.txt", "r")
    heap_writes = f.read().strip().split("\n")
    f.close()

    file_data = None

    pair = all_pairs[0]
    p = pair.split(":")
    client_traffic_secret = p[0]
    server_traffic_secret = p[1]


    print(f"\nsearching for client handshake key...")
    count = 0
    for client_handshake_secret in heap_writes:
        file_data = f"{names[1]} {client_random} {server_traffic_secret}\n{names[3]} {client_random} {client_handshake_secret}\n{names[0]} {client_random} {client_traffic_secret}\n"

        f = open("test_keyfile.txt", "w")
        f.write(file_data)
        f.close()

        #print(f"trying server_handshake_secret: {client_handshake_secret}")
        #print(f"trying client_traffic_secret: {client_traffic_secret}")
        #print(f"trying server_traffic_secret: {server_traffic_secret}")

        if pyshark_find_client_handshake_secret():
            return client_handshake_secret

        count += 1
        if count % 100 == 0:
            print(f"tried {count} keys...")




def find_client_traffic_key():
    names = ["CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_HANDSHAKE_TRAFFIC_SECRET"]

    f = open("/home/becker/panda_ssl/heap_pairs.txt", "r")
    all_pairs = f.read().strip().split("\n")
    f.close()

    f = open("/home/becker/panda_ssl/heap_writes.txt", "r")
    heap_writes = f.read().strip().split("\n")
    f.close()

    file_data = None
    ctk = ""
    stk = ""

    print("\nsearching for client traffic key...")
    count = 0
    for client_traffic_key in heap_writes:
        file_data = f"{names[2]} {client_random} {SERVER_HANDSHAKE_SECRET}\n{names[3]} {client_random} {CLIENT_HANDSHAKE_SECRET}\n{names[0]} {client_random} {client_traffic_key}"

        f = open("test_keyfile.txt", "w")
        f.write(file_data)
        f.close()

        #print(f"trying server_handshake_secret: {SERVER_HANDSHAKE_SECRET}")
        #print(f"trying client_handshake_secret: {CLIENT_HANDSHAKE_SECRET}")
        #print(f"trying client_traffic_secret: {client_traffic_key}")

        if pyshark_find_client_traffic_secret():
            print(f"found client traffic secret: {client_traffic_key}")
            ctk = client_traffic_key
            break

        count += 1
        if count % 100 == 0:
            print(f"tried {count} keys...")


    print("\nsearching for server traffic key...")
    count = 0
    for server_traffic_key in heap_writes:
        file_data = f"{names[2]} {client_random} {SERVER_HANDSHAKE_SECRET}\n{names[1]} {client_random} {server_traffic_key}\n{names[3]} {client_random} {CLIENT_HANDSHAKE_SECRET}"

        f = open("test_keyfile.txt", "w")
        f.write(file_data)
        f.close()

        #print(f"trying server_handshake_secret: {SERVER_HANDSHAKE_SECRET}")
        #print(f"trying client_handshake_secret: {CLIENT_HANDSHAKE_SECRET}")
        #print(f"trying server_traffic_secret: {server_traffic_key}")

        if pyshark_find_server_traffic_secret():
            print(f"found server traffic secret: {server_traffic_key}")
            stk = server_traffic_key
            break

        count += 1
        if count % 100 == 0:
            print(f"tried {count} keys...")


    return (ctk, stk)






if not get_client_random():
    print("couldn't get the client_random from the pcap")
    exit(1)

SERVER_HANDSHAKE_SECRET = find_server_handshake_key()
if SERVER_HANDSHAKE_SECRET == 0:
    print("failed to find server handshake secret")
    exit(1)
print(f"found server handshake secret: {SERVER_HANDSHAKE_SECRET}")


CLIENT_HANDSHAKE_SECRET = find_client_handshake_key()
if CLIENT_HANDSHAKE_SECRET == 0:
    print("failed to find client handshake secret")
    exit(1)
print(f"found client handshake secret: {CLIENT_HANDSHAKE_SECRET}")


CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0 = find_client_traffic_key()
if CLIENT_TRAFFIC_SECRET_0 == 0 or SERVER_TRAFFIC_SECRET_0 == 0:
    print(f"failed to find client/server traffic secrets")
    exit(1)


print("found all keys!")
write_keyfile()