from pandare import Panda
from OpenSSL import SSL
import sys
import os
import pyshark



client_random = None


SERVER_HANDSHAKE_SECRET = None
SERVER_TRAFFIC_SECRET_0 = None
CLIENT_HANDSHAKE_SECRET = None
CLIENT_TRAFFIC_SECRET_0 = None

pcap_filename = sys.argv[1]
key_candidates_filename = sys.argv[2]

key_candidates = []
total_keys = 0
names = ["SERVER_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_0", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0"]

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
        if 'tls' in packet and packet['tls'].has_field("handshake"):
            if packet['tls'].handshake == "Handshake Protocol: Finished":       #this is encrypted with the client handshake secret
                capture.close()
                return True

    capture.close()

    return False

def pyshark_find_server_traffic_secret():
    capture = pyshark.FileCapture(pcap_filename,
                        override_prefs={'tls.keylog_file': os.path.abspath('./test_keyfile.txt')},
                        debug=False)

    count = 0
    for packet in capture:

        #packets sent from the server have a high dest port and 443 as source port
        #all encrypted packets have an opaque content type "23", the decrypted packets also have a content type, also "23" when the content is application data
        #see RFC 8446 pg. 80-81, 122
        if 'tls' in packet and packet['tcp'].srcport.hex_value == 443:
            if packet['tls'].has_field("record_opaque_type") and packet['tls'].has_field("record_content_type"):
                if packet['tls'].get_field_value("record_opaque_type") == "23" and packet['tls'].get_field_value("record_content_type") == "23":
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

        #packets sent from the client have a high source port and 443 as dest port
        #all encrypted packets have an opaque content type "23", the decrypted packets also have a content type, also "23" when the content is application data
        #see RFC 8446 pg. 80-81, 122
        if 'tls' in packet and packet['tcp'].dstport.hex_value == 443:
            if packet['tls'].has_field("record_opaque_type") and packet['tls'].has_field("record_content_type"):
                if packet['tls'].get_field_value("record_opaque_type") == "23" and packet['tls'].get_field_value("record_content_type") == "23":
                    capture.close()
                    return True


    capture.close()
    return False




def pyshark_find_server_handshake_secret():
    capture = pyshark.FileCapture(pcap_filename,
                        override_prefs={'tls.keylog_file': os.path.abspath('./test_keyfile.txt')},
                        debug=False)

    for packet in capture:
        if 'tls' in packet and packet['tls'].has_field("handshake"):
            if packet['tls'].handshake == "Handshake Protocol: Certificate":        #this part is encrypted with the server handshake key in TLS 1.3
                capture.close()
                return True

    capture.close()

    return False


def find_server_handshake_key():

    file_data = None

    print("\nsearching for server handshake key...")
    count = 0
    
    for server_handshake_secret in key_candidates:
        file_data = f"{names[0]} {client_random} {server_handshake_secret}\n"

        f = open("test_keyfile.txt", "w")
        f.write(file_data)
        f.close()

        if pyshark_find_server_handshake_secret():
            return server_handshake_secret

        count += 1
        print(f"\rtried {count}/{total_keys} possible keys...", end="")



def find_client_handshake_key():
    file_data = None


    print(f"\nsearching for client handshake key...")
    count = 0
    for client_handshake_secret in key_candidates:
        file_data = f"{names[2]} {client_random} {client_handshake_secret}\n"

        f = open("test_keyfile.txt", "w")
        f.write(file_data)
        f.close()

        if pyshark_find_client_handshake_secret():
            return client_handshake_secret

        count += 1
        print(f"\rtried {count}/{total_keys} possible keys...", end="")




def find_client_traffic_key():
    file_data = None
    ctk = None
    stk = None

    print("\nsearching for client traffic key...")
    count = 0
    for client_traffic_key in key_candidates:
        file_data = f"{names[0]} {client_random} {SERVER_HANDSHAKE_SECRET}\n{names[2]} {client_random} {CLIENT_HANDSHAKE_SECRET}\n{names[3]} {client_random} {client_traffic_key}"

        f = open("test_keyfile.txt", "w")
        f.write(file_data)
        f.close()

        if pyshark_find_client_traffic_secret():
            print(f"\nfound client traffic secret: {client_traffic_key}")
            ctk = client_traffic_key
            break

        count += 1
        print(f"\rtried {count}/{total_keys} possible keys...", end="")


    print("\nsearching for server traffic key...")
    count = 0
    for server_traffic_key in key_candidates:
        file_data = f"{names[0]} {client_random} {SERVER_HANDSHAKE_SECRET}\n{names[1]} {client_random} {server_traffic_key}\n{names[2]} {client_random} {CLIENT_HANDSHAKE_SECRET}"

        f = open("test_keyfile.txt", "w")
        f.write(file_data)
        f.close()

        if pyshark_find_server_traffic_secret():
            print(f"\nfound server traffic secret: {server_traffic_key}")
            stk = server_traffic_key
            break

        count += 1
        print(f"\rtried {count}/{total_keys} possible keys...", end="")


    return (ctk, stk)



f = open(key_candidates_filename, "r")
key_candidates = f.read().strip().split("\n")
f.close()
total_keys = len(key_candidates)



if not get_client_random():
    print("couldn't get the client_random from the pcap")
    exit(1)

SERVER_HANDSHAKE_SECRET = find_server_handshake_key()
if SERVER_HANDSHAKE_SECRET == None:
    print("failed to find server handshake secret")
    exit(1)
print(f"\nfound server handshake secret: {SERVER_HANDSHAKE_SECRET}")


CLIENT_HANDSHAKE_SECRET = find_client_handshake_key()
if CLIENT_HANDSHAKE_SECRET == None: 
    print("failed to find client handshake secret")
    exit(1)
print(f"\nfound client handshake secret: {CLIENT_HANDSHAKE_SECRET}")


CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0 = find_client_traffic_key()
if CLIENT_TRAFFIC_SECRET_0 == None or SERVER_TRAFFIC_SECRET_0 == None:
    print(f"failed to find client/server traffic secrets")
    exit(1)


print("found all keys!")
write_keyfile()