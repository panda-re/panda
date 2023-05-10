Plugin: keyfind
===========

Summary
-------

The `keyfind` plugin attempts to extract TLS keys from a replay in which a TLS 1.3 connection is established. It does so by watching every memory write, and checking if the data written could be a potential key, and then logging this data to a file. Once the replay is complete, the actual keys can be identified using `keychecker.py`. 

The input to the plugin is a recording where the guest establishes a TLS 1.3 connection, and a packet capture of that TLS session. The input to `keychecker.py` is the same packet capture, and the list of potential keys identified by `keyfind` (`key_candidates.txt` by default). If successful, `keychecker` produces a keyfile (`verified_keys.txt` by default) in the same format as the OpenSSL keylogfile, so that these keys can be used by external programs.  



Arguments
---------

`keyfind` is designed to be run on a recording in which a TLS session is established. It requires a .pcap file of the TLS session. 

`keychecker.py` requires that same .pcap file, and a list of potential keys to check (produced by `keyfind`).

Dependencies
------------

`keyfind` depends on libpcap, which can be installed with `apt-get install libpcap-dev ` or equivalent.

`keychecker.py` depends on pyshark, which can be installed with `pip install pyshark`.

APIs and Callbacks
------------------

None.

Example
-------

First, create a recording in which the guest establishes a TLS connection, and create a .pcap file at the same time. Start PANDA with normal arguments, and set a filename for the recorded packet capture

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 \
        -net dump,file=tls_session.pcap
        
Once the guest is running, open the QEMU monitor (Ctrl-a) and run `begin_record [tls_recording_name]` to start the record. Close the monitor, then run commands which will establish a TLS connection. Then, open the monitor again and run `end_record` to save the recording. 


Once a recording is created, run PANDA with `keyfind` and provide the .pcap file as an argument:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 \
        -replay tls_recording_name \
        -panda keyfind:pcap=tls_session.pcap

The information in the .pcap file allows keyfind to identify the ciphersuite that was used, and by extension, the size of the keys used to encrypt data. After successful execution, keyfind will produce a list of values that may be cryptographic keys, and write them to `key_candidates.txt`. 

Lastly, run `keychecker.py` to identify which values in `key_candidates.txt` are actually TLS keys:

    python keychecker.py tls_session.pcap key_candidates.txt
    
`keychecker` conducts a search for four keys:
- SERVER_HANDSHAKE_TRAFFIC_SECRET
- SERVER_TRAFFIC_SECRET_0
- CLIENT_HANDSHAKE_TRAFFIC_SECRET
- CLIENT_TRAFFIC_SECRET_0

if all four are found, they are written to `verified_keys.txt`. They are written using the OpenSSL's standard keylogfile format, and can be easily used by other programs (e.g. Wireshark, see https://wiki.wireshark.org/TLS for details). 
