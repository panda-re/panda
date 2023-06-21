Plugin: keyfind
===========

Summary
-------

The `keyfind` plugin attempts to extract TLS keys from a replay in which a TLS 1.3 connection is established. It does so by watching every memory write, and checking if the data written could be a potential key, and then logging this data to a file. Once the replay is complete, the actual keys can be identified using `keychecker.py`. 

The input to the plugin is a recording where the guest establishes a TLS 1.3 connection. The input to `keychecker.py` is a packet capture of the TLS session, and the list of potential keys identified by `keyfind` (`key_candidates.txt` by default). If successful, `keychecker` produces a keyfile (`verified_keys.txt` by default) in the same format as the OpenSSL keylogfile, so that these keys can be used by external programs.  



Arguments
---------

`keyfind` is designed to be run on a recording in which a TLS session is established. It requires the user to provide either the name of the ciphersuite (`ciphersuite_name`) used to encrypt the TLS traffic, or the corresponding ciphersuite ID (`ciphersuite_id`), both of which can be extracted from a packet capture of the TLS session.

To recover the ciphersuite ID from a .pcap file, the following command can be used:

    $ tshark -Y "ssl.handshake.type == 2" -V -e tls.handshake.ciphersuite -Tfields -nr capture.pcap

Alternatively, the name of the ciphersuite (one of `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, or `TLS_CHACHA20_POLY1305_SHA256`) can be provided to keyfind.

`keychecker.py` requires the packet capture of the TLS session, and a list of potential keys to check (produced by `keyfind`, saved as `key_candidates.txt` by default).

Dependencies
------------

`keychecker.py` depends on pyshark, which can be installed with `pip install pyshark`.

APIs and Callbacks
------------------

None.

Example
-------

First, create a recording in which the guest establishes a TLS connection, and create a .pcap file at the same time. Start the guest under PANDA with normal arguments, and set a filename for the recorded packet capture

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 \
        -net dump,file=tls_session.pcap
        
Once the guest is running, open the QEMU monitor (Ctrl-a) and run `begin_record [tls_recording_name]` to start the record. Close the monitor, then run commands which will establish a TLS connection. Then, open the monitor again and run `end_record` to save the recording. 


Once a recording is created, run PANDA with `keyfind` and provide either the name of the ciphersuite, or the ciphersuite ID:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 \
        -replay tls_recording_name \
        -panda keyfind:ciphersuite_name=TLS_AES_256_GCM_SHA384

OR

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 \
        -replay tls_recording_name \
        -panda keyfind:ciphersuite_id=4866

After successful execution, keyfind will produce a list of values that may be cryptographic keys, and write them to `key_candidates.txt`. 

Lastly, run `keychecker.py` to identify which values in `key_candidates.txt` are used to encrypt TLS traffic:

    python keychecker.py tls_session.pcap key_candidates.txt
    
`keychecker` conducts a search for four keys:
- SERVER_HANDSHAKE_TRAFFIC_SECRET
- SERVER_TRAFFIC_SECRET_0
- CLIENT_HANDSHAKE_TRAFFIC_SECRET
- CLIENT_TRAFFIC_SECRET_0

if all four are found, they are written to `verified_keys.txt`. They are written using the OpenSSL's standard keylogfile format, and can be easily used by other programs (e.g. Wireshark, see https://wiki.wireshark.org/TLS for details). 
