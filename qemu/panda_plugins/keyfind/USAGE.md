Plugin: keyfind
===========

Summary
-------

The `keyfind` plugin attempts to locate the point within a replay where TLS master secrets are generated. It does so by watching every memory read and write, and then using this data as a possible key to decrypt some sample data.

The plugin is described in greater detail in PANDA's [SSL Tutorial](docs/panda_ssltut.md).

The input to the plugin is a configuration file that contains information about the encryption algorithms in use, the sample data to decrypt, and the connection ID. The `keyfind_config.txt` must contain, at minimum:

* Client-Random: The random nonce sent by the client.
* Server-Random: The random nonce sent by the server.
* Content-Type: The content-type field (used in calculating the HMAC, for verification)
* Version: The version of the TLS protocol, e.g. `0302`
* Enc-Msg: The encrypted message that we should try to decrypt.
* Cipher: The cipher used for the session, in the form OpenSSL expects (e.g., `AES-128-CBC`)
* MAC: The algorithm used for the TLS MAC (e.g., `SHA1`).

You can generate a configuration file given a PCAP file with TLS data you want to decrypt using the `list_enc.py` script (available in PANDA's `scripts` directory). 

You may also, optionally, supply a list of candidate tap points in a file named `keytap_candidates.txt`. For example, one might exclude all tap points that read or wrote very little data (less than one key's worth -- 48 bytes) or whose content had low entropy (since encryption keys are expected to be random). This can greatly speed up the search.

The key found (if any) will be printed to stderr, and all matching tap points will be saved to the file `key_matches.txt` for later perusal.

Arguments
---------

None.

Dependencies
------------

`keyfind` uses the `callstack_instr` plugin to split memory accesses up into individual tap points.

APIs and Callbacks
------------------

None.

Example
-------

An example configuration file:

    # ==== 127.0.0.1:443 <-> 127.0.0.1:52103 ====
    Client-Random: 508db4fea3925d766805a41f918350b9dc8822253d490d85bfa3d25763bf220a
    Server-Random: 508db4fe6d3fa3fa913427f5fd8cbf3213211249acccff598d47fc0a0049143f
    Content-Type:  16
    Version:       0302
    Enc-Msg:       7c90069ae372aba7e91c51a91db7a1d73e282ed44178bb2ec87b7535240a9b394db93219c4227fae48ebcaf40f7a49298ea91849157ed24f83733616ef4bdd68
    Cipher:        AES-128-CBC
    MAC:           SHA1

Then, run PANDA with `keyfind`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda callstack_instr -panda keyfind

