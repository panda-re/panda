Finding SSL/TLS Master Secrets with PANDA
=========================================

Introduction
------------

Monitoring SSL/TLS-encrypted traffic is a classic problem for intrusion
detection systems. Currently, hypervisor- or network- based IDSes that
wish to analyze encrypted traffic must perform a man-in-the-middle
attack on the connection, presenting a false server certificate to the
client. Not only does this require the client to cooperate by trusting
certificates signed by the intrusion detection system, it also takes
control of the certificate verification process out of the hands of the
client---a dangerous step, given that many existing SSL/TLS interception
proxies have a history of certificate trust vulnerabilities.

Instead of a man-in-the-middle attack, we can instead attempt to locate
the code that generates SSL/TLS master secret; this secret is sufficient
to decrypt any encrypted traffic in a given session, giving us a
"man-on-the-inside". Once we have identified the location of the code
that generates this secret, we can hook it using any number of standard
techniques in order to dump out the master secret. This secret can then
be provided to an IDS to decrypt the content of the SSL stream; it may
also be provided to a tool like Wireshark to decrypt packet captures
after the fact (even if perfect forward secrecy is used).

In this tutorial, we will show how to use a PANDA plugin called
`keyfind`, which examines memory accesses made during a recorded session
and looks for code that processes SSL/TLS master secrets.

Setting up the VM
-----------------

For this tutorial, we'll be working off of an [i386 Debian squeeze
virtual machine created by Aurelien
Jarno](http://people.debian.org/~aurel32/qemu/i386/). If you're interested
in using these virtual machines, you'll need a more recent copy of qemu to
convert these images to a lower version of qcow2 which PANDA supports. You can
do this with:

    qemu-img convert -f qcow2 -O qcow2 -o compat=0.10 \
    debian_wheezy_amd64_desktop.qcow2 debian_wheezy_amd64_desktop_panda.qcow2
    
where debian_wheezy_amd64_desktop.qcow2 is the example name of the qcow2 image
you're looking to downgrade and debian_wheezy_amd64_desktop_panda.qcow2 is the
new output file. Also, note again that this is using your distro's more recent 
version of qemu-img, not PANDA's. This command is needed if you're running 
into the following error:

    'ide0-hd0' uses a qcow2 feature which is not supported by this qemu
    version: QCOW version 3

If you want to follow along without creating your own recording, there is [a sample
virtual machine image and recording log
available](http://amnesia.gtisc.gatech.edu/~moyix/ssltut.tar.gz) (beware
though, it clocks in at around 2GB).

Once you have the VM, boot it using

    x86_64-softmmu/qemu-system-x86_64 -hda debian_squeeze_i386_desktop_tut.qcow2 \
        -m 256 -monitor stdio -net nic,model=e1000 -net user

After it has booted, log in with the default username and password
(`user:user`) and open up a terminal. We're going to install debug
symbols for the OpenSSL inside the VM so that when we eventually find
the code that generates the master secret, we can find out the names of
the actual functions rather than just their addresses. As root
(password: `root`), issue:

    # apt-get update
    # apt-get install libssl0.9.8-dbg gdb

Once this is done, you can shut down the VM.

Creating the Recording
----------------------

The `keyfind` plugin runs on a recorded execution in which an SSL
connection is made. It works by examining every memory access made by
the system and checking whether the data being accessed forms a valid
master secret that can decrypt some data provided by the user. One may
wonder why the plugin cannot run on a live execution. There are two
reasons: first, because it does several cryptographic operations for
every memory access performed, it is extremely computationally
intensive, with a slowdown of around 500x over normal execution. Second,
at the time the master secret is generated, no packets have been sent,
so there is no encrypted data we can use to test whether a candidate key
is correct.

Instead, we start by creating a recording using PANDA's record and
replay feature. In this recording session, we will run a command that
makes an SSL connection (in this case, `openssl s_client`). We will also
do a packet capture so that we have some encrypted data we can use to
test any potential keys against. 

To get started, boot up the VM. In addition to the arguments used to
boot the VM in the previous section, we will also tell QEMU to capture
all packets sent and received by the VM to a file called `ssltut.pcap`:

    x86_64-softmmu/qemu-system-x86_64 -hda ~/qcow/debian_squeeze_i386_desktop_tut.qcow2 \
        -m 256 -monitor stdio -net nic,model=e1000 \
        -net user -net dump,file=ssltut.pcap

Once the VM is booted and we have logged in, we start up `openssl`
inside `gdb`, which will allow us to resolve symbols alter.

    gdb --args openssl s_client -connect google.com:443

This launches `gdb` but does not yet start running `openssl` (which is
good, since at this point we are not yet recording anything!). Now,
in the QEMU monitor, we start the recording:

    QEMU 1.0,1 monitor - type 'help' for more information
    (qemu) begin_record ssltut

This will create a snapshot inside the QCOW named `ssltut-rr-snp`, and
an on-disk log file called `ssltut-rr-nondet.log`. Taking the snapshot
can take a long time (on the order of a few minutes), because QEMU's
default policy is to issue an `fsync` after every write, which is
extremely slow. Once the snapshot is made, the VM will resume. Type
`run` into the `gdb` session, and `openssl` will make the SSL connection
to `google.com`. If you like, once it has connected, you can issue a
request like `GET / HTTP/1.0` in order to have some actual traffic in
the SSL session aside from the handshake. This isn't required, however.

Once the connection has been successfully made, end the recording
session from the QEMU monitor and quit.

    (qemu) end_record
    (qemu) quit

Examining the Encrypted Data
----------------------------

Now that we have a recording and a packet capture, we need to extract
enough information from the packet capture to allow `keyfind` to test
potential keys. Included with PANDA is the program
`scripts/list_enc.py`, which will extract and print out the necessary
information and create a configuration file for `keyfind`. It depends on
the community-supported version of `scapy`, which can be installed using
Mercurial:

    $ hg clone http://hg.secdev.org/scapy-com
    $ cd scapy-com
    $ sudo python setup.py install

When run on the packet capture, `list_enc.py` will produce a
configuration file suitable for use with `keyfind`. In our sample
capture, its output looks like this:

    # ==== 10.0.2.15:35295 <-> 74.125.140.100:443 ====
    Client-Random: cfcc650a27e439ebd5395f8fcdf1341085e49e6dcbb7347f76a6804be7eddf53
    Server-Random: 52251293ef208ac7b2f942d71665785fc16a819d70e11e8dc5b0dcb359d93625
    Content-Type:  16
    Version:       0301
    Enc-Msg:       a70adb2eeff6e23f7d528f0cd52285097f4077d93786fb2ed63418a8ad266e2d577b14b1
    Cipher:        RC4
    MAC:           SHA1
    Ciphersuite:   TLS_RSA_WITH_RC4_128_SHA
    Session-ID:    acd4b061aee65594d0ebdec5212076c35cfe5bf9c895305d2036584b17bdc889

Place this output into a file named `keyfind_config.txt` in the
`panda/qemu` directory. Alternatively, the same information can be
derived by hand using a tool like Wireshark and copied into
`keyfind_config.txt`, but this is rather more labor intensive.

Locating the Master Key Code
----------------------------

Finally, we can run a replay with the `keyfind` plugin enabled to find
out what code generates the master secret. Because the `keyfind` plugin
tracks the calling function in order to better identify different memory
accesses, we also need to enable the `callstack_instr` plugin, which
keeps track of function calls and returns. We'll also use QEMU's VNC
output rather than the default SDL because replays don't show any
GUI output.

Using `keyfind` can be quite slow! On my machine, this short session,
which takes only 12 seconds to replay with no plugins, takes almost 2
hours to run with `keyfind` enabled. This is what the output looks like:

    brendan@brendantemp:~/git/panda/qemu$ echo "begin_replay ssltut" | \
        x86_64-softmmu/qemu-system-x86_64 -hda debian_squeeze_i386_desktop_tut.qcow2 \
        -m 256 -monitor stdio -vnc :0 -net nic,model=e1000 -net user \
        -panda "callstack_instr;keyfind"
    Initializing plugin callstack_instr
    Initializing plugin keyfind
    Couldn't open keyfind_candidates.txt; no key tap candidates defined.
    We will proceed, but it may be SLOW.
    Unknown key: Ciphersuite
    Unknown key: Session-ID
    QEMU 1.0,1 monitor - type 'help' for more information
    (qemu) begin_replay ssltut
    (qemu) loading snapshot
    ... done.

    Logging all cpu states
    CPU #0:
    EAX=c1358000 EBX=c13b9f04 ECX=c180295c EDX=00000001
    ESI=00000000 EDI=c135b000 EBP=0166a003 ESP=c1359fd0
    EIP=c101a7f4 EFL=00000246 [---Z-P-] CPL=0 II=0 A20=1 SMM=0 HLT=1
    ES =007b 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
    CS =0060 00000000 ffffffff 00cf9a00 DPL=0 CS32 [-R-]
    SS =0068 00000000 ffffffff 00c09300 DPL=0 DS   [-WA]
    DS =007b 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
    FS =00d8 003ee000 ffffffff 008f9300 DPL=0 DS16 [-WA]
    GS =00e0 c1807fe0 00000018 00409100 DPL=0 DS   [--A]
    LDT=0000 00000000 00000000 00008200 DPL=0 LDT
    TR =0080 c1805e20 0000206b 00008900 DPL=0 TSS32-avl
    GDT=     c1800000 000000ff
    IDT=     c135b000 000007ff
    CR0=8005003b CR2=0927707c CR3=0e0cd000 CR4=000006d0
    DR0=0000000000000000 DR1=0000000000000000 DR2=0000000000000000 DR3=0000000000000000 
    DR6=0000000000000000 DR7=0000000000000000
    EFER=0000000000000000
    FCW=037f FSW=7a00 [ST=7] FTW=80 MXCSR=00001f80
    FPR0=0000000000000000 0000 FPR1=bb00000000000000 4006
    FPR2=0000000000000000 0000 FPR3=0000000000000000 0000
    FPR4=0000000000000000 0000 FPR5=8000000000000000 3fff
    FPR6=0000000000000000 0000 FPR7=fb80000000000000 4014
    XMM00=00000000ffffff000000000000000000 XMM01=0000001f0000001f0000001f0000001f
    XMM02=00000000000000000000000000000000 XMM03=00000000000000000000000000000000
    XMM04=00000000000000000000000000000000 XMM05=00000000000000000000000000000000
    XMM06=00000000000000000000000000000000 XMM07=00000000000000000000000000000000
    opening nondet log for read :   /home/brendan/rrlogs/ssltut-rr-nondet.log
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  143814 of 11080621 (1.30%) bytes, 4541541 of 453214375 (1.00%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  210906 of 11080621 (1.90%) bytes, 9091720 of 453214375 (2.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  484122 of 11080621 (4.37%) bytes, 13617608 of 453214375 (3.00%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  683758 of 11080621 (6.17%) bytes, 18260476 of 453214375 (4.03%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  749427 of 11080621 (6.76%) bytes, 23196699 of 453214375 (5.12%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  758565 of 11080621 (6.85%) bytes, 27223059 of 453214375 (6.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  761233 of 11080621 (6.87%) bytes, 32376235 of 453214375 (7.14%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  1354800 of 11080621 (12.23%) bytes, 36720016 of 453214375 (8.10%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  1891930 of 11080621 (17.07%) bytes, 41580331 of 453214375 (9.17%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2131340 of 11080621 (19.23%) bytes, 45332198 of 453214375 (10.00%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2136310 of 11080621 (19.28%) bytes, 49951437 of 453214375 (11.02%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2138950 of 11080621 (19.30%) bytes, 54489279 of 453214375 (12.02%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2141498 of 11080621 (19.33%) bytes, 59032146 of 453214375 (13.03%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2152406 of 11080621 (19.42%) bytes, 63606185 of 453214375 (14.03%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2188070 of 11080621 (19.75%) bytes, 68029265 of 453214375 (15.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2268570 of 11080621 (20.47%) bytes, 72517889 of 453214375 (16.00%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2273534 of 11080621 (20.52%) bytes, 77402116 of 453214375 (17.08%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2277726 of 11080621 (20.56%) bytes, 82434861 of 453214375 (18.19%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2279274 of 11080621 (20.57%) bytes, 86646747 of 453214375 (19.12%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2335598 of 11080621 (21.08%) bytes, 91064503 of 453214375 (20.09%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2499561 of 11080621 (22.56%) bytes, 95186132 of 453214375 (21.00%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  2864296 of 11080621 (25.85%) bytes, 99737735 of 453214375 (22.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  3162679 of 11080621 (28.54%) bytes, 104446100 of 453214375 (23.05%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  3877818 of 11080621 (35.00%) bytes, 109292089 of 453214375 (24.11%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  4440493 of 11080621 (40.07%) bytes, 113779181 of 453214375 (25.10%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  4724424 of 11080621 (42.64%) bytes, 117950541 of 453214375 (26.03%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  5280948 of 11080621 (47.66%) bytes, 123079972 of 453214375 (27.16%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  5713998 of 11080621 (51.57%) bytes, 127025118 of 453214375 (28.03%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6307898 of 11080621 (56.93%) bytes, 132404879 of 453214375 (29.21%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6429147 of 11080621 (58.02%) bytes, 136380997 of 453214375 (30.09%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6579261 of 11080621 (59.38%) bytes, 140949180 of 453214375 (31.10%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6585435 of 11080621 (59.43%) bytes, 145140080 of 453214375 (32.02%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6591803 of 11080621 (59.49%) bytes, 149618983 of 453214375 (33.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6598833 of 11080621 (59.55%) bytes, 154398192 of 453214375 (34.07%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6606623 of 11080621 (59.62%) bytes, 158757560 of 453214375 (35.03%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6609927 of 11080621 (59.65%) bytes, 163242304 of 453214375 (36.02%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6612911 of 11080621 (59.68%) bytes, 168158017 of 453214375 (37.10%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6615459 of 11080621 (59.70%) bytes, 172703399 of 453214375 (38.11%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6618269 of 11080621 (59.73%) bytes, 177317392 of 453214375 (39.12%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6620453 of 11080621 (59.75%) bytes, 181365899 of 453214375 (40.02%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6623093 of 11080621 (59.77%) bytes, 186146152 of 453214375 (41.07%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6625937 of 11080621 (59.80%) bytes, 190618463 of 453214375 (42.06%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6628577 of 11080621 (59.82%) bytes, 195274254 of 453214375 (43.09%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6631125 of 11080621 (59.84%) bytes, 200046282 of 453214375 (44.14%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6633401 of 11080621 (59.86%) bytes, 204171920 of 453214375 (45.05%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6635949 of 11080621 (59.89%) bytes, 209082088 of 453214375 (46.13%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6638413 of 11080621 (59.91%) bytes, 213349182 of 453214375 (47.07%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6641053 of 11080621 (59.93%) bytes, 218154703 of 453214375 (48.13%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6643329 of 11080621 (59.95%) bytes, 222555714 of 453214375 (49.11%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6645877 of 11080621 (59.98%) bytes, 226861370 of 453214375 (50.06%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6648061 of 11080621 (60.00%) bytes, 231548405 of 453214375 (51.09%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6650981 of 11080621 (60.02%) bytes, 236143832 of 453214375 (52.10%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6653529 of 11080621 (60.05%) bytes, 240879388 of 453214375 (53.15%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6657373 of 11080621 (60.08%) bytes, 245158621 of 453214375 (54.09%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6696133 of 11080621 (60.43%) bytes, 249747822 of 453214375 (55.11%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  6935907 of 11080621 (62.59%) bytes, 254304094 of 453214375 (56.11%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  7063439 of 11080621 (63.75%) bytes, 258609527 of 453214375 (57.06%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  7374417 of 11080621 (66.55%) bytes, 263001263 of 453214375 (58.03%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  7795148 of 11080621 (70.35%) bytes, 267434787 of 453214375 (59.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  7845894 of 11080621 (70.81%) bytes, 271937269 of 453214375 (60.00%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  7936689 of 11080621 (71.63%) bytes, 276525822 of 453214375 (61.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  7968405 of 11080621 (71.91%) bytes, 281052338 of 453214375 (62.01%) instructions processed.
    MAC match found at 00000000b7e82bad 00000000b7d3cb16 000000000e101000
    Key: f6e162a5891fa91fd60d16bedc1718d201e18dedde6defbcc68e5a15b82932e2a84d4832a2816fab5c6663a8d4187c91
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  7979525 of 11080621 (72.01%) bytes, 285717048 of 453214375 (63.04%) instructions processed.
    MAC match found at 00000000b7e82bad 00000000b7d3cb16 000000000e101000
    Key: f6e162a5891fa91fd60d16bedc1718d201e18dedde6defbcc68e5a15b82932e2a84d4832a2816fab5c6663a8d4187c91
    MAC match found at 00000000b7e82bad 00000000b7d3cb16 000000000e101000
    Key: f6e162a5891fa91fd60d16bedc1718d201e18dedde6defbcc68e5a15b82932e2a84d4832a2816fab5c6663a8d4187c91
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  7998242 of 11080621 (72.18%) bytes, 290267484 of 453214375 (64.05%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  8151160 of 11080621 (73.56%) bytes, 295043876 of 453214375 (65.10%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  8155416 of 11080621 (73.60%) bytes, 299408530 of 453214375 (66.06%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  8159364 of 11080621 (73.64%) bytes, 303904584 of 453214375 (67.06%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  8163970 of 11080621 (73.68%) bytes, 308397756 of 453214375 (68.05%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  8320892 of 11080621 (75.09%) bytes, 312801346 of 453214375 (69.02%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  8509748 of 11080621 (76.80%) bytes, 317262765 of 453214375 (70.00%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  8679104 of 11080621 (78.33%) bytes, 321787790 of 453214375 (71.00%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  8703862 of 11080621 (78.55%) bytes, 326352317 of 453214375 (72.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  8974876 of 11080621 (81.00%) bytes, 330891001 of 453214375 (73.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9150324 of 11080621 (82.58%) bytes, 335463753 of 453214375 (74.02%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9223711 of 11080621 (83.24%) bytes, 340087530 of 453214375 (75.04%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9227233 of 11080621 (83.27%) bytes, 344443859 of 453214375 (76.00%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9230169 of 11080621 (83.30%) bytes, 349203234 of 453214375 (77.05%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9393269 of 11080621 (84.77%) bytes, 353633505 of 453214375 (78.03%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9519905 of 11080621 (85.91%) bytes, 358230954 of 453214375 (79.04%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9578551 of 11080621 (86.44%) bytes, 362654498 of 453214375 (80.02%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9700325 of 11080621 (87.54%) bytes, 367159218 of 453214375 (81.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9725009 of 11080621 (87.77%) bytes, 371686972 of 453214375 (82.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9835984 of 11080621 (88.77%) bytes, 376259786 of 453214375 (83.02%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9844410 of 11080621 (88.84%) bytes, 380751536 of 453214375 (84.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9847618 of 11080621 (88.87%) bytes, 385242096 of 453214375 (85.00%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9850992 of 11080621 (88.90%) bytes, 389913657 of 453214375 (86.03%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9874987 of 11080621 (89.12%) bytes, 394572449 of 453214375 (87.06%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9880957 of 11080621 (89.17%) bytes, 399585919 of 453214375 (88.17%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9884689 of 11080621 (89.21%) bytes, 403759578 of 453214375 (89.09%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  9887829 of 11080621 (89.24%) bytes, 408636625 of 453214375 (90.16%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  10121787 of 11080621 (91.35%) bytes, 412493014 of 453214375 (91.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  10261175 of 11080621 (92.60%) bytes, 417075719 of 453214375 (92.03%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  10366717 of 11080621 (93.56%) bytes, 421688356 of 453214375 (93.04%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  10379709 of 11080621 (93.67%) bytes, 426207758 of 453214375 (94.04%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  10617913 of 11080621 (95.82%) bytes, 430657217 of 453214375 (95.02%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  10639237 of 11080621 (96.02%) bytes, 435163591 of 453214375 (96.02%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  10696611 of 11080621 (96.53%) bytes, 439645747 of 453214375 (97.01%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  10795111 of 11080621 (97.42%) bytes, 444228835 of 453214375 (98.02%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  10855619 of 11080621 (97.97%) bytes, 448922948 of 453214375 (99.05%) instructions processed.
    /home/brendan/rrlogs/ssltut-rr-nondet.log:  log is empty.
    Replay completed successfully.
    Time taken was: 6839 seconds.
    Stats:
    RR_INPUT_1 number = 0, size = 0 bytes
    RR_INPUT_2 number = 0, size = 0 bytes
    RR_INPUT_4 number = 14947, size = 448410 bytes
    RR_INPUT_8 number = 109960, size = 3738640 bytes
    RR_INTERRUPT_REQUEST number = 43307, size = 1212596 bytes
    RR_EXIT_REQUEST number = 0, size = 0 bytes
    RR_SKIPPED_CALL number = 1088, size = 5680925 bytes
    RR_DEBUG number = 0, size = 0 bytes
    max_queue_len = 671
    670 items on recycle list, 48240 bytes total
    Replay completed successfully.
    Logging all cpu states
    CPU #0:
    EAX=1858d431 EBX=00000000 ECX=00000000 EDX=000000cc
    ESI=00000030 EDI=c180397c EBP=c18085e0 ESP=c1359f00
    EIP=c1007569 EFL=00000017 [----APC] CPL=0 II=0 A20=1 SMM=0 HLT=0
    ES =007b 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
    CS =0060 00000000 ffffffff 00cf9a00 DPL=0 CS32 [-R-]
    SS =0068 00000000 ffffffff 00c09300 DPL=0 DS   [-WA]
    DS =007b 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
    FS =00d8 003ee000 ffffffff 008f9300 DPL=0 DS16 [-WA]
    GS =00e0 c1807fe0 00000018 00409100 DPL=0 DS   [--A]
    LDT=0000 00000000 00000000 00008200 DPL=0 LDT
    TR =0080 c1805e20 0000206b 00008900 DPL=0 TSS32-avl
    GDT=     c1800000 000000ff
    IDT=     c135b000 000007ff
    CR0=8005003b CR2=0a040000 CR3=0c052000 CR4=000006d0
    DR0=0000000000000000 DR1=0000000000000000 DR2=0000000000000000 DR3=0000000000000000 
    DR6=0000000000004000 DR7=0000000000000000
    EFER=0000000000000000
    FCW=037f FSW=3900 [ST=7] FTW=80 MXCSR=00001f80
    FPR0=00000000d2771d00 3ffe FPR1=0000000000000000 3fff
    FPR2=0000000000000000 4001 FPR3=0000000000000000 3ffd
    FPR4=0000000000000000 0000 FPR5=0000000000000000 4008
    FPR6=0000000000000000 4008 FPR7=fb80000000000000 4014
    XMM00=000000000000000000000000d2771d00 XMM01=00000000000000000000000000000000
    XMM02=ffffffffffffffffffffffffffffffff XMM03=00000000000000000000000000000000
    XMM04=00110000000000000012000000000000 XMM05=01010101010101010101010101010101
    XMM06=00ff000f001d003000ff000f001d0030 XMM07=00010001000100010006000600060006
    0 / 0 blocks instrumented.
    Misses: 61850 Total: 9584516

This output somewhat cryptically tells us that the program point
(the code we want to hook to extract the master secret) is at

    00000000b7e82bad 00000000b7d3cb16 000000000e101000

Going from right to left, the numbers are: the address space identifier
for the program (on x86, this is the value of the `CR3` register), the
program counter where the memory access happened, and call site of the
function that called this one. This information is also saved to a file
called `key_matches.txt`.

It also gives us the actual key, if we want to decrypt our packet
capture:
    
    Key: f6e162a5891fa91fd60d16bedc1718d201e18dedde6defbcc68e5a15b82932e2a84d4832a2816fab5c6663a8d4187c91

If we like, we can now paste this into a Wireshark config file and
decrypt the session using the [procedure documented
here](http://ask.wireshark.org/answer_link/4238/). For our sample
capture the configuration file looks like:

    RSA Session-ID:acd4b061aee65594d0ebdec5212076c35cfe5bf9c895305d2036584b17bdc889 Master-Key:f6e162a5891fa91fd60d16bedc1718d201e18dedde6defbcc68e5a15b82932e2a84d4832a2816fab5c6663a8d4187c91

After providing this information to Wireshark, we can decrypt the
session:

![A screenshot showing the decrypted SSL
session](http://i.imgur.com/BWSPFaf.png "Wireshark successfully decrypts
the SSL data")

All this is great if we only want to decrypt one session, but we have a
bit more work to do if we want to reliably identify the point within
`openssl` where the keys are generated.

Validation
----------

We should also validate that the code location found is what we want.
One danger is that the combination of program counter and calling
function doesn't uniquely identify the code that handles the data we
want -- that same program point may handle other data as well. To check
this, we will re-run the replay and tell PANDA to dump all the data
passing through this program point.

This is done using the (somewhat misnamed) `textprinter` plugin, which
dumps out all data passing through a given program point, as well as the
full call stack. To use it, we create a file in `panda/qemu` called
`tap_points.txt`, and put our program point into it, creating a file
that looks like:

    00000000b7e82bad 00000000b7d3cb16 000000000e101000

Now, we run the replay:

    $ echo "begin_replay ssltut" | x86_64-softmmu/qemu-system-x86_64 -hda debian_squeeze_i386_desktop_tut.qcow2 \
        -m 256 -monitor stdio -vnc :0 -net nic,model=e1000 -net user \
        -panda callstack_instr;textprinter

It will produce two files, `read_tap_buffers.txt.gz` and
`write_tap_buffers.txt.gz`. Let's focus on `write_tap_buffers.txt.gz`
for now. Each line in this file represents the write of a single byte in
memory, and gives (in order): the full call stack, the program counter,
the address space identifier, the address being written to, a counter
indicating (with respect to the entire execution trace) which memory
access this is, and finally the byte that was written.

As we feared, there is a lot more data passing through this
point than just our master key. Let's look at the full stack where the
first byte of our key is written:

    0000000008055e71 00000000b7cdec76 000000000805672c 000000000805603d 000000000807eef0 00000000b7fb2e59 00000000b7fa531b 00000000b7fa4b33 00000000b7fb324a 00000000b7f9bd0b 00000000b7fa8aab 00000000b7fa72aa 00000000b7e82bad 00000000b7d3cb16 000000000e101000 00000000bfffe988 136342983 f6

Here's that same information expanded out a bit and annotated:

    0000000008055e71 [Caller 13]
    00000000b7cdec76 [Caller 12]
    000000000805672c [Caller 11]
    000000000805603d [Caller 10]
    000000000807eef0 [Caller 9]
    00000000b7fb2e59 [Caller 8]
    00000000b7fa531b [Caller 7]
    00000000b7fa4b33 [Caller 6]
    00000000b7fb324a [Caller 5]
    00000000b7f9bd0b [Caller 4]
    00000000b7fa8aab [Caller 3]
    00000000b7fa72aa [Caller 2]
    00000000b7e82bad [Caller 1]
    00000000b7d3cb16 [PC]
    000000000e101000 [Address space]
    00000000bfffe988 [Write address]
           136342983 [Index]
                  f6 [Data]

Using `zgrep`, we can find out how many levels of callstack information
we need in order to capture *just* the key we're interested in. We know
that an SSL master secret is 48 bytes, so we can include successively
more calling context until are left with data that is some multiple of
48 bytes, indicating that only SSL keys are being printed:

    $ zgrep -c "00000000b7e82bad 00000000b7d3cb16" write_tap_buffers.txt.gz
    504
    $ zgrep -c "00000000b7fa72aa 00000000b7e82bad 00000000b7d3cb16" write_tap_buffers.txt.gz
    192
    $ zgrep -c "00000000b7fa8aab 00000000b7fa72aa 00000000b7e82bad 00000000b7d3cb16" write_tap_buffers.txt.gz
    24

From this output, we can see that we need exactly two levels of calling
context in addition to the program counter: with just one level, we get
504 bytes, meaning extra data is being included, whereas with three
levels, we get only 24 bytes, which means parts of the key are being
left out. With two levels, 192 bytes are produced, which is exactly the
length of four SSL master secrets (it is a multiple rather than exactly
48 because `openssl` may generate multiple keys, and it may regenerate
the same key multiple times in a single session).

Getting Function Names
----------------------

Now that we know how much context is needed, we just need to translate
the raw addresses we have back into symbolic names. Because we started
`openssl` under `gdb`, this is easy. We can load up the snapshot that
was taken at the start of recording and just directly ask `gdb` to look
up the addresses for us. Start the VM back up at the snapshot with:

    $ x86_64-softmmu/qemu-system-x86_64 -hda debian_squeeze_i386_desktop_tut.qcow2 \
        -m 256 -monitor stdio -net nic,model=e1000 -net user -loadvm ssltut-rr-snp

Next, we can enter the addresses into `gdb`. Because `gdb` doesn't load
symbols until the program starts, we'll have to issue `run` and then use
Control-C to break into the program after it starts:

    (gdb) run
    ^C
    Program received signal SIGINT, Interrupt.
    0xb7fe2424 in __kernel_vsyscall ()
    (gdb)

Now we can resolve the addresses using `info symbol`:

    (gdb) info symbol 0xb7d3cb16
    memcpy + 70 in section .text of /lib/i686/cmov/libc.so.6
    (gdb) info symbol 0xb7e82bad
    HMAC_Init_ex + 141 in section .text of /usr/lib/i686/cmov/libcrypto.so.0.9.8
    (gdb) info symbol 0xb7fa72aa
    tls1_P_hash + 154 in section .text of /usr/lib/i686/cmov/libssl.so.0.9.8


Conclusion
----------

We now have all the information we need to reliably find SSL/TLS master
keys generated by OpenSSL. This same process generalizes to *any*
application that uses SSL/TLS. Indeed, in our 2013 CCS paper ([Tappan
Zee (North) Bridge: Mining Memory Accesses for
Introspection](http://www.cc.gatech.edu/~brendan/tzb_author.pdf)), we
found the key generation code for seven applications across three
operating systems and three different hardware architectures. This
flexibility demonstrates how valuable it is that PANDA is whole-system,
architecture neutral, and traces can be recorded and later replayed
under instrumentation.
