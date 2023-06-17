# Searching for YARA rules in memory in PANDA

This example PyPanda plugin checks each buffer written to memory (by a specific process) against provided YARA rules.

To make sure we have the necessary dependencies, we build a custom Docker image based on `pandare/panda`.

### Example
For testing we use a simple example that simulates a simple malware packer. Our test binary contains a hard-coded, encrypted buffer, which it decrypts and writes to disk. If the decrypted buffer matches a YARA rule, the plugin should detect (and dump) it during execution.

We use [the following YARA rule from Mandiant](https://www.mandiant.com/resources/blog/cosmicenergy-ot-malware-russian-response):
```YARA
rule M_Hunting_Disrupt_LIGHTWORK_Strings
{
     meta:
          author = "Mandiant"
          description = "Searching for strings associated with IEC-104 used in LIGHTWORK."
          date = "2023-04-19"

     strings:
          $s1 = "Connecting to: %s:%i\n" ascii wide nocase
          $s2 = "Connected!" ascii wide nocase
          $s3 = "Send control command C_SC_NA_1" ascii wide nocase
          $s4 = "Connect failed!" ascii wide nocase
          $s5 = "Send time sync command" ascii wide nocase
          $s6 = "Wait ..." ascii wide nocase
          $s7 = "exit 0" ascii wide nocase

     condition:
          filesize < 5MB and
          uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
          all of them
}
```

We use the following byte sequence as a (benign) buffer that matches the YARA rule.
```Python
b"\x4D\x5A"
+ b"\x00" * (0x3c - 2)
+ b"\x40\x00\x00\x00"
+ b"\x50\x45\x00\x00"
+ b"Connecting to: %s:%i\n"
+ b"Connected!"
+ b"Send control command C_SC_NA_1"
+ b"Connect failed!"
+ b"Send time sync command"
+ b"Wait ..."
+ b"exit 0"
+ b"\x00" * 100
```

We encrypt the buffer by XOR'ing it with `0xFF`.

The following Nim program contains the encrypted buffer. It decrypts it and writes the plaintext to disk. The goal of this demo program is to create a binary that, at some point during execution, has a buffer that matches the YARA rule inside its memory.
```nim
proc decrypt(key: byte, ciphertext: seq[byte]): seq[byte] =
    var plaintext = newSeq[byte](ciphertext.len)
    for i, c in ciphertext:
        plaintext[i] = key xor c
    return plaintext

const KEY = 0xFF
const PAYLOAD = @[
    byte 178, 165, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 191, 255,
    255, 255, 175, 186, 255, 255, 188, 144, 145,
    145, 154, 156, 139, 150, 145, 152, 223, 139,
    144, 197, 223, 218, 140, 197, 218, 150, 245,
    188, 144, 145, 145, 154, 156, 139, 154, 155,
    222, 172, 154, 145, 155, 223, 156, 144, 145,
    139, 141, 144, 147, 223, 156, 144, 146, 146,
    158, 145, 155, 223, 188, 160, 172, 188, 160,
    177, 190, 160, 206, 188, 144, 145, 145, 154,
    156, 139, 223, 153, 158, 150, 147, 154, 155,
    222, 172, 154, 145, 155, 223, 139, 150, 146,
    154, 223, 140, 134, 145, 156, 223, 156, 144,
    146, 146, 158, 145, 155, 168, 158, 150, 139,
    223, 209, 209, 209, 154, 135, 150, 139, 223,
    207, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255
]

let plaintext = decrypt(KEY, PAYLOAD)
writeFile("output.dat", plaintext)
```

When we run the plugin, it finds and dumps two buffers. As we can see, these buffers perfectly match our original buffer:
```shell
$ xxd matches/2023_06_17_14_36_48-M_Hunting_Disrupt_LIGHTWORK_Strings-0x4219597-0x140737353650592-decrypt.dat
00000000: 4d5a 0000 0000 0000 0000 0000 0000 0000  MZ..............
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 4000 0000  ............@...
00000040: 5045 0000 436f 6e6e 6563 7469 6e67 2074  PE..Connecting t
00000050: 6f3a 2025 733a 2569 0a43 6f6e 6e65 6374  o: %s:%i.Connect
00000060: 6564 2153 656e 6420 636f 6e74 726f 6c20  ed!Send control
00000070: 636f 6d6d 616e 6420 435f 5343 5f4e 415f  command C_SC_NA_
00000080: 3143 6f6e 6e65 6374 2066 6169 6c65 6421  1Connect failed!
00000090: 5365 6e64 2074 696d 6520 7379 6e63 2063  Send time sync c
000000a0: 6f6d 6d61 6e64 5761 6974 202e 2e2e 6578  ommandWait ...ex
000000b0: 6974 2030 0000 0000 0000 0000 0000 0000  it 0............
000000c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000100: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000110: 0000 0000 0000 0000                      ........
```
