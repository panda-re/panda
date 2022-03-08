# FirmWire PANDA

This repo holds the FirmWire distribution of the Platform for Architecture-Neutral Dynamic Analysis (PANDA). The upstream version of PANDA is developed by MIT Lincoln Laboratory, NYU, and Northeastern University under the [GPLv2 license](LICENSE) over at https://github.com/panda-re/panda.

FirmWire PANDA is based on the stable version of PANDA (git tag [qemu2.9.1-panda3.0.0](https://github.com/panda-re/panda/tree/qemu2.9.1-panda3.0.0)). Within FirmWire we use PANDA as base emulation platform by using its pypanda and configurable machine interfaces. 

### Why ship your own distribution?

For firmwire, we required a significant amount of changes to the framework. As some of them are modifications to the core emulation engine which break existing Panda functionality, we don't think we can upstream all of them. 

For a summary of our changes, check further below in this README file.

## Installation

The easiest way of building FirmWire PANDA is by using the Dockerfile shipped with FirmWire [[link](https://github.com/FirmWire/FirmWire/blob/main/Dockerfile)].

However, if you want to build it on your own, we won't stop you!
The following instructions are tested under Ubuntu 20.04:

```
git@github.com:FirmWire/panda.git
cd panda/
mkdir build
CFLAGS=-Wno-error ../build.sh --python arm-softmmu,mipsel-softmmu
```

For a more minimalistic installation, please refer to the [Dockerfile](https://github.com/FirmWire/FirmWire/blob/main/Dockerfile).


## Summary of changes

Below we list a non-exhaustive list of changes to the PANDA framework for FirmWire. For a complete list of changes please check the git history; this summary is solely meant as convience to provide a high-level overview of our modifications.

### Shannon-specific changes

To enable the emulation of Shannon firmware, we added a dedicated timer peripheral.
Its implementation is solely based on our insights won during reverse engineering and you can find the implementation [[here](https://github.com/FirmWire/panda/blob/main/hw/timer/shannon_timer.c)].


### MTK-specific changes

In order to emulate MediaTek based firmware images, we needed to add support for the MIPS16e2 instruction set extension. The commits introducing this support are partially  cherry-picked from [upstream qemu](https://github.com/qemu/qemu), and partially developed on our own. You will find most of the changes under [target/mips/translate.c](target/mips/translate.c).

Another small change regarding MIPS emulation is that we had to replace `first_cpu` with `current_cpu` at various places. PANDA uses by default `first_cpu` to get a global handle to the current emulation state. Unfortunately, especially during fuzzing, this broke some things and we ended up with this rather ad-hoc fix. While this allows for proper emulation and fuzzing for MediaTek-based firmware images, it also inherently breaks some of PANDA's features.

### AFL++ Integration (TriForce AFL inspired)

One of our core-additions to PANDA is the integration with a fuzzer. Specifically, we use the same hypercall-based approach as presented by [Triforce-AFL](https://github.com/nccgroup/TriforceAFL), but significantly extend upon it.

First of all, we integrated the improved coverage collection techniques provided by [AFL++](https://github.com/AFLplusplus/AFLplusplus) and implemented persistent mode fuzzing, which both leads to a significantly improved fuzzing throughput. Then, for ARM-emulation (i.e., Shannon-based firmware), we also implemented compcov/laf-intel-style instrumentation for compare operations.

The major part of our additions can be found in the [include/afl](include-afl)-directory.
