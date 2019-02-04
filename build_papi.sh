#!/bin/bash
gcc -g -o papi panda_api_sample.c ./build/i386-softmmu/libpanda-i386.so -Ipanda/include -lglib2.0
