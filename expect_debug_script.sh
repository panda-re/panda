#!/usr/bin/expect -f
 
set timeout -1
spawn telnet localhost 4444
expect "(qemu)"
send "c\r"
sleep 0.6
send "begin_record expect_test\r"
expect "(qemu)"
sleep 1
send "end_record\r"
send "quit\r"
expect eof