from pandare import Panda, blocking, qcows
import sys
import time

assert(len(sys.argv) == 2)
arch="x86_64"

qi = qcows.Qcows.get_qcow_info(arch)
panda = Panda(arch=qi.arch, mem="1G", expect_prompt=qi.prompt, os=qi.os, qcow=sys.argv[1], extra_args="-nographic")


@panda.queue_blocking
def setup():

    login_prompt = b"ubuntu login: "
    password_prompt = b"Password: "
    shell_prompt = b'root@ubuntu:'

    panda.serial_read_until(login_prompt)
    print ("saw login prompt")
    panda.serial_socket.sendall(b'root\n')
    panda.serial_read_until(password_prompt)
    print ("saw password prompt")
    panda.serial_socket.sendall(b'root\n')
    panda.serial_read_until(shell_prompt)
    print ("saw shell prompt #1")
    panda.serial_socket.sendall(b'/bin/ls\n')
    res = panda.serial_read_until(shell_prompt)
    print ("saw shell prompt #2")

    print ("res=[%s]" % res)
    print ("Logged in.  Sleeping for 1 min")
    time.sleep(60)

    charptr = panda.ffi.new("char[]", bytes("root", "utf-8"))
    panda.queue_main_loop_wait_fn(panda.libpanda.panda_snap, [charptr])
    panda.queue_main_loop_wait_fn(panda.libpanda.panda_cont)
    time.sleep(60)
    
    panda.end_analysis()
    print ("Done")


if __name__ == '__main__':

    panda.run()

