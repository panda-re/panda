from pandare import Panda

panda = Panda(generic="x86_64")

# =====================================================================

def extend_class(cls):
    return lambda f: (setattr(cls, f.__name__, f) or f)

# =====================================================================

from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Callable

@dataclass
class SocketInfo:
    ip: IPv4Address
    pid: int
    port: int
    is_server: bool

    def from_ffi(raw):
        ip = IPv4Address(bytes([raw.ip[i] for i in range(4)]))
        pid = raw.pid
        port = raw.port
        is_server = raw.server

        return SocketInfo(ip, pid, port, is_server)

@extend_class(Panda)
def forward_socket(self, guest_port: int, host_port: int):
    self.plugins["tcp_passthrough"].forward_socket(
        self.ffi.cast("const char*", self.ffi.NULL),
        self.ffi.cast("uint16_t", guest_port),
        self.ffi.cast("uint16_t", host_port)
    )

@extend_class(Panda)
def on_get_socket_list(self, callback: Callable[[list], None]):
    @self.ffi.callback("void(*)(const struct SocketInfo*, uintptr_t)")
    def cb(ptr, length):
        callback([SocketInfo.from_ffi(ptr[i]) for i in range(length)])

    self.socket_list = (self.__dict__.get("socket_list") or []) + [cb]

    self.plugins["tcp_passthrough"].on_get_socket_list(cb)

@extend_class(Panda)
def print_socket_info(self):
    self.plugins["tcp_passthrough"].print_socket_info()

# =====================================================================

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")

    def run(cmd):
        print(panda.run_serial_cmd(cmd, no_timeout=True))

    # Start up an HTTP server as a background job
    run("python3 -m http.server &")

    # Give the HTTP server time to start up before pulling socket info
    run("sleep 2")

    # Print a table of the TCP servers in the guest
    panda.print_socket_info()

    # Forward a socket from localhost:8000 in the guest to localhost:4343 on the host
    panda.forward_socket(8000, 4343)

    # print out the socket list ourselves too
    @panda.on_get_socket_list
    def callback(socket_info: list):
        print(" Ip Address\tPID\tIs Server?")
        print("====================================")
        for socket in socket_info:
            print(f" {socket.ip}:{socket.port}\t{socket.pid}\t{socket.is_server}")

    # Injecting into a cat command, but this could be anything
    run("cat")

    panda.end_analysis()

panda.run()
