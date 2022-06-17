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

class TcpPassthrough:
    def __init__(self, panda):
        self.panda = panda

    def forward_socket(self, guest_port: int, host_port: int):
        self.panda.plugins["tcp_passthrough"].forward_socket(
            self.panda.ffi.cast("const char*", self.panda.ffi.NULL),
            self.panda.ffi.cast("uint16_t", guest_port),
            self.panda.ffi.cast("uint16_t", host_port)
        )

    def on_get_socket_list(self, callback: Callable[[list], None]):
        @self.panda.ffi.callback("void(*)(const struct SocketInfo*, uintptr_t)")
        def cb(ptr, length):
            callback([SocketInfo.from_ffi(ptr[i]) for i in range(length)])

        self.socket_list = (self.__dict__.get("socket_list") or []) + [cb]

        self.panda.plugins["tcp_passthrough"].on_get_socket_list(cb)

    def print_socket_info(self):
        self.panda.plugins["tcp_passthrough"].print_socket_info()
