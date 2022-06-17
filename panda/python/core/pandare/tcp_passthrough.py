from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Callable

@dataclass
class SocketInfo:
    '''
    Information about a socket running in the guest.

    Fields:
        * `ip`: `IPv4Address` - the IP address within the guest being bound to
        * `pid`: `int` - the Process ID of the process which is bound to the socket
        * `port`: `int` - the TCP port (0-65565) within the guest being used
        * `is_server`: `bool` - Whether the socket within the guest is a listener or an outgoing connection
    '''

    ip: IPv4Address
    pid: int
    port: int
    is_server: bool

    def from_ffi(raw):
        '''
        Takes a C FFI instances of SocketInfo and converts it to a python-native type
        '''

        ip = IPv4Address(bytes([raw.ip[i] for i in range(4)]))
        pid = raw.pid
        port = raw.port
        is_server = raw.server

        return SocketInfo(ip, pid, port, is_server)

class TcpPassthrough:
    '''
    Object to interact with the `tcp_passthrough` PANDA plugin. An instance can be found
    at `panda.tcp`, where `panda` is a `Panda` object.
    '''

    def __init__(self, panda):
        self.panda = panda

    def forward_socket(self, guest_port: int, host_port: int):
        '''
        Forward TCP connections performed on a host port to a TCP server running in the
        guest. This could, for example, be used to allow access to a guest HTTP server.

        ```
        # Allow connecting to the guest localhost:80 via the host localhost:8500
        panda.tcp.forward_socket(80, 8500)
        ```
        '''
        self.panda.plugins["tcp_passthrough"].forward_socket(
            self.panda.ffi.cast("const char*", self.panda.ffi.NULL),
            self.panda.ffi.cast("uint16_t", guest_port),
            self.panda.ffi.cast("uint16_t", host_port)
        )

    def on_get_socket_list(self, callback: Callable[[list], None]):
        '''
        Request a list of sockets from the guest, running a provided callback when they
        are available. The callback is given a `list` of `SocketInfo`s.

        ```
        @panda.tcp.on_get_socket_list
        def with_sockets(sockets):
            for socket in sockets:
                print(f"Socket bound on guest port {socket.port}")
        ```
        '''
        @self.panda.ffi.callback("void(*)(const struct SocketInfo*, uintptr_t)")
        def cb(ptr, length):
            callback([SocketInfo.from_ffi(ptr[i]) for i in range(length)])

        self.socket_list = (self.__dict__.get("socket_list") or []) + [cb]

        self.panda.plugins["tcp_passthrough"].on_get_socket_list(cb)

    def print_socket_info(self):
        '''
        Request that a list of sockets in the guest is printed as a table to stdout,
        including information about what the given port is typically reserved for.

        ```
        panda.tcp.print_socket_info()
        ```
        '''
        self.panda.plugins["tcp_passthrough"].print_socket_info()
