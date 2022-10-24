from pandare import Panda

panda = Panda(generic="x86_64")

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")

    # Start up an HTTP server as a background job
    panda.run_serial_cmd("python3 -m http.server &")

    # Give the HTTP server time to start up before pulling socket info
    panda.run_serial_cmd("sleep 2")

    # Print a table of the TCP servers in the guest
    panda.tcp.print_socket_info()

    # Forward a socket from localhost:8000 in the guest to localhost:4343 on the host
    panda.tcp.forward_socket(8000, 4343)

    # print out the socket list ourselves too
    @panda.tcp.on_get_socket_list
    def callback(socket_info: list):
        print(" Ip Address\tPID\tIs Server?")
        print("====================================")
        for socket in socket_info:
            print(f" {socket.ip}:{socket.port}\t{socket.pid}\t{socket.is_server}")

    # Injecting into a cat command, but this could be anything
    panda.run_serial_cmd("cat", no_timeout=True)

    panda.end_analysis()

panda.run()
