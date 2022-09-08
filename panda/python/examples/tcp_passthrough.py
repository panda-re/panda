from pandare import Panda

panda = Panda(generic="x86_64")

page = "<html><body><h1>Guest Web Server</h1><p>CPU Info:</p><iframe src=\"/cpuinfo.html\" style=\"width: 70%; height: 70%\"></iframe></body></html>"

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")

    panda.run_serial_cmd("echo '<html><body><pre>' > cpuinfo.html")
    panda.run_serial_cmd("cat /proc/cpuinfo >> cpuinfo.html")
    panda.run_serial_cmd("echo '</pre></body></html>' >> cpuinfo.html")
    panda.run_serial_cmd(f"echo '{page}' > index.html")

    #print(panda.run_serial_cmd("mknod -m 777 fifo p"))
    #print(panda.run_serial_cmd("head -c10000 fifo | netcat -l -k localhost 1234 > fifo"))

    # Start up an HTTP server as a background job
    panda.run_serial_cmd("python3 -m http.server &")

    # Give the HTTP server time to start up before pulling socket info
    panda.run_serial_cmd("sleep 2")

    # Print a table of the TCP servers in the guest
    panda.tcp.print_socket_info()

    # Forward a socket from localhost:8000 in the guest to localhost:8000 on the host
    panda.tcp.forward_socket(8000, 8000)

    # Forward a socket from localhost:1234 in the guest to localhost:1234 on the host
    panda.tcp.forward_socket(1234, 1234)

    # print out the socket list ourselves too
    @panda.tcp.on_get_socket_list
    def callback(socket_info: list):
        print(" Ip Address\tPID\tIs Server?")
        print("====================================")
        for socket in socket_info:
            print(f" {socket.ip}:{socket.port}\t{socket.pid}\t{socket.is_server}")

    # Injecting into a cat command, but this could be anything
    panda.load_plugin("linjector", {
        "guest_binary": "guest_daemon",
        "proc_name": "cat"
    })
    panda.run_serial_cmd("cat", no_timeout=True)

    panda.end_analysis()

panda.run()
