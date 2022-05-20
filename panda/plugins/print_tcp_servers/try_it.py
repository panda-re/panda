from pandare import Panda

panda = Panda(generic="x86_64")

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")

    def run(cmd):
        print(panda.run_serial_cmd(cmd, no_timeout=True))

    run("python3 -m http.server &")

    run("sleep 2")

    panda.load_plugin("print_tcp_servers", {
        "print_sockets": True,
        "forward_port": 8000,
        "host_port": 4343
    })

    run("cat")
    panda.end_analysis()

panda.run()
