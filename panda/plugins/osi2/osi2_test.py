from pandare import Panda, PyPlugin

panda = Panda(generic='x86_64')
@panda.queue_blocking
def driver():
    panda.revert_sync('root')
    panda.load_plugin("osi2")
    
    print(panda.run_serial_cmd("python3 -c 'import socket; serv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); cli = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); serv.bind(\"/tmp/test_sock\"); cli.connect(\"/tmp/test_sock\"); x = 10;cli.send(x.to_bytes(4, byteorder=\"little\")); x = serv.recv(32); print(x); cli.close(); serv.close()'"))
    #print(panda.run_serial_cmd("python3 scripts/cli_script.py"))
    panda.end_analysis()

    



panda.run()
