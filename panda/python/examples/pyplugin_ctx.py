from threading import Lock
from time import sleep
from pandare import PyPlugin, Panda

class Server(PyPlugin):
    def __init__(self, panda):
        self.x = 0
        self.lock = Lock()
    
    @PyPlugin.ppp_export
    def __enter__(self):
        self.lock.acquire()

    @PyPlugin.ppp_export
    def __exit__(self, *args):
        self.lock.release()

    @PyPlugin.ppp_export
    def do_add(self, x):
        self.x += x
        sleep(5)
        return self.x

class Consumer1(PyPlugin):
    def __init__(self, panda):
        print(f"Consumer1 init. Getting server lock")
        with self.ppp.Server as server:
            print(f"Consumer1: got lock. Calling do_add")
            print(server.do_add(1))
            print(f"Consumer1: finished with do_add")

class Consumer2(PyPlugin):
    def __init__(self, panda):
        print(f"Consumer2 init. Getting server lock")
        with self.ppp.Server as server:
            print(f"Consumer2: got lock. Calling do_add")
            print(server.do_add(1))
            print(f"Consumer2: finished with do_add")

panda = Panda(generic="x86_64")
panda.pyplugins.load(Server)
panda.pyplugins.load(Consumer1)
panda.pyplugins.load(Consumer2)