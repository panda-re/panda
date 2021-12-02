from pandare import PyPlugin

class Server(PyPlugin):
    '''
    PyPlugin which provides a PPP-style callback: `some_f` which is run once at
    the next BBE callback and a PPP-exported function `do_add`
    '''
    def __init__(self, panda):
        self.counter = 0
        self.ppp_cb_boilerplate('some_f') # Inform the world that Server.some_f is a PPP callback

        @panda.cb_before_block_exec
        def server_bbe(cpu, tb):
            print("Server is running all registered `some_f` callbacks")
            self.ppp_run_cb('some_f', panda.current_pc(cpu)) # Run cbs registered to run with Server.some_f: args are current_pc

            panda.disable_callback('server_bbe')

    @PyPlugin.ppp_export
    def do_add(self, x):
        self.counter += x
        return self.counter

class Consumer(PyPlugin):
    '''
    PyPlugin which calls do_add in Server and defines a function to run when
    Server's `some_f` callback is triggered
    '''
    def __init__(self, panda):
        self.ppp.Server.ppp_reg_cb('some_f', self.my_f)
        print(f"Calling Server's do_add(1) (expecting 1): ", self.ppp.Server.do_add(1))
        print(f"Calling Server's do_add(2) (expecting 3): ", self.ppp.Server.do_add(1))

    def my_f(self, arg):
        print("Consumer my_f runs with arg:", hex(arg))


if __name__ == "__main__":
    from pandare import Panda
    panda = Panda(generic="i386")

    @panda.queue_blocking
    def drive():
        panda.revert_sync("root")
        print(panda.run_serial_cmd("whoami"))
        panda.end_analysis()

    panda.pyplugins.load(Server)
    panda.pyplugins.load(Consumer)

    panda.run()
