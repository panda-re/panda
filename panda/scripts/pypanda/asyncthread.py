import threading
import functools
from queue import Queue
from time import sleep

# Module to run a thread in parallel to QEMU's main cpu loop
# Enables queuing up python functions from main thread and vice versa

class AsyncThread:
    """
    Create a single worker thread which runs commands from a queue
    """

    def __init__(self, panda_running):
        # Attributes are configured by thread
        self.task_queue = Queue()
        self.running = True
        self.panda_running = panda_running

        self.athread = threading.Thread(target=self.run)
        self.athread.daemon = True # Quit on main quit
        self.athread.start()

    def stop(self):
        # XXX: This doesn't work until a command finishes
        self.running = False

    def queue(self, x): # Queue an item to be run soon
        print("Queuing up command..")
        self.task_queue.put_nowait(x)

    def run(self): # Run functions from queue
        #name = threading.get_ident()


        while self.running: # Note setting this to false will take some time
            func = self.task_queue.get() # Implicit (blocking) wait
            # Don't interact with guest if it isn't running 
            # XXX it may be possible to still run monitor commands if the guest has started but is currently paused. But not serial
            self.panda_running.wait()

            try:
                #print(f"{name} calling {func}")
                func()
            except Exception as e:
                #print(f"{name} exception {e!r}")
                print(f"exception {e!r}")
                raise
            finally:
                self.task_queue.task_done()


if __name__ == '__main__':
    # Basic test: create an AsyncThread and run a coroutine 3 times
    # Should output t0 three times, then maybe t1 three times, then shutdown
    from time import sleep

    a = AsyncThread()

    def afunc():
        for x in range(3):
            print("afunc: t{}")
            sleep(10)

    print("\nQueuing up functions...")
    a.queue(afunc)
    a.queue(afunc)
    a.queue(afunc)

    print("\nAll queued. Wait 1s")
    sleep(5)

    print("\nBegin shutdown")
    a.stop()
