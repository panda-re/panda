import threading
import functools
from queue import Queue, Empty
from time import sleep
from colorama import Fore, Style

# Module to run a thread in parallel to QEMU's main cpu loop
# Enables queuing up python functions from main thread and vice versa

def progress(msg):
	print(Fore.CYAN + '[asyncthread.py] ' + Fore.RESET + Style.BRIGHT + msg +Style.RESET_ALL)


class AsyncThread:
    """
    Create a single worker thread which runs commands from a queue
    """

    def __init__(self, panda_started):
        # Attributes are configured by thread
        self.task_queue = Queue()
        self.running = True
        self.panda_started = panda_started

        self.athread = threading.Thread(target=self.run)
        self.athread.daemon = True # Quit on main quit
        self.athread.start()

    def stop(self):
        self.running = False

    def queue(self, func): # Queue a function to be run soon. Must be @blocking
        if not func:
            raise RuntimeError("Queued up an undefined function")
        if not (hasattr(func, "__blocking__")) or not func.__blocking__:
            raise RuntimeError("Refusing to queue function '{}' without @blocking decorator".format(func.__name__))
        self.task_queue.put_nowait(func)

    def run(self): # Run functions from queue
        #name = threading.get_ident()
        while self.running: # Note setting this to false will take some time
            try: # Try to get an item repeatedly, but also check if we want to stop running
                func = self.task_queue.get(True, 1) # Implicit (blocking) wait for 1s
            except Empty:
                continue

            # Don't interact with guest if it isn't running
            # Wait for self.panda_started, but also abort if running becomes false
            while not self.panda_started and self.running:
                try:
                    self.panda_started.wait(True, 1)
                except Empty:
                    continue

            if not self.running:
                break
            try:
                print(f"Calling {func.__name__}")
                # XXX: If running become false while func is running we need a way to kill it
                func()
            except Exception as e:
                print("exception {}".format(e))
                raise
            finally:
                self.task_queue.task_done()


if __name__ == '__main__':
    # Basic test: create an AsyncThread and run a coroutine 3 times
    # Should output t0 three times, then maybe t1 three times, then shutdown
    from time import sleep

    started = threading.Event()
    a = AsyncThread(started)

    def afunc():
        for x in range(3):
            print("afunc: t{}".format(x))
            sleep(1)

    afunc.__blocking__ = "placeholder" # Hack to pretend it's decorated

    print("\nQueuing up functions...")
    a.queue(afunc)
    a.queue(afunc)
    a.queue(afunc)

    print("\nAll queued. Wait 5s")
    sleep(5)

    print("\nBegin shutdown")
    a.stop()

    # Expected output: t0, t1, t2, t0, t1
