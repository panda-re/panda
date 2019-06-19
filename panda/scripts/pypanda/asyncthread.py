import asyncio
import logging
import threading
import functools
from time import sleep

# Module to run an async thread in parallel to the main thread
# Enables queuing up coroutines from main thread

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("asyncio").setLevel(logging.WARNING)


class AsyncThread:
    """
    Crete a single worker thread running async functions
    """

    def __init__(self):
        self.num_workers = 1
        # Attributes are configured by thread
        self.task_queue = None
        self.running = None
        self.thread_loop = None # So we can schedule things on the thread's event loop

        self.athread = threading.Thread(target=self.thread_start)
        self.athread.start()

    def stop(self):
        self._wait_for_thread_loop()
        self.thread_loop.call_soon_threadsafe(self._shutdown) # Schedule shutdown
        self.athread.join()

    def queue(self, x): # Queue an item to be run soon
        self._wait_for_thread_loop()
        self.thread_loop.call_soon_threadsafe(
                functools.partial(self._queue, x)) # schedule _queue to run on athread loop

    def _wait_for_thread_loop(self):
        # Wait up to 3s for thread_loop to be set by self.athread
        ctr = 0
        while not self.thread_loop and ctr < 30:
            sleep(0.1) # May take a moment to become available
            ctr += 1
        if not self.thread_loop:
            raise RuntimeError("AsyncThread.thred_loop never set")


    # Methods only to be run inside self.athread
    def _shutdown(self): # Request shutdown
        self.running.release()

    def _queue(self, x): # Add an item to the queue. Must be run on the thread_loop
        self.task_queue.put_nowait(x)

    def thread_start(self):
        asyncio.run(self.run(), debug=True)

    async def run(self):
        self.task_queue = asyncio.Queue()
        self.thread_loop = asyncio.get_running_loop()
        self.running = asyncio.Condition(loop=self.thread_loop)
        await self.running.acquire()


        # each task consumes from 'queue'
        tasks = []
        for i in range(self.num_workers):
            tasks.append(asyncio.create_task(
                self.consumer(f'worker-{i}')))

         # Block until all items are processed and then shut everything down
        #await self.task_queue.join()

        # Wait until we can acquire the self.running lock, if so
        # a shutdown has been reuqested so kill tasks
        async with self.running:
            for task in tasks:
                task.cancel()

        # Wait for thread to finish being canceled?
        await asyncio.gather(*tasks, return_exceptions=True)

    async def consumer(self, name):
        try:
            while True:
                func = await self.task_queue.get()
                try:
                    print(f"{name} calling {func}")
                    asyncio.create_task(func())
                except Exception as e:
                    print(f"{name} exception {e!r}")
                    raise
                finally:
                    self.task_queue.task_done()
        except asyncio.CancelledError:
            print(f"{name} is being cancelled")
            raise


if __name__ == '__main__':
    # Basic test: create an AsyncThread and run a coroutine 3 times
    # Should output t0 three times, then maybe t1 three times, then shutdown
    a = AsyncThread()

    async def afunc():
        for x in range(10):
            print(f"afunc: t{x}")
            await asyncio.sleep(1)

    print("\nQueuing up functions...")
    a.queue(afunc)
    a.queue(afunc)
    a.queue(afunc)

    print("\nAll queued. Wait 1s")
    sleep(1)

    print("\nBegin shutdown")
    a.stop()
