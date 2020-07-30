"""
The decorator submodule provide the basis for syntactic sugar on callbacks.
"""

# Decorator to ensure a function isn't called in the main thread

import threading
def blocking(func):
    def wrapper(*args, **kwargs):
        assert (threading.current_thread() is not threading.main_thread()), "Blocking function run in main thread"
        return func(*args, **kwargs)
    wrapper.__blocking__ = True
    wrapper.__name__ = func.__name__ + " (with async thread)"
    return wrapper


