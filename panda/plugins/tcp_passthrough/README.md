# Guest Agent TCP Passthrough

A plugin for using the PANDA guest agent in order to perform passthrough of TCP servers present in the guest.

See `try_it.py` for example on how to forward an HTTP server running on port 8000 in the guest to port 4343 on the host, as well as print out a table of the sockets listening in the guest.
