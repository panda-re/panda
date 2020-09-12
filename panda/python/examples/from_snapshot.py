from panda import Panda, blocking

panda = Panda(generic="x86_64")


@blocking
def bb():
    print("CALLED BLOCKING BB")
#    panda.revert_sync("root")
 #   print("MADE IT PAST REVERT SYNC")
    print(panda.run_serial_cmd("cat /etc/passwd"))

panda.queue_async(bb)
panda.run(from_snapshot="root")
#panda.run()