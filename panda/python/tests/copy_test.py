import os
from pandare import Panda
from sys import argv

# Create some host directories, copy them into the
# guest and assert that they contain the expected output

arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

# First we make two directories - /tmp/pandatest1 and /tmp/pandatest2
for d in ["/tmp/pandatest1", "/tmp/pandatest2"]:
    if not os.path.exists(d):
        os.mkdir(d)

with open("/tmp/pandatest1/f1.txt", "w") as f:
    f.write("hello world")

with open("/tmp/pandatest2/f2.txt", "w") as f:
    f.write("panda panda")


@panda.queue_blocking
def drive():
    panda.revert_sync("root")
    panda.copy_to_guest("/tmp/pandatest1")
    panda.copy_to_guest("/tmp/pandatest2")

    #print(panda.run_serial_cmd("ls -al pandatest*"))

    f1 = panda.run_serial_cmd("cat pandatest1/f1.txt")
    f2 = panda.run_serial_cmd("cat pandatest2/f2.txt")

    assert f1 == "hello world", f"Expected f1 to contain 'hello world' but it contians {f1}"
    assert f2 == "panda panda", f"Expected f2 to contain 'panda panda' but it contians {f2}"

    panda.end_analysis()


panda.run()
print("Success")
