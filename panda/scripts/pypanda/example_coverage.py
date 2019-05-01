from pypanda import *
import qcows
from sys import argv

# Single arg of arch, defaults to i386

arg1 = "i386" if len(argv) <= 1 else argv[1]
q = qcows.get_qcow(arg1)

pargs = "-panda coverage"

panda = Panda(qcow=q, extra_args=pargs)

panda.run()
