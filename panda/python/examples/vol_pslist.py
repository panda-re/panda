'''
volatility pslist two ways.
By: Luke Craig
'''

from pandare import Panda, blocking
from sys import argv
from time import time
from volatility.framework.objects import utility

arch = "x86_64" if len(argv) <= 1 else argv[1]
extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4444,server,nowait"
qcow = "/home/luke/workspace/qcows/instance-1.qcow2"
panda = Panda(arch=arch,qcow=qcow,extra_args=extra,mem="1G")

timechange = 5
oldtime,oldtime2 = time(),time()

'''
In on_asid_change we use the fast method. It gives us back the volatility symbols
and we "become" the volatility plugin. The reason this is fast is because we clear
the cache between runs so we don't have to reconstruct the whole plugin again. This
way we only have to run the 10+ second startup once.
'''
@panda.cb_asid_changed()
def on_asid_change(env, old_asid, new_asid):
	global oldtime
	if time() - oldtime > timechange:
		vmlinux = panda.get_volatility_symbols(debug=True)
		init_task = vmlinux.object_from_symbol(symbol_name = "init_task")
		out = [(task.pid,task.parent.pid,utility.array_to_string(task.comm)) for task in init_task.tasks if task.pid]
		print("PID\tPPID\tProcess Name")
		for task in out:
			print("{}\t{}\t{}".format(task[0],task[1],task[2]))
		print("Number of tasks: "+len(out))
		oldtime = time()
	return 0

'''
In on_asid_change_slow we have an example where volatility will be run with the name
(and arguments) desired and a dictionary of results will be be returned. This must
re-construct the plugin and re-scan memory every time. It is quite slow.
'''
@panda.cb_asid_changed()
def on_asid_change_slow(env, old_asid, new_asid):
	global oldtime2
	if time() - oldtime > timechange:
		a = time()
		print(panda.run_volatility("linux.pslist.PsList"))
		ran_in = time() - a
		print("ran in "+str(ran_in) + " seconds")
		oldtime = time()
	return 0

panda.run()
