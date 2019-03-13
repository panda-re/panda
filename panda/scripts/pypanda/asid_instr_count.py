from pypanda import *
from time import sleep

ac_instr_start = 0

<<<<<<< HEAD
def InstrRange:
=======
panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img", mem="2048M")

class InstrRange:
>>>>>>> pypanda-fix
	def __init__(self, old_instr, new_instr):
		self.old = old # first
		self.new = new # secod

<<<<<<< HEAD
asid_rr_sub_factor = {}
asid_instr_intervals = {}
=======
asid_rr_sub_factor = {} 	# (int -> instr)
asid_instr_intervals = {}	# (int -> instrrange)
>>>>>>> pypanda-fix

def update_asid_rr_sub_factor(old_asid, rr):
	if old_asid not in asid_instr_intervals:
		asid_instr_intervals[old_asid] = [rr]
	else:
		asid_instr_intervals[old_asid].append(rr)
<<<<<<< HEAD
	rri_len = rr.new - rr.old
	for kvp in asid_rr_sub_factor:
		asid = kvp.old_instr
		if 
	if len(asid_rr_sub_factor) == 0:
		asid_rr_sub_factor[old_asid] = panda.get_guest_instr_count()

@pyp.callback("int(CPUState*, uint32_t, uint32_t)")
def asid_changed(cpustate, old_asid, new_asid):
	if new_asid < 10:
		return 0
	instr = panda.get_guest_instr_count()	
	if (old_asid != new_asid):
		
	ac_instr_count = panda.get_guest_instr_count()
	return 0

@pyp.callback("bool(void*)")
def init(handle):
	panda.register_callback(handle, "asid_changed", 23, asid_changed)
	return True

panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img", mem="2048M")
=======
	rri_len = rr[1] - rr[0]
	for kvp in asid_rr_sub_factor:
#		asid = kvp.old
		if kvp != old_asid:
			asid_rr_sub_factor[kvp] += rri_len
	if len(asid_rr_sub_factor) == 0:
		asid_rr_sub_factor[old_asid] = panda.rr_get_guest_instr_count()

@panda.callback.asid_changed
def asid_changed(cpustate, old_asid, new_asid):
	if new_asid < 10:
		return 0
	instr = panda.rr_get_guest_instr_count()	
	if (old_asid != new_asid):
		update_asid_rr_sub_factor(old_asid, (ac_instr_start, instr-1))
	if old_asid != new_asid:
		print("ASID CHANGE: "+str(old_asid)+" "+str(new_asid)+" IN_KERNEL: "+str(panda.in_kernel(cpustate))+" "+str(asid_instr_intervals))
#	print(asid_instr_intervals)
	current_asid = new_asid
	ac_instr_start = panda.rr_get_guest_instr_count()
	return 0

@panda.callback.init
def init(handle):
	panda.register_callback(handle, panda.callback.asid_changed, asid_changed)
	return True

>>>>>>> pypanda-fix
panda.load_python_plugin(init,"Cool Plugin")
#panda.begin_replay("/home/luke/recordings/this_is_a_recording")
panda.run()
