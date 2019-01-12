from pypanda import *
from time import sleep

ac_instr_start = 0


def InstrRange:
	def __init__(self, old_instr, new_instr):
		self.old = old # first
		self.new = new # secod

asid_rr_sub_factor = {} # (int -> instr)
asid_instr_intervals = {}	# (int -> instrrange)

def update_asid_rr_sub_factor(old_asid, rr):
	if old_asid not in asid_instr_intervals:
		asid_instr_intervals[old_asid] = [rr]
	else:
		asid_instr_intervals[old_asid].append(rr)
	rri_len = rr.new - rr.old
	for kvp in asid_rr_sub_factor:
		asid = kvp.old_instr
		if asid != old_asid:
			asid_rr_sub_factor[asid] += rri_len
	if len(asid_rr_sub_factor) == 0:
		asid_rr_sub_factor[old_asid] = panda.rr_get_guest_instr_count_external()

@panda.callback.asid_changed
def asid_changed(cpustate, old_asid, new_asid):
	if new_asid < 10:
		return 0
	instr = panda.get_guest_instr_count()	
	if (old_asid != new_asid):
		
	ac_instr_count = panda.get_guest_instr_count()
	return 0

@panda.callback.init
def init(handle):
	panda.register_callback(handle, panda.callback.asid_changed, asid_changed)
	return True

panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img", mem="2048M")
panda.load_python_plugin(init,"Cool Plugin")
#panda.begin_replay("/home/luke/recordings/this_is_a_recording")
panda.run()
