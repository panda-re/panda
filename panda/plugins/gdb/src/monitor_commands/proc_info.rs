use panda::prelude::*;
use panda::plugins::osi::OSI;

use gdbstub::outputln;

pub(crate) fn print(cpu: &mut CPUState, mut out: impl std::fmt::Write) {
    let proc = OSI.get_current_process(cpu);

    outputln!(out);
    outputln!(out, "{}", proc.get_name());
    outputln!(out, "====================");
    outputln!(out, "PID: {}", proc.pid);
    outputln!(out, "ASID: {:#x?}", proc.asid);
    outputln!(out, "Parent PID: {}", proc.ppid);
    outputln!(out, "Creation time: {}", proc.create_time);
    outputln!(out, "PC in shared library: {}", OSI.in_shared_object(cpu, &*proc));
    outputln!(out);
}
