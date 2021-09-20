use panda::prelude::*;
use panda::plugins::osi::OSI;

use gdbstub::outputln;

pub(crate) fn print(cpu: &mut CPUState, mut out: impl std::fmt::Write) {
    let thread = OSI.get_current_thread(cpu);

    outputln!(out);
    outputln!(out, "Current thread");
    outputln!(out, "pid: {}", thread.pid);
    outputln!(out, "tid: {}", thread.tid);
    outputln!(out);
}
