use panda::prelude::*;
use panda::plugins::osi::OSI;

use gdbstub::outputln;
use tabwriter::{TabWriter, Alignment};

use std::io::Write;

pub(crate) fn print(cpu: &mut CPUState, mut out: impl std::fmt::Write) {
    let procs = OSI.get_processes(cpu);
    let current_pid = OSI.get_current_process(cpu).pid;

    outputln!(out);

    let output = Vec::new();
    let mut output = TabWriter::new(output).padding(1).alignment(Alignment::Right);

    let _ = writeln!(output, " \tPID\tASID\tParent\tCreate Time\tProcess Name");
    let _ = writeln!(output, " \t===\t====\t======\t===========\t============");

    #[allow(unused_must_use)]
    for proc in procs.iter() {
        writeln!(
            output,
            "{}\t{}\t{:#x?}\t{}\t{}\t{}",
            if proc.pid == current_pid { '*' } else { ' ' },
            proc.pid,
            proc.asid,
            proc.ppid,
            proc.create_time,
            proc.get_name()
        );
    }

    let _ = writeln!(output, " \t===\t====\t======\t===========\t============");
    let _ = writeln!(output, " \tPID\tASID\tParent\tCreate Time\tProcess Name");

    let _ = output.flush();
    let output = String::from_utf8(output.into_inner().unwrap()).unwrap();
    outputln!(out, "{}", output);
    outputln!(out);
}
