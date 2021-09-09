use panda::prelude::*;
use panda::regs::Reg;

use peg::{str::LineCol, error::ParseError};

use std::convert::TryInto;

pub(crate) enum Command {
    Taint(TaintTarget, u32),
    CheckTaint(TaintTarget),
    GetTaint(TaintTarget),
    Help,
    MemInfo,
    ThreadInfo,
    ProcInfo,
    ProcList,
}

impl Command {
    pub(crate) fn parse(cmd: &str) -> Result<Self, ParseError<LineCol>> {
        monitor_commands::command(cmd)
    }
}

pub(crate) enum TaintTarget {
    Address(target_ptr_t),
    Register(Reg),
}

peg::parser!{
    grammar monitor_commands() for str {
        pub(crate) rule command() -> Command
            = taint()
            / check_taint()
            / get_taint()
            / mem_info()
            / proc_info()
            / proc_list()
            / thread_info()
            / help()

        rule help() -> Command
            = "help" { Command::Help }

        rule mem_info() -> Command
            = "meminfo" { Command::MemInfo }

        rule proc_info() -> Command
            = "procinfo" { Command::ProcInfo }

        rule proc_list() -> Command
            = "proclist" { Command::ProcList }

        rule thread_info() -> Command
            = "threadinfo" { Command::ThreadInfo }

        rule taint() -> Command
            = "taint" _ target:taint_target() _ label:number() {
                Command::Taint(target, label as u32)
            }

        rule taint_target() -> TaintTarget
            = quiet!{
                "*" addr:number() { TaintTarget::Address(addr.try_into().unwrap()) }
                / reg:register() { TaintTarget::Register(reg) }
            }
            / expected!("an address (example: *0x55555555) or a register name")

        rule check_taint() -> Command
            = "check_taint" _ target:taint_target() { Command::CheckTaint(target) }

        rule get_taint() -> Command
            = "get_taint" _ target:taint_target() { Command::GetTaint(target) }

        // TODO: display available registers on error
        rule register() -> Reg
            = reg:$(['a'..='z' | 'A'..='Z'] ['a'..='z' | 'A'..='Z' | '0'..='9']*) {?
                reg.parse()
                    .map_err(|_| "invalid register name")
            }

        rule number() -> u64
            = quiet!{
                "0x" hex:$(['0'..='9' | 'a'..='f' | 'A'..='F']+) {?
                    u64::from_str_radix(hex, 16)
                        .map_err(|_| "invalid hex number")
                }
                / decimal:$(['0'..='9']+) {?
                    decimal.parse()
                        .map_err(|_| "invalid decimal number")
                }
            }
            / expected!("a number")

        rule _() = quiet!{ [' ' | '\n' | '\t']+ }
    }
}
