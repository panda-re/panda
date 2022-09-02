use api::FAULT_HOOK_MANAGER;
use panda::{current_pc, prelude::*};

#[macro_use]
extern crate lazy_static;

mod api;
mod fault_hook_manager;
mod exceptions;
use exceptions::EXCEPTIONS;

fn in_kernel_space(addr: target_ulong) -> bool {
    let msb_mask: target_ulong = 1 << (std::mem::size_of::<target_long>() * 8) - 1;
    addr & msb_mask != 0
}

#[panda::start_block_exec]
fn sbe(cpu: &mut CPUState, _tb: &mut TranslationBlock) {
    // wait until out of the kernel space
    if !in_kernel_space(current_pc(cpu)) {
        FAULT_HOOK_MANAGER.run_fault(cpu);
        sbe::disable();
    }
}

#[panda::before_handle_exception]
fn handle_exception(_cpu: &mut CPUState, en: i32) -> i32 {
    if EXCEPTIONS.contains(&en) {
        sbe::enable();
    }
    en
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    if cfg!(not(any(
        feature = "x86_64",
        feature = "i386",
        feature = "arm",
        feature = "mips"
    ))) {
        panic!("Unsupported architecture");
    } else {
        sbe::disable();
        true
    }
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {}
