use api::FAULT_HOOK_MANAGER;
use panda::{current_pc, prelude::*};

#[macro_use]
extern crate lazy_static;

mod api;
mod fault_hook_manager;

fn in_kernel_space(addr: target_ulong) -> bool {
    let msb_mask: target_ulong = 1 << (std::mem::size_of::<target_long>() * 8) - 1;
    addr & msb_mask != 0
}

#[allow(unused_variables)]
#[allow(non_upper_case_globals)]
fn exception_is_page_fault(exception: i32) -> bool {
    // constants match QEMU source
    // unused variables are the NOT case.
    #[cfg(any(feature = "x86_64", feature = "i386"))]
    {
        const EXCP0D_GPF: i32 = 0xe;
        exception == EXCP0D_GPF
    }
    #[cfg(feature = "arm")]
    {
        const EXCP_DATA_ABORT: i32 = 4;
        const EXCP_PREFETCH_ABORT: i32 = 3;
        exception == EXCP_DATA_ABORT || exception == EXCP_PREFETCH_ABORT
    }
    #[cfg(feature = "mips")]
    {
        const EXCP_TLBF: i32 = 26;
        const EXCP_TLBS: i32 = 27;
        const EXCP_AdEL: i32 = 13;
        const EXCP_AdES: i32 = 12;

        exception == EXCP_TLBF
            || exception == EXCP_TLBS
            || exception == EXCP_AdEL
            || exception == EXCP_AdES
    }
    #[cfg(not(any(
        feature = "x86_64",
        feature = "i386",
        feature = "arm",
        feature = "mips"
    )))]
    {
        false
    }
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
    if exception_is_page_fault(en) {
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
