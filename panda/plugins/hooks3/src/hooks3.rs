#![feature(backtrace)]
use std::arch::asm;
use std::backtrace::Backtrace;
use std::env::Args;

/// PANDABEGINCOMMENT
///
///  Authors:
///  Luke Craig                  luke.craig@ll.mit.edu
///
/// This work is licensed under the terms of the GNU GPL, version 2.
/// See the COPYING file in the top-level directory.
///
/// PANDAENDCOMMENT
///
/// DESCRIPTION:
///
/// This file is the PANDA plugin interactions: init, uninit, and callbacks.
///
/// It also contains the callback inserted for TCG instrumentation.
///
use panda::prelude::*;
use panda::sys::panda_do_flush_tb;

#[macro_use]
extern crate lazy_static;

mod hook_manager;

mod api;
use api::HMANAGER;

extern "C" fn middle_filter(cpu: &mut CPUState, tb: &mut TranslationBlock, pc: target_ulong) {
    HMANAGER.run_tb(cpu, tb, pc);
}

#[panda::before_tcg_codegen]
pub fn tcg_codegen(cpu: &mut CPUState, tb: &mut TranslationBlock) {
    HMANAGER.new_hooks_add();
    HMANAGER.clear_tbs(cpu, Some(tb));
    HMANAGER.insert_on_matches(cpu, tb);
    // println!("tcg_codegen end");
}

extern "C" {
    fn tb_lock();
    fn tb_unlock();
}

#[panda::before_block_exec_invalidate_opt]
pub fn bbeio(cpu: &mut CPUState, tb: &mut TranslationBlock) -> bool {
    bbeio::disable();
    // bbeio does not hold tb_lock unlike tcg_codegen
    unsafe {
        tb_lock();
    }
    HMANAGER.new_hooks_add();
    HMANAGER.clear_tbs(cpu, Some(tb));
    unsafe {
        tb_unlock();
    }
    false
}

#[panda::init]
pub fn init(_: &mut PluginHandle) -> bool {
    tcg_codegen::disable();
    bbeio::disable();
    true
}

#[panda::uninit]
pub fn exit(_: &mut PluginHandle) {
    unsafe {
        panda_do_flush_tb();
    }
}
