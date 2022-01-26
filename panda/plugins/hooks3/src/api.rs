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
/// This file contains a C-compatible API for hooks3.
///
use crate::bbeio;
// use crate::dyn_sym_hooks::symbol_hook;
use crate::hook_manager::{rust_tb_jmp_cache_hash_func, FnCb, Hook, HookManager};
use panda::sys::{get_cpu, tb_phys_invalidate};
use panda::{current_pc, prelude::*};
use std::sync::atomic::{AtomicU32, Ordering};

extern "C" {
    fn qemu_in_vcpu_thread() -> bool;
    fn panda_do_exit_cpu();
    fn tb_trylock() -> i32;
    fn tb_lock_reset();
}

lazy_static! {
    pub(crate) static ref HMANAGER: HookManager = HookManager::new();
}

pub(crate) type PluginReg = u32;
static PLUGIN_REG_NUM: AtomicU32 = AtomicU32::new(1);

#[no_mangle]
pub extern "C" fn register_plugin() -> PluginReg {
    PLUGIN_REG_NUM.fetch_add(1, Ordering::SeqCst)
}

#[no_mangle]
pub extern "C" fn unregister_plugin(num: PluginReg) {
    HMANAGER.remove_plugin(num);
}

pub fn eval_jmp_list_val(cpu: &mut CPUState, pc: target_ulong, val: usize) -> bool {
    let vdir = val as usize & 2;
    let tb = vdir as *mut TranslationBlock;
    if !tb.is_null() {
        if vdir == 2 || vdir == 3 {
            false
        } else {
            pc_in_tb(cpu, pc, tb)
        }
    } else {
        false
    }
}

pub fn pc_in_tb(cpu: &mut CPUState, pc: target_ulong, tb: *mut TranslationBlock) -> bool {
    // println!("tb {:x}", tb as usize);
    unsafe {
        if tb.is_null() {
            false
        } else {
            if (*tb).pc <= pc && pc < (*tb).pc + (*tb).size as target_ulong {
                println!("returning true for pc_in_tb");
                true
            } else {
                eval_jmp_list_val(cpu, pc, (*tb).jmp_list_next[0])
                    || eval_jmp_list_val(cpu, pc, (*tb).jmp_list_next[1])
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn add_hook3(
    num: PluginReg,
    pc: target_ulong,
    asid: target_ulong,
    always_starts_block: bool,
    fun: FnCb,
) {
    // TODO: Consider returning hash value of hook to plugin to
    // uniquely identify it so it can be removed with the same
    // value. Alternatively, use a UID

    if HMANAGER.add(&Hook {
        pc,
        asid: match asid {
            0 => None,
            p => Some(p),
        },
        cb: Some(fun),
        always_starts_block,
        plugin_num: num,
    }) {
        unsafe {
            let cpu = &mut *get_cpu();
            let vcpu_thread = qemu_in_vcpu_thread();
            if vcpu_thread && cpu.running {
                // if we can't get it we're in a TCG thread so we should
                // already have it.
                let res = tb_trylock();
                let current_pc = current_pc(cpu);
                let index = rust_tb_jmp_cache_hash_func(current_pc);
                let tb = cpu.tb_jmp_cache[index as usize];
                if pc_in_tb(cpu, pc, tb) {
                    tb_phys_invalidate(tb, u64::MAX);
                    panda_do_exit_cpu();
                }
                // if we got a TB lock explicitly go ahead and clear some
                // TBs. Otherwise enable bbeio to do it for us on the next
                // run.
                if res == 0 {
                    HMANAGER.clear_tbs(cpu, Some(tb));
                    tb_lock_reset();
                } else {
                    bbeio::enable();
                }
            }
        }
    }
}

// plugin_import! {
//     static DYNAMIC_SYMBOLS: DynamicSymbols = extern "dynamic_symbols"{
//         void (*hook_symbol_resolution_dlsym)(struct hook_symbol_resolve*);
//     }
// }

// #[no_mangle]
// pub extern "C" fn add_symbol_hook3(sh: &symbol_hook) {}
