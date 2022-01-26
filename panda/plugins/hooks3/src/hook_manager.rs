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
/// This file does most of the state management for the hooks plugin.
///
/// The vast majority of the logic is implemented in the hook manager.
///
use crate::api::PluginReg;
use crate::{middle_filter, tcg_codegen};
use std::cmp::{Ord, Ordering};
use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::{Mutex, RwLock};

use ord_by_set::{OrdBySet, Order};
use panda::current_asid;
use panda::prelude::{target_ulong, CPUState, TranslationBlock};
use panda::sys::{tb_phys_invalidate, TCGOp};

// middle callback type
pub(crate) type MCB = extern "C" fn(&mut CPUState, &mut TranslationBlock, pc: target_ulong);
// check_cpu_exit callback type
pub(crate) type CCE = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
// hooks callback type
pub(crate) type FnCb = extern "C" fn(&mut CPUState, &mut TranslationBlock, &Hook) -> bool;
// wrapper function
pub(crate) type WFN = unsafe extern "C" fn(CCE, a1: *mut c_void, a2: *mut c_void, a3: *mut c_void);

extern "C" {
    fn find_first_guest_insn() -> *mut TCGOp;
    fn find_guest_insn_by_addr(pc: target_ulong) -> *mut TCGOp;
    fn call_3p_check_cpu_exit(f: CCE, a1: *mut c_void, a2: *mut c_void, a3: *mut c_void);
    #[allow(improper_ctypes)]
    fn insert_call_4p(
        after_op: *mut *mut TCGOp,
        wrapper_fn: WFN,
        fun: MCB,
        cpu: &mut CPUState,
        tb: &mut TranslationBlock,
        pc: target_ulong,
    );
}

// ARM doesn't export because it's technically variable,
// but realistically it's 12
const TARGET_PAGE_BITS: u32 = 12;

const TB_JMP_CACHE_BITS: u32 = 12;
const TB_JMP_PAGE_BITS: u32 = TB_JMP_CACHE_BITS / 2;
const TB_JMP_PAGE_SIZE: u32 = 1 << TB_JMP_PAGE_BITS;
const TB_JMP_ADDR_MASK: u32 = TB_JMP_PAGE_SIZE - 1;
const TB_JMP_CACHE_SIZE: u32 = 1 << TB_JMP_CACHE_BITS;
const TB_JMP_PAGE_MASK: u32 = TB_JMP_CACHE_SIZE - TB_JMP_PAGE_SIZE;

pub fn rust_tb_jmp_cache_hash_func(pc: target_ulong) -> u32 {
    let tmp = pc ^ (pc >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS));
    (((tmp >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS)) & TB_JMP_PAGE_MASK as target_ulong)
        | (tmp & TB_JMP_ADDR_MASK as target_ulong)) as u32
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Hook {
    /// program counter as virtual address
    pub pc: target_ulong,
    ///optional value that represents the ASID to match to
    pub asid: Option<target_ulong>,
    /// associated plugin ID number
    pub plugin_num: PluginReg,
    /// pointer to C function to call
    pub cb: Option<FnCb>,
    /// guarantee that PC starts the TB
    pub always_starts_block: bool,
}

impl Hook {
    pub fn from_pc_asid(pc: target_ulong, asid: Option<target_ulong>) -> Self {
        Self {
            pc,
            asid,
            plugin_num: 0,
            cb: None,
            always_starts_block: false,
        }
    }
    pub fn from_pc(pc: target_ulong) -> Self {
        Self {
            pc,
            asid: None,
            plugin_num: 0,
            cb: None,
            always_starts_block: false,
        }
    }
}

impl PartialEq for Hook {
    fn eq(&self, other: &Self) -> bool {
        if self.pc == other.pc && self.asid == other.asid && self.plugin_num == other.plugin_num {
            match (self.cb, other.cb) {
                (None, None) => true,
                (Some(a), Some(b)) => a as usize == b as usize,
                _ => false,
            }
        } else {
            false
        }
    }
}

#[derive(Default)]

struct HookOrderer;

type HookSet = OrdBySet<Hook, HookOrderer>;

impl Order<Hook> for HookOrderer {
    fn order_of(&self, left: &Hook, right: &Hook) -> Ordering {
        match left.pc.cmp(&right.pc) {
            Ordering::Equal => left.asid.cmp(&right.asid),
            other => other,
        }
    }
}

#[derive(Clone)]
pub struct HookManagerState {
    clear_full_tb: Vec<target_ulong>,
    clear_start_tb: Vec<target_ulong>,
}

pub struct HookManager {
    add_hooks: Mutex<Vec<Hook>>,
    hooks: RwLock<HookSet>,
    instrumented_pcs: RwLock<HashSet<target_ulong>>,
    state: Mutex<HookManagerState>,
}

impl HookManager {
    pub fn new() -> Self {
        Self {
            add_hooks: Mutex::new(Vec::new()),
            hooks: RwLock::new(HookSet::new()),
            instrumented_pcs: RwLock::new(HashSet::new()),
            state: Mutex::new(HookManagerState {
                clear_full_tb: Vec::new(),
                clear_start_tb: Vec::new(),
            }),
        }
    }

    pub fn has_hooks(self: &Self) -> bool {
        let hooks = self.hooks.read().unwrap();
        return !hooks.is_empty();
    }

    pub fn add(self: &Self, h: &Hook) -> bool {
        if !self.has_hooks() {
            tcg_codegen::enable();
        }
        let hooks = self.hooks.read().unwrap();
        if !hooks.contains(h) {
            let mut add_hooks = self.add_hooks.lock().unwrap();
            if !add_hooks.contains(h) {
                add_hooks.push(*h);
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn new_hooks_add(self: &Self) {
        let mut add_hooks = self.add_hooks.lock().unwrap();
        if !add_hooks.is_empty() {
            let mut hooks = self.hooks.write().unwrap();
            let mut state = self.state.lock().unwrap();
            for &h in add_hooks.iter() {
                hooks.insert(h);
                if h.always_starts_block {
                    state.clear_start_tb.push(h.pc);
                } else {
                    state.clear_full_tb.push(h.pc);
                }
            }
            add_hooks.clear();
        }
    }

    fn clear_empty_hooks(self: &Self, matched_hooks: Vec<Hook>) {
        if !matched_hooks.is_empty() {
            let mut hooks = self.hooks.write().unwrap();
            for &elem in matched_hooks.iter() {
                hooks.remove_specific(&elem);
            }
        }

        if !self.has_hooks() {
            tcg_codegen::disable();
        }
    }

    pub fn remove_plugin(self: &Self, num: PluginReg) {
        let hooks = self.hooks.read().unwrap();
        let mut matched_hooks = Vec::new();
        for &elem in hooks.iter() {
            if elem.plugin_num == num {
                matched_hooks.push(elem);
            }
        }
        drop(hooks);
        self.clear_empty_hooks(matched_hooks);
    }

    fn run_tb_asid(
        self: &Self,
        cpu: &mut CPUState,
        tb: &mut TranslationBlock,
        target_pc: target_ulong,
        asid: Option<target_ulong>,
    ) {
        let hooks = self.hooks.read().unwrap();
        if let Some(matching) = hooks.get(&Hook::from_pc_asid(target_pc, asid)) {
            let mut matched_hooks = Vec::new();
            for &elem in matching {
                if elem.asid == asid {
                    if let Some(cb) = elem.cb {
                        if cb(cpu, tb, &elem) {
                            matched_hooks.push(elem);
                        }
                    }
                }
            }
            drop(hooks);
            if !matched_hooks.is_empty() {
                self.clear_empty_hooks(matched_hooks);
            }
        }
    }

    pub fn run_tb(
        self: &Self,
        cpu: &mut CPUState,
        tb: &mut TranslationBlock,
        target_pc: target_ulong,
    ) {
        self.new_hooks_add();
        self.run_tb_asid(cpu, tb, target_pc, None);
        let asid = current_asid(cpu);
        self.run_tb_asid(cpu, tb, target_pc, Some(asid));
    }

    pub fn insert_on_matches(self: &Self, cpu: &mut CPUState, tb: &mut TranslationBlock) {
        let pc_start = tb.pc;
        let pc_end = tb.pc + tb.size as target_ulong - 1;

        let hooks = self.hooks.read().unwrap();

        if let Some(matched) = hooks.range(&Hook::from_pc(pc_start), &Hook::from_pc(pc_end)) {
            let mut matched_pcs = HashSet::new();
            for &elem in matched {
                // add matches to set. avoid duplicates
                if matched_pcs.contains(&elem.pc) {
                    continue;
                }

                // get op by technique based on guarantees
                let mut op = unsafe {
                    if elem.always_starts_block || tb.pc == elem.pc {
                        find_first_guest_insn()
                    } else {
                        find_guest_insn_by_addr(elem.pc)
                    }
                };

                // check op and insert both middle filter and check_cpu_exit
                // so we can cpu_exit if need be.
                if !op.is_null() {
                    // println!("inserting call {:x}", elem.pc);
                    unsafe {
                        insert_call_4p(
                            &mut op,
                            call_3p_check_cpu_exit,
                            middle_filter,
                            cpu,
                            tb,
                            elem.pc,
                        );
                    }
                } else {
                    println!("failed insertion");
                    assert_eq!(1, 0);
                }
                matched_pcs.insert(elem.pc);
            }
            // iterate over matches. Add matches to set to avoid duplicates
            let mut instrumented_pcs = self.instrumented_pcs.write().unwrap();
            for pc in matched_pcs.iter() {
                instrumented_pcs.insert(*pc);
            }
        }
    }

    pub fn clear_tbs(self: &Self, cpu: &mut CPUState, tb: Option<*mut TranslationBlock>) {
        // start_tbs guarantee that pc is the start of the block
        let mut state = self.state.lock().unwrap();
        if !state.clear_start_tb.is_empty() {
            let instrumented_pcs = self.instrumented_pcs.read().unwrap();
            for &pc in state.clear_start_tb.iter() {
                if !instrumented_pcs.contains(&pc) {
                    let index = rust_tb_jmp_cache_hash_func(pc);
                    unsafe {
                        let pot = cpu.tb_jmp_cache[index as usize];
                        if !pot.is_null() && Some(pot) != tb && (*pot).pc == pc {
                            // u64::MAX -> -1
                            tb_phys_invalidate(pot, u64::MAX);
                        }
                    }
                }
            }
            state.clear_start_tb.clear();
        }
        //full_tbs can be any part of the block
        if !state.clear_full_tb.is_empty() {
            let instrumented_pcs = self.instrumented_pcs.read().unwrap();
            for &elem in cpu.tb_jmp_cache.iter() {
                if !elem.is_null() && Some(elem) != tb {
                    for &pc in state.clear_full_tb.iter() {
                        if !instrumented_pcs.contains(&pc) {
                            unsafe {
                                if (*elem).pc <= pc
                                    && pc < (*elem).pc + (*elem).size as target_ulong
                                {
                                    // u64::MAX -> -1
                                    tb_phys_invalidate(elem, u64::MAX);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            state.clear_full_tb.clear();
        }
    }
}
