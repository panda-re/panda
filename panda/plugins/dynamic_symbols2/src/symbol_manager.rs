use std::{
    ascii::AsciiExt,
    collections::{HashMap, HashSet},
    ffi::CStr,
    mem::MaybeUninit,
};

// use setjmp::{jmp_buf, setjmp, sigjmp_buf};

use crate::{library_start_hook, OSI};
use libc::{c_void, Elf32_Ehdr};
use once_cell::sync::OnceCell;
#[cfg(any(feature = "i386", feature = "x86_64"))]
use panda::sys::CPUX86State;
use panda::{current_asid, mem::virtual_memory_read, plugin_import, prelude::*};
use panda::{current_pc, sys::MMUAccessType_MMU_DATA_LOAD};
use panda::{sys::MMUAccessType, CPUArchPtr};
use std::sync::{Mutex, RwLock};

type Asid = target_ulong;

type PluginReg = u32;
// hooks callback type
pub(crate) type FnCb = extern "C" fn(&mut CPUState, &mut TranslationBlock, &Hook) -> bool;

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
pub(crate) static HOOKS3_PLUGIN_REG: OnceCell<PluginReg> = OnceCell::new();

plugin_import! {
    static HOOKS3: Hooks3 = extern "hooks3"{
        fn add_hook3(
            num: PluginReg,
            pc: target_ulong,
            asid: target_ulong,
            always_starts_block: bool,
            fun: FnCb,
        );
        fn register_plugin() -> PluginReg;
        fn unregister_plugin(num: PluginReg);
    };
}

type FaultHookCb =
    extern "C" fn(cpu: *mut CPUState, asid: target_ulong, page_addr: target_ulong) -> bool;
type PluginNum = u32;
plugin_import! {
    static FAULT_HOOKS: FaultHooks = extern "fault_hooks" {
        fn fault_hooks_add_hook(
            plugin_num: PluginNum,
            page_addr: target_ulong,
            asid: target_ulong,
            cb: FaultHookCb,
        );
        fn fault_hooks_unregister_plugin(num: PluginNum);
        fn fault_hooks_register_plugin() -> PluginNum;
    };
}

pub struct Library {
    name: String,
    symbols: HashMap<String, target_ulong>,
}

pub struct ProgramLibraryState {
    libraries: HashMap<String, Library>,
}

pub struct SymbolManager {
    programs: RwLock<HashMap<Asid, ProgramLibraryState>>,
    libraries: RwLock<Vec<Library>>,
    inserted_hooks: Mutex<Vec<Hook>>,
}

extern "C" {
    static tcg_call_return_addr: u64;
    fn request_tlb_fill(addr: target_ulong);
}
#[cfg(any(feature = "i386", feature = "x86_64"))]
extern "C" {
    fn raise_exception_ra(env: *mut CPUX86State, exception_index: i32, retaddr: u64);
    // fn setjmp(env: [u8; 200]) -> i32;
}

impl SymbolManager {
    pub fn new() -> Self {
        Self {
            programs: RwLock::new(HashMap::new()),
            libraries: RwLock::new(Vec::new()),
            inserted_hooks: Mutex::new(Vec::new()),
        }
    }

    pub fn resolve_symbols(&self, cpu: &mut CPUState) {}

    pub fn hook_module_entries(&self, cpu: &mut CPUState) {
        let mut current_process = OSI.get_current_process(cpu);
        if current_process.as_ptr().is_null() {
            return;
        }
        let mut mapped_libraries: HashSet<String> = HashSet::new();
        OSI.get_mappings(cpu, &mut *current_process)
            .iter()
            .for_each(|lib| {
                if lib.name.is_null() {
                    return;
                }
                let name = match unsafe { CStr::from_ptr(lib.name) }.to_str().to_owned() {
                    Ok(name) => name,
                    Err(_x) => return,
                };
                if mapped_libraries.contains(&name.to_owned()) {
                    return;
                }
                if name.contains("[???]") {
                    return;
                }
                if let Ok(header) =
                    virtual_memory_read(cpu, lib.base, std::mem::size_of::<Elf32_Ehdr>())
                {
                    if header[0..3] == [0x7F, 0x45, 0x4C, 0x46] {
                        let elf_header = unsafe { &*(header.as_ptr() as *const Elf32_Ehdr) };
                        let entry_addr = lib.base + elf_header.e_entry as target_ulong;
                        HOOKS3.add_hook3(
                            *HOOKS3_PLUGIN_REG.get().unwrap(),
                            entry_addr,
                            current_asid(cpu),
                            true,
                            library_start_hook,
                        );
                        mapped_libraries.insert(name.to_owned());
                    } else {
                        return;
                    }
                } else {
                    let base = lib.base;
                    let pc = panda::current_pc(cpu);
                    let asid = panda::current_asid(cpu);
                    println!("failed to read header {base:x} PC={pc:x} ASID={asid:x}\n");
                    // FAULT_HOOOKS.
                }
            });
    }
}
