#![feature(once_cell)]
use once_cell::sync::OnceCell;

use panda::plugins::glib::{GBox, GBoxedSlice};
use panda::plugins::osi::{OsiModule, OsiProc, OsiProcHandle, OsiThread};
use panda::{current_asid, plugin_import, prelude::*};
mod api;
mod symbol_manager;
use api::SYMBOL_MANAGER;

use panda::plugins::proc_start_linux::AuxvValues;
use symbol_manager::{Hook, HOOKS3, HOOKS3_PLUGIN_REG};

#[macro_use]
extern crate lazy_static;

plugin_import! {
    static PROC_START_LINUX: ProcStartLinux = extern "proc_start_linux" {
        callbacks {
            fn on_rec_auxv(cpu: &mut CPUState, tb: &mut TranslationBlock, auxv: &AuxvValues);
        }
    };
}

plugin_import! {
    static OSI: Osi = extern "osi" {
        fn get_process_handles(cpu: *mut CPUState) -> GBoxedSlice<OsiProcHandle>;
        fn get_current_thread(cpu: *mut CPUState) -> GBox<OsiThread>;
        fn get_modules(cpu: *mut CPUState) -> GBoxedSlice<OsiModule>;
        fn get_mappings(cpu: *mut CPUState, p: *mut OsiProc) -> GBoxedSlice<OsiModule>;
        fn get_processes(cpu: *mut CPUState) -> GBoxedSlice<OsiProc>;
        fn get_current_process(cpu: *mut CPUState) -> GBox<OsiProc>;
    };
}

extern "C" fn library_page_hook() {}

extern "C" fn library_start_hook(cpu: &mut CPUState, tb: &mut TranslationBlock, h: &Hook) -> bool {
    true
}

extern "C" fn program_start_hook(
    cpu: &mut CPUState,
    _tb: &mut TranslationBlock,
    _h: &Hook,
) -> bool {
    SYMBOL_MANAGER.hook_module_entries(cpu);
    true
}

extern "C" fn on_program_start(cpu: &mut CPUState, _tb: &mut TranslationBlock, auxv: &AuxvValues) {
    let program_entry_addr = if cfg!(target = "arm") {
        auxv.entry & !0x1
    } else {
        auxv.entry
    };
    HOOKS3.add_hook3(
        *HOOKS3_PLUGIN_REG.get().unwrap(),
        program_entry_addr,
        current_asid(cpu),
        true,
        program_start_hook,
    );
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    HOOKS3_PLUGIN_REG.set(HOOKS3.register_plugin()).unwrap();
    PROC_START_LINUX.add_callback_on_rec_auxv(on_program_start);

    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    // panda::get_plugin
    if let Some(hooks3) = HOOKS3_PLUGIN_REG.get() {
        HOOKS3.unregister_plugin(*hooks3);
    }
    println!("Exiting");
}
