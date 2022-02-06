use std::sync::atomic::{AtomicU32, Ordering};

use panda::prelude::*;

use crate::fault_hook_manager::FaultHookManager;

pub(crate) type FaultHookCb =
    extern "C" fn(cpu: *mut CPUState, asid: target_ulong, page_addr: target_ulong) -> bool;

pub(crate) type PluginNum = u32;

pub(crate) const PLUGIN_START_NUM: PluginNum = 1;

pub static PLUGIN_REG_NUM: AtomicU32 = AtomicU32::new(PLUGIN_START_NUM);

lazy_static! {
    pub static ref FAULT_HOOK_MANAGER: FaultHookManager = FaultHookManager::new();
}

#[no_mangle]
pub extern "C" fn fault_hooks_register_plugin() -> PluginNum {
    PLUGIN_REG_NUM.fetch_add(1, Ordering::SeqCst)
}

#[no_mangle]
pub extern "C" fn fault_hooks_unregister_plugin(num: PluginNum) {
    FAULT_HOOK_MANAGER.remove_plugin(num);
}

#[no_mangle]
pub extern "C" fn fault_hooks_add_hook(
    plugin_num: PluginNum,
    page_addr: target_ulong,
    asid: target_ulong,
    cb: FaultHookCb,
) {
    FAULT_HOOK_MANAGER.add_hook(plugin_num, page_addr, asid, cb);
}
