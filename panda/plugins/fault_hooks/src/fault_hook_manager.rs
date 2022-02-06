use std::{
    cmp::Ordering,
    sync::{Mutex, RwLock},
};

use ord_by_set::{OrdBySet, Order};

use crate::api::{FaultHookCb, PluginNum};
use panda::{mem::virt_to_phys, prelude::*};

const PAGE_SIZE: target_ulong = 4096;
const PAGE_MASK: target_ulong = PAGE_SIZE - 1;

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
struct FaultHookHolder {
    plugin_num: PluginNum,
    page: target_ulong,
    asid: target_ulong,
    cb: Option<FaultHookCb>,
}

impl FaultHookHolder {
    fn new_from_asid(asid: target_ulong) -> Self {
        FaultHookHolder {
            plugin_num: 0,
            page: 0,
            asid: asid,
            cb: None,
        }
    }
}

#[derive(Default)]
struct FaultHookOrderer;

type FaultHookSet = OrdBySet<FaultHookHolder, FaultHookOrderer>;

impl Order<FaultHookHolder> for FaultHookOrderer {
    fn order_of(&self, left: &FaultHookHolder, right: &FaultHookHolder) -> Ordering {
        left.asid.cmp(&right.asid)
    }
}

pub struct FaultHookManager {
    hooks: RwLock<FaultHookSet>,
    add_hooks: Mutex<Vec<FaultHookHolder>>,
    remove_hooks: Mutex<Vec<FaultHookHolder>>,
}

impl FaultHookManager {
    pub fn new() -> Self {
        Self {
            hooks: RwLock::new(FaultHookSet::new()),
            add_hooks: Mutex::new(Vec::new()),
            remove_hooks: Mutex::new(Vec::new()),
        }
    }

    pub fn add_hook(
        &self,
        plugin_num: PluginNum,
        page_addr: target_ulong,
        asid: target_ulong,
        cb: FaultHookCb,
    ) {
        let page = page_addr & !PAGE_MASK;
        let hook = FaultHookHolder {
            plugin_num,
            page,
            asid,
            cb: Some(cb),
        };

        if let Ok(mut hooks) = self.hooks.try_write() {
            hooks.insert(hook);
        } else {
            self.add_hooks.lock().unwrap().push(hook);
        }
    }

    fn update_hooks(&self) {
        // this is the only place where we must be able to write to hooks
        // prevents deadlocks when making an API call in a callback.
        let mut hooks = self.hooks.write().unwrap();
        for h in self.add_hooks.lock().unwrap().drain(..) {
            hooks.insert(h);
        }
        for h in self.remove_hooks.lock().unwrap().drain(..) {
            hooks.remove_specific(&h);
        }
    }

    pub fn run_fault(&self, cpu: &mut CPUState) {
        // only need to update hooks before we run the fault
        self.update_hooks();
        let hooks = self.hooks.read().unwrap();
        let asid = panda::current_asid(cpu);
        if let Some(mhooks) = hooks.get(&FaultHookHolder::new_from_asid(asid)) {
            // we use a temporary vec to hold removed hooks because
            // locking remove_hooks will deadlock if a CB calls
            // remove_plugin
            let mut rem_hooks = Vec::new();
            for &holder in mhooks {
                if holder.asid == asid && virt_to_phys(cpu, holder.page).is_some() {
                    if let Some(cb) = holder.cb {
                        cb(cpu, holder.asid, holder.page);
                        rem_hooks.push(holder);
                    }
                }
            }
            let mut remove_hooks = self.remove_hooks.lock().unwrap();
            for h in rem_hooks {
                remove_hooks.push(h);
            }
        }
    }

    pub fn remove_plugin(&self, num: PluginNum) {
        // add hooks remove too
        self.add_hooks
            .lock()
            .unwrap()
            .drain_filter(|h| h.plugin_num == num);

        // try to write. if not possible, add to remove hooks
        if let Ok(mut hooks) = self.hooks.try_write() {
            hooks.retain(|h| h.plugin_num != num);
        } else {
            let hooks = self.hooks.read().unwrap();
            for holder in hooks.iter() {
                if holder.plugin_num == num {
                    self.remove_hooks.lock().unwrap().push(*holder);
                }
            }
        }
    }
}
