use panda::{
    plugins::{hooks::Hook, osi2::symbol_addr_from_name, syscalls2::Syscalls2Callbacks},
    prelude::*,
};

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    let sys_callback = panda::PppCallback::new();
    sys_callback.on_all_sys_enter(move |_, _, _| {
        let printk_addr = symbol_addr_from_name("printk");

        println!("printk @ {:#x?}", printk_addr);

        printk_hook::hook()
            .before_block_exec()
            //.kernel(true)
            .at_addr(printk_addr);

        sys_callback.disable();
    });

    true
}

#[panda::hook]
fn printk_hook(_: &mut CPUState, _: &mut TranslationBlock, _hook: &mut Hook) {
    println!("printk hit");
}
