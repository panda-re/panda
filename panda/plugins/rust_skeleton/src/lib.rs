use panda::prelude::*;

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    println!("Initialized!");
    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}

#[panda::before_block_exec]
fn bbe(_cpu: &mut CPUState, _tb: &mut TranslationBlock){
}
