use panda::prelude::*;

#[panda::init]
fn init(_: &mut PluginHandle) {
    println!("Initialized!");
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}

#[panda::before_block_exec]
fn bbe(_cpu: &mut CPUState, _tb: &mut TranslationBlock) {
    // runs every basic block
}
