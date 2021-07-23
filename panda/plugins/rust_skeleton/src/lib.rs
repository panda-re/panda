use panda::prelude::*;

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    #[cfg(feature = "aarch64")] {
        panic!("aarch64 is not a supported target");
    }
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
