use panda::prelude::*;

#[panda::init]
fn init(_: &mut PluginHandle) {
    println!("Initialized!");
}

//#[panda::before_block_exec]
//fn bbe(_cpu: &mut CPUState, _tb: &mut TranslationBlock){
//}
