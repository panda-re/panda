use panda::prelude::*;
use panda::plugin_import;





#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    println!("Initialized!");
    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}