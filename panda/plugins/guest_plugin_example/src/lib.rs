use panda::{plugins::guest_plugin_manager::*, prelude::*};
use std::io::Write;

// Print out all the messages sent from the guest
#[channel_recv]
fn message_recv(_: u32, data: &str) {
    println!("[rust_example] {}", data);
}

#[panda::init]
fn init(_: &mut PluginHandle) {
    let mut channel = load_guest_plugin("rust_example", message_recv);

    // the `rust_example` plugin expects to be sent a u32 which it will log
    // so let's sent it one.
    let num: u32 = 1234;
    channel.write_all(&num.to_le_bytes()).unwrap();
}
