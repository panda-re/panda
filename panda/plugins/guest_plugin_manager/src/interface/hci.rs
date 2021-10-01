use super::channels::ChannelId;
use super::channels::{poll_plugin_message, publish_message_from_guest};
use super::plugin_manager::new_manager_channel;
use crate::MAGIC;
use panda::mem::{virtual_memory_read, virtual_memory_write};
use panda::prelude::*;

pub fn hyp_start(
    _cpu: &mut CPUState,
    _channel_id: ChannelId,
    _arg1: usize,
    _arg2: usize,
) -> Option<usize> {
    println!("start");
    Some(!MAGIC)
}
pub fn hyp_stop(
    _cpu: &mut CPUState,
    _channel_id: ChannelId,
    _arg1: usize,
    _arg2: usize,
) -> Option<usize> {
    println!("stop");
    None
}
pub fn hyp_read(
    cpu: &mut CPUState,
    channel_id: ChannelId,
    addr: usize,
    _max_size: usize,
) -> Option<usize> {
    println!("read");
    if let Some(msg) = poll_plugin_message(channel_id) {
        // could check max len more
        virtual_memory_write(cpu, addr as target_ulong, &msg);
        Some(msg.len())
    } else {
        None
    }
}
pub fn hyp_write(
    cpu: &mut CPUState,
    channel_id: ChannelId,
    buf_ptr: usize,
    buf_size: usize,
) -> Option<usize> {
    println!("write");
    if let Ok(buf_out) =
        virtual_memory_read(cpu, buf_ptr as target_ulong, buf_size)
    {
        publish_message_from_guest(channel_id, buf_out);
        Some(0)
    } else {
        println!("Failed to read virtual memory in hyp_write");
        None
    }
}
pub fn hyp_error(
    _cpu: &mut CPUState,
    _channel_id: ChannelId,
    _arg1: usize,
    _arg2: usize,
) -> Option<usize> {
    println!("error");
    None
}

pub fn hyp_get_manager(
    _cpu: &mut CPUState,
    _channel_id: ChannelId,
    _arg1: usize,
    _arg2: usize,
) -> Option<usize> {
    println!("get_manager");
    Some(new_manager_channel() as usize)
}

