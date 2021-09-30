use super::plugin::ChannelId;
use super::plugin::{poll_plugin_message, publish_message_from_guest};
use panda::mem::{virtual_memory_read, virtual_memory_write};
use panda::prelude::*;

pub fn hyp_start(
    cpu: &mut CPUState,
    channel_id: ChannelId,
    arg1: usize,
    _arg2: usize,
) -> Option<usize> {
    None
}
pub fn hyp_stop(
    cpu: &mut CPUState,
    channel_id: ChannelId,
    arg1: usize,
    _arg2: usize,
) -> Option<usize> {
    None
}
pub fn hyp_read(
    cpu: &mut CPUState,
    channel_id: ChannelId,
    addr: usize,
    max_size: usize,
) -> Option<usize> {
    if let Some(msg) = poll_plugin_message(channel_id) {
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
    cpu: &mut CPUState,
    channel_id: ChannelId,
    arg1: usize,
    _arg2: usize,
) -> Option<usize> {
    None
}
