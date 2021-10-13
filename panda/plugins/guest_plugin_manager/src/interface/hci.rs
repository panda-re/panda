use super::channels::ChannelId;
use super::channels::{poll_plugin_message, publish_message_from_guest,get_channel_from_name};
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
    max_size: usize,
) -> Option<usize> {
    println!("got to hyp_read with CID {}", channel_id);
    if let Some(msg) = poll_plugin_message(channel_id) {
        if msg.len() > max_size{
            panic!();
        }
        // could check max len more
        virtual_memory_write(cpu, addr as target_ulong, &msg);
        println!("end of get some message");
        Some(msg.len())
    } else {
        println!("end of get nothing");
        Some(0)
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
    dbg!(Some(new_manager_channel() as usize))
}

pub fn hyp_get_channel_by_name(
    cpu: &mut CPUState,
    _channel_id: ChannelId,
    buf_ptr: usize,
    buf_size: usize,
) -> Option<usize>{
    println!("channel_by_name");
    if let Ok(buf_out) =
        virtual_memory_read(cpu, buf_ptr as target_ulong, buf_size)
    {
        if let Some(cd) = get_channel_from_name(dbg!(&String::from_utf8_lossy(&buf_out))){
            println!("found channel number {}", cd);
            Some(cd as usize)
        }else{
            println!("failed to find channel number");
            Some(-1_isize as usize)
        }
    } else {
        panic!("Failed to read virtual memory in hyp_write");
    }
}