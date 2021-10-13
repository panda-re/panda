use super::channels::{publish_message_to_guest,ChannelId,add_channel};
use std::mem::size_of;
use std::convert::TryFrom;
use std::slice::from_raw_parts;

type OperationID = u32; 


enum ManagerOp {
    GetChannelFromName = 0,
    DebugOutput = 2,
}

impl TryFrom<usize> for ManagerOp {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, ()> {
        match value {
            0 => Ok(ManagerOp::GetChannelFromName),
            2 => Ok(ManagerOp::DebugOutput),
            _ => Err(()),
        }
    }
}

fn get_channel_from_name(origin_channel: ChannelId, buffer: Vec<u8>){
    let plugin_name = String::from_utf8_lossy(&buffer).into_owned();
    if let Some(channel_id) =  super::channels::get_channel_from_name(&plugin_name){
        println!("success got channel from name {} FD is {}", plugin_name, channel_id);
        let buf = u32::to_le_bytes(channel_id);

        publish_message_to_guest(origin_channel,buf.to_vec());
    }else{
        println!("Failed to get channel from name");
    }
}

extern "C" fn read_callback(channel_id: ChannelId, ptr: *const u8, len: usize){
    println!("made it to read callback");
    let mut buf = unsafe{from_raw_parts(ptr, len).to_vec()};
    const OPSIZE: usize = size_of::<OperationID>();
    let mut operation: [u8;OPSIZE] = [0;4];
    operation.copy_from_slice(&buf[..OPSIZE]);
    let op_num = OperationID::from_le_bytes(operation);
    buf.drain(0..OPSIZE);
    match ManagerOp::try_from(op_num as usize) {
        Ok(ManagerOp::GetChannelFromName) => get_channel_from_name(channel_id, buf),
        Ok(ManagerOp::DebugOutput) => {},
        _ => {}
    }
}

pub fn new_manager_channel() -> ChannelId {
    dbg!(add_channel(None, read_callback))
}