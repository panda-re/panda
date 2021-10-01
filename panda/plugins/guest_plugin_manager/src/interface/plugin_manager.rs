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

fn get_channel_from_name(buffer: Vec<u8>){
    let plugin_name = String::from_utf8_lossy(&buffer).into_owned();
    if let Some(channel_id) =  super::channels::get_channel_from_name(&plugin_name){
        let buf = u32::to_le_bytes(channel_id);
        publish_message_to_guest(channel_id,buf.to_vec());
    }
}

extern "C" fn read_callback(_channel_id: ChannelId, ptr: *const u8, len: usize){
    let mut buf = unsafe{from_raw_parts(ptr, len).to_vec()};
    const OPSIZE: usize = size_of::<OperationID>();
    let mut operation: [u8;OPSIZE] = [0;4];
    operation.copy_from_slice(&buf[..OPSIZE]);
    let op_num = OperationID::from_le_bytes(operation);
    buf.drain(0..OPSIZE);
    match ManagerOp::try_from(op_num as usize) {
        Ok(ManagerOp::GetChannelFromName) => get_channel_from_name(buf),
        Ok(ManagerOp::DebugOutput) => {},
        _ => {}
    }
}

pub fn new_manager_channel() -> ChannelId {
    add_channel(None, read_callback)
}