use super::plugin::{add_plugin};
use std::mem::size_of;
use std::convert::TryFrom;

type OperationID = u32;

enum ManagerOp {
    GetChannelFromName = 0,
    GetNewChannel = 1,
    DebugOutput = 2,
}

impl TryFrom<usize> for ManagerOp {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, ()> {
        match value {
            0 => Ok(ManagerOp::GetChannelFromName),
            1 => Ok(ManagerOp::GetNewChannel),
            2 => Ok(ManagerOp::DebugOutput),
            _ => Err(()),
        }
    }
}

fn get_channel_from_name(buffer: Vec<u8>){
    let plugin_name = String::from_utf8_lossy(&buffer).into_owned();
    if let Some(channel_id) =  super::plugin::get_channel_from_name(&plugin_name){
        // publish_message_to_guest();
    }
}

fn read_callback(mut buf: Vec<u8>){
    const OPSIZE: usize = size_of::<OperationID>();
    let mut operation: [u8;OPSIZE] = [0;4];
    operation.copy_from_slice(&buf[..OPSIZE]);
    let OpNum = OperationID::from_le_bytes(operation);
    buf.drain(0..OPSIZE);
    match ManagerOp::try_from(OpNum as usize) {
        Ok(ManagerOp::GetChannelFromName) => get_channel_from_name(buf),
        Ok(ManagerOp::GetNewChannel) => {},
        Ok(ManagerOp::DebugOutput) => {},
        _ => {}
    }
}