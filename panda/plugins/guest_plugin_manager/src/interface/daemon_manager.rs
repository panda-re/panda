use super::channels::{ChannelId, add_channel, publish_message_to_guest};
use std::fs::read_to_string;
use std::path::Path;
use once_cell::sync::OnceCell;

const CHANNEL_NAME: &str = "guest_daemon";
static CHANNEL_DESC: OnceCell<ChannelId> = OnceCell::new();

enum PacketKind {
    LoadPlugin = 0,
}

#[allow(dead_code)]
struct Packet {
    kind: PacketKind,
    payload: Vec<u8>,
}

#[allow(dead_code)]
impl PacketKind {
    fn from(kind: u32) -> Option<Self> {
        match kind {
            0 => Some(Self::LoadPlugin),
            _ => None
        }
    }
}

extern "C" fn read_callback(_channel_id: ChannelId, _ptr: *const u8, _len: usize){}

pub fn load_binary(binary_path: &str){
    if Path::new(binary_path).is_file() {
        if let Ok(binary) = read_to_string(binary_path) {
            let payload_size = binary.len();
            let mut buf = u32::to_le_bytes(PacketKind::LoadPlugin as u32).to_vec();
            buf.extend(u32::to_le_bytes(payload_size as u32).to_vec());
            let cd = CHANNEL_DESC.get().unwrap();
            publish_message_to_guest(*cd, buf);
            publish_message_to_guest(*cd, binary.as_bytes().to_vec());

        }else{
            panic!("Failed to read binary at {}", binary_path);
        }
    }else{
        panic!("failed to check for file {}", binary_path);
    }
}

pub fn init(){
    CHANNEL_DESC.set(add_channel(Some(CHANNEL_NAME), read_callback)).unwrap();
}