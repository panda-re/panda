use super::channels::{add_channel, publish_message_to_guest, ChannelId};
use once_cell::sync::OnceCell;
use std::path::Path;

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
            _ => None,
        }
    }
}

extern "C" fn read_callback(
    _channel_id: ChannelId,
    _ptr: *const u8,
    _len: usize,
) {
}

pub fn load_binary(binary_path: &str) {
    if Path::new(binary_path).is_file() {
        if let Ok(binary) = std::fs::read(binary_path) {
            for chunk in binary.chunks(4096) {
                let cd = CHANNEL_DESC.get().unwrap();
                publish_message_to_guest(*cd, chunk.to_owned());
            }
        } else {
            panic!("Failed to read binary at {}", binary_path);
        }
    } else {
        panic!("failed to check for file {}", binary_path);
    }
}

pub fn init() {
    CHANNEL_DESC
        .set(add_channel(Some(CHANNEL_NAME), read_callback))
        .unwrap();
}
