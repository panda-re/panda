use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub type Pid = u64;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SocketInfo {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub pid: Option<Pid>,
    pub server: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Request {
    /// Request a Vec<SocketInfo> be sent to a given channel
    GetSocketList { channel_id: u32 },

    /// Connect to the given TCP port at the provided IP and forward the connection
    /// over the given channel
    ForwardConnection {
        ip: Ipv4Addr,
        port: u16,
        channel_id: u32,
    },

    /// Closes a socket so the TCP server knows the connection ended
    CloseSocket { channel_id: u32 },
}
