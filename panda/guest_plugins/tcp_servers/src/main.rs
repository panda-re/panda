use panda_channels::{Channel, RawChannel};
use proc_net_tcp::socket_info;

use std::collections::HashMap;
use std::mem::transmute;
use std::net::{Ipv4Addr, TcpStream};

use tcp_shared_types::{Request, SocketInfo};

mod allow_cancel;
use allow_cancel::{AllowCancel, CancelSignal};

fn recv_request(mut channel: &mut Channel) -> Request {
    loop {
        if let Ok(request) = bincode::deserialize_from(&mut channel) {
            break request;
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn build_socket_list_packet() -> Vec<u8> {
    let sockets = socket_info()
        .into_iter()
        .filter_map(|socket| {
            socket.ok().map(|socket| SocketInfo {
                ip: *socket.local_address.ip(),
                port: socket.local_address.port(),
                pid: socket.owning_pid,
                server: socket.is_listening(),
            })
        })
        .collect::<Vec<_>>();

    bincode::serialize(&sockets).unwrap()
}

fn forward_connection(ip: Ipv4Addr, port: u16, channel_id: u32) -> CancelSignal {
    let raw = unsafe { transmute(channel_id) };

    let mut write_channel = AllowCancel::new(Channel::from_raw(raw));
    let mut read_channel = write_channel.clone();

    let cancel_signal = write_channel.cancel_signal();

    let write_socket = TcpStream::connect((ip, port)).unwrap();
    let read_socket = write_socket.try_clone().unwrap();

    let mut read_socket = AllowCancel::new(read_socket).with_signal(cancel_signal.clone());
    let mut write_socket = AllowCancel::new(write_socket).with_signal(cancel_signal.clone());

    std::thread::spawn(move || {
        let _ = std::io::copy(&mut read_channel, &mut write_socket);
    });

    std::thread::spawn(move || {
        let _ = std::io::copy(&mut read_socket, &mut write_channel);
    });

    cancel_signal
}

fn main() {
    let mut channel = Channel::main("tcp_servers").unwrap();
    let mut active_sockets = HashMap::new();

    loop {
        let request = recv_request(&mut channel);

        // debug??
        //let _ = Channel::main(&format!("Request: {:?}", request));
        //panda_channels::debug_output(&);
        match request {
            Request::GetSocketList { channel_id } => {
                eprintln!("Getting socket list...");
                let socket_list_channel: RawChannel = unsafe { transmute(channel_id) };

                socket_list_channel.write_packet(&build_socket_list_packet());
            }

            Request::ForwardConnection {
                ip,
                port,
                channel_id,
            } => {
                let cancel_signal = forward_connection(ip, port, channel_id);

                active_sockets.insert(channel_id, cancel_signal);
            }

            Request::CloseSocket { channel_id } => {
                if let Some(socket) = active_sockets.remove(&channel_id) {
                    socket.cancel();
                }
            }
        }
    }
}
