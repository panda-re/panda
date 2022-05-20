use dashmap::DashMap;
use once_cell::sync::Lazy;
use panda::plugins::guest_plugin_manager::*;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::thread;

use tcp_shared_types::Request;

static CONNECTIONS: Lazy<DashMap<u32, Mutex<TcpStream>>> = Lazy::new(DashMap::new);

#[channel_recv]
fn incoming_tcp(channel_id: u32, data: &[u8]) {
    eprintln!("[{channel_id}] TCP data: len={}", data.len());
    if let Some(channel) = CONNECTIONS.get(&channel_id) {
        channel.lock().unwrap().write_all(data).unwrap();
        eprintln!("[{channel_id}] TCP data written");
    }
}

pub fn forward(ip: Ipv4Addr, guest_port: u16, host_port: u16) {
    thread::spawn(move || {
        let listener =
            TcpListener::bind(("localhost", host_port)).expect("Could not bind to host port");
        eprintln!("Listening on localhost:{}...", host_port);

        for stream in listener.incoming() {
            match stream {
                Ok(mut outgoing_tcp_stream) => {
                    println!(
                        "Incoming connection for port {} (guest port {})",
                        host_port, guest_port
                    );
                    let mut incoming_channel = Channel::new(incoming_tcp);

                    CONNECTIONS.insert(
                        incoming_channel.id(),
                        Mutex::new(outgoing_tcp_stream.try_clone().unwrap()),
                    );

                    let channel_id = incoming_channel.id();

                    thread::spawn(move || {
                        if let Err(err) =
                            std::io::copy(&mut outgoing_tcp_stream, &mut incoming_channel)
                        {
                            eprintln!("Connection Closed for host port {}: {:?}", host_port, err);
                        }
                    });

                    crate::send_request(Request::ForwardConnection {
                        ip,
                        port: guest_port,
                        channel_id,
                    });
                }
                Err(_) => {
                    eprintln!("Failed to accept connection to localhost:{}", host_port);
                }
            }
        }
    });
}
