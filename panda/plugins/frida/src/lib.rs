use panda::{plugins::guest_plugin_manager::*, prelude::*};
use parking_lot::{const_mutex, Mutex};
use std::io::Write;
use std::net::{TcpListener, TcpStream};

#[channel_recv]
fn message_recv(_: u32, data: &[u8]) {
    if let Some(socket) = SOCKET.lock().as_mut() {
        socket.write_all(data).unwrap();
    }
}

static SOCKET: Mutex<Option<TcpStream>> = const_mutex(None);

#[panda::init]
fn init(_: &mut PluginHandle) {
    pretty_env_logger::init_custom_env("FRIDA_LOG");
    let mut channel = load_guest_plugin("frida_server", message_recv);

    std::thread::spawn(move || {
        let server = TcpListener::bind("localhost:27042").unwrap();

        for socket in server.incoming() {
            let mut socket = socket.unwrap();
            log::debug!("Socket connected");
            SOCKET.lock().replace(socket.try_clone().unwrap());
            log::debug!("Forwarding socket...");
            std::io::copy(&mut socket, &mut channel).unwrap();
            log::debug!("Socket disconnected");
            SOCKET.lock().take();
        }
    });
}
