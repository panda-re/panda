use once_cell::sync::Lazy;
use panda::{plugins::guest_plugin_manager::*, prelude::*};
use std::net::Ipv4Addr;
use std::sync::Mutex;

mod display;
mod forward_socket;
mod send_ext;
mod socket_list;

use send_ext::SendExt;
use socket_list::on_get_socket_list;

use tcp_shared_types::Request;

#[no_mangle]
pub extern "C" fn print_socket_info() {
    on_get_socket_list(display::print_table);
}

fn forward_socket(ip: Ipv4Addr, port: u16, host_port: u16) {
    forward_socket::forward(ip, port, host_port);
}

#[channel_recv]
fn main_channel_cb(_: u32, _: &[u8]) {
    // TODO: support for guest closing the socket
}

static MAIN_CHANNEL: Lazy<Mutex<Channel>> =
    Lazy::new(|| Mutex::new(load_guest_plugin("tcp_servers", main_channel_cb)));

fn send_request(req: Request) {
    MAIN_CHANNEL.lock().unwrap().send(req)
}

#[derive(PandaArgs)]
#[name = "print_tcp_servers"]
struct Args {
    print_sockets: bool,
    forward_port: u32,
    host_port: u32,
}

static ARGS: Lazy<Args> = Lazy::new(Args::from_panda_args);

#[panda::init]
fn init(_: &mut PluginHandle) {
    // TODO: switch to pretty_env_logger

    if ARGS.print_sockets {
        print_socket_info();
    }

    let forward_port = ARGS.forward_port as u16;
    let host_port = ARGS.host_port as u16;
    if forward_port != 0 {
        Lazy::force(&MAIN_CHANNEL);

        forward_socket(
            "0.0.0.0".parse().unwrap(),
            forward_port,
            match host_port {
                0 => forward_port,
                port => port,
            },
        );
    }
}
