use once_cell::sync::Lazy;
use panda::{plugins::guest_plugin_manager::*, prelude::*};
use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::os::raw::c_char;
use std::sync::Mutex;

mod display;
mod forward_socket;
mod send_ext;
mod socket_list;

use send_ext::SendExt;

use tcp_shared_types::Request;

/// Request that a table of sockets be printed once guest execution resumes
#[no_mangle]
pub extern "C" fn print_socket_info() {
    socket_list::on_get_socket_list(display::print_table);
}

fn forward_socket_internal(ip: Ipv4Addr, port: u16, host_port: u16) {
    forward_socket::forward(ip, port, host_port, false);
}

/// Information about a given socket binding
#[repr(C)]
pub struct SocketInfo {
    pub ip: [u8; 4],
    pub pid: u64,
    pub port: u16,
    pub server: bool,
}

/// Provide a callback for receiving a socket list that will get called once the guest
/// resumes execution
#[no_mangle]
pub extern "C" fn on_get_socket_list(callback: extern "C" fn(*const SocketInfo, usize)) {
    socket_list::on_get_socket_list(move |socket_list| {
        let socket_list: Vec<SocketInfo> = socket_list
            .into_iter()
            .map(
                |tcp_shared_types::SocketInfo {
                     ip,
                     port,
                     pid,
                     server,
                 }| {
                    SocketInfo {
                        ip: ip.octets(),
                        port,
                        pid: pid.unwrap_or(u64::MAX),
                        server,
                    }
                },
            )
            .collect();

        callback(socket_list.as_ptr(), socket_list.len());

        drop(socket_list);
    })
}

/// Forward a socket from the guest, returning true if no issue is hit. Returns `false` if
/// the IP address fails to parse. A null IP address is treated as 0.0.0.0
///
/// Guest must resume execution for an unspecified amount of time before TCP traffic
/// will actually be processed.
#[no_mangle]
pub unsafe extern "C" fn forward_socket(
    ip: *const c_char,
    guest_port: u16,
    host_port: u16,
) -> bool {
    let ip = if ip.is_null() {
        "0.0.0.0".parse().unwrap()
    } else {
        let ip = CStr::from_ptr(ip);

        if let Ok(ip) = ip.to_str().unwrap().parse() {
            ip
        } else {
            return false;
        }
    };

    forward_socket_internal(ip, guest_port, host_port);

    true
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
#[name = "tcp_passthrough"]
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

        forward_socket_internal(
            "0.0.0.0".parse().unwrap(),
            forward_port,
            match host_port {
                0 => forward_port,
                port => port,
            },
        );
    }
}
