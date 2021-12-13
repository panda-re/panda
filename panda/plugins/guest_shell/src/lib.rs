use once_cell::sync::OnceCell;
use panda::{plugins::guest_plugin_manager::*, prelude::*};

use std::{
    io::{self, Write},
    os::unix::net::{UnixListener, UnixStream},
    sync::Mutex,
    thread,
};

static STDOUT: OnceCell<Mutex<UnixStream>> = OnceCell::new();

// Copy all messages from the guest to the unix socket
extern "C" fn message_recv(_: u32, data: *const u8, size: usize) {
    let data = unsafe { std::slice::from_raw_parts(data, size) };
    let mut stdout = STDOUT.get().unwrap().lock().unwrap();
    let _ = stdout.write_all(data);
}

#[derive(PandaArgs)]
#[name = "guest_shell"]
struct Args {
    #[arg(default = "/tmp/guest_shell.sock")]
    socket_path: String,
}

lazy_static::lazy_static! {
    static ref ARGS: Args = Args::from_panda_args();
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    let mut channel = load_guest_plugin("guest_shell", message_recv);

    let socket = UnixListener::bind(&ARGS.socket_path).unwrap();
    let mut socket = socket.accept().unwrap().0;

    STDOUT.set(Mutex::new(socket.try_clone().unwrap())).unwrap();

    thread::spawn(move || {
        // Copy stdin from unix socket to guest
        io::copy(&mut socket, &mut channel).unwrap();
    });

    true
}
