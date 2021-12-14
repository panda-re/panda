use panda::{plugins::guest_plugin_manager::*, prelude::*};
use parking_lot::{const_mutex, Mutex};
use std::{
    io::{self, Write},
    os::unix::net::{UnixListener, UnixStream},
};

static STDOUT: Mutex<Option<UnixStream>> = const_mutex(None);

// Copy all messages from the guest to the unix socket
#[channel_recv]
fn message_recv(_: u32, data: &[u8]) {
    STDOUT.lock().as_mut().unwrap().write_all(data).ok();
}

#[derive(PandaArgs)]
#[name = "guest_shell"]
struct Args {
    #[arg(default = "/tmp/guest_shell.sock")]
    socket_path: String,
}

fn get_split_socket(path: &str) -> io::Result<(UnixStream, UnixStream)> {
    let (socket, _) = UnixListener::bind(path)?.accept()?;
    Ok((socket.try_clone()?, socket))
}

#[panda::init]
fn init(_: &mut PluginHandle) {
    let args = Args::from_panda_args();
    let mut guest_channel = load_guest_plugin("guest_shell", message_recv);

    let (stdout, mut stdin) = get_split_socket(&args.socket_path).unwrap();
    STDOUT.lock().replace(stdout);

    std::thread::spawn(move || {
        // Copy stdin from unix socket to guest
        io::copy(&mut stdin, &mut guest_channel).unwrap();
    });
}
