use once_cell::sync::OnceCell;
use panda::plugins::guest_plugin_manager::*;
use panda::prelude::*;

use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Mutex;

static STDOUT: OnceCell<Mutex<UnixStream>> = OnceCell::new();

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

    let socket_out = socket.try_clone().unwrap();
    STDOUT.set(Mutex::new(socket_out)).unwrap();

    std::thread::spawn(move || {
        std::io::copy(&mut socket, &mut channel).unwrap();
        println!("Closed");
    });

    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}
