use once_cell::sync::OnceCell;
use panda::plugins::guest_plugin_manager::*;
use panda::prelude::*;

use std::ffi::CString;
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Mutex;

#[cfg(feature = "x86_64")]
const PATH: &str = "/home/jmcleod/dev/igloo-internal/pie_idea/guest_code/target/x86_64-unknown-linux-musl/release/guest_daemon";

#[cfg(feature = "arm")]
const PATH: &str = "/home/jmcleod/dev/igloo-internal/pie_idea/guest_code/target/arm-unknown-linux-musleabi/release/guest_daemon";

#[cfg(feature = "i386")]
const PATH: &str = "/home/jmcleod/dev/igloo-internal/pie_idea/guest_code/target/i686-unknown-linux-musl/release/guest_daemon";

#[cfg(feature = "x86_64")]
const GUEST_PLUGIN_PATH: &str = "/home/jmcleod/dev/igloo-internal/pie_idea/guest_code/target/x86_64-unknown-linux-musl/release/guest_shell";

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

struct Channel(ChannelId);

impl Write for Channel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        GUEST_PLUGIN_MANAGER.channel_write(self.0, buf.as_ptr(), buf.len());

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    let plugin_name = CString::new("linjector".as_bytes()).unwrap();
    let plugin_arg = CString::new(format!("guest_binary={}", PATH).as_bytes()).unwrap();
    unsafe {
        let path = panda::sys::panda_plugin_path(plugin_name.as_ptr());
        panda::sys::panda_add_arg(plugin_name.as_ptr(), plugin_arg.as_ptr());
        panda::sys::panda_load_plugin(path, plugin_name.as_ptr());
    }
    println!("after load_plugin in guest_shell");

    GUEST_PLUGIN_MANAGER.ensure_init();
    let channel = GUEST_PLUGIN_MANAGER.add_guest_plugin(GuestPlugin::new(
        "guest_shell".into(),
        Path::new(GUEST_PLUGIN_PATH),
        message_recv,
    ));
    println!("hyperfuse established channel with fd {}", channel);

    let socket = UnixListener::bind(&ARGS.socket_path).unwrap();
    let socket = socket.accept().unwrap().0;

    let socket_out = socket.try_clone().unwrap();
    STDOUT.set(Mutex::new(socket_out)).unwrap();

    std::thread::spawn(move || {
        std::io::copy(&mut { socket }, &mut Channel(channel)).unwrap();
        println!("Closed");
    });

    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}

