use fuser::{
    Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    ReplyWrite,
};
use libc::ENOENT;
use panda::prelude::*;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::marker::PhantomData;
use std::path::Path;

mod types;
use types::*;

struct HyperFilesystem {
    reply: Receiver<Reply>,
    request: Sender<types::Request>,

    lookup_cache: HashMap<(u64, OsString), LookupCacheEntry>,
}

macro_rules! on_reply {
    (
        $self:ident => $reply:ident (
            $type:ident { $($field:ident),* }

            => $reply_ty:ident { $(
                    $reply_field:ident
                ),*}

            => $code:block
        ) $(;)?
    ) => {
        println!("Before send");
        $self.request.send(Request::$type { $( $field ),* }).unwrap();
        println!("After send");
        match $self.reply.recv() {
            Ok(Reply::$reply_ty { $( $reply_field ),* }) => $code,
            Ok(Reply::Error(err)) => $reply.error(err),
            Ok(reply) => panic!("Invalid reply {:?}", reply),
            Err(_) => $reply.error(ENOENT),
        }
    };
}

macro_rules! send_reply {
    (
        $self:ident => $reply:ident.$method:ident (
            $type:ident { $($field:ident),* }

            => $reply_ty:ident { $(
                    $reply_field:ident $( . $reply_field_method:ident () )?
                ),*}
        ) $(;)?
    ) => {
        println!("{}(...)", stringify!($method));
        on_reply! {
            $self => $reply (
                $type { $($field),* }

                => $reply_ty { $(
                        $reply_field
                    ),*}

                => {
                    $(
                        let $reply_field = $reply_field $( .$reply_field_method () )?;
                    )*
                    $reply.$method( $($reply_field),* );
                }
            )
        }
    };
}

impl Filesystem for HyperFilesystem {
    fn lookup(&mut self, _req: &fuser::Request, parent_ino: u64, name: &OsStr, reply: ReplyEntry) {
        if let Some(LookupCacheEntry {
            ttl,
            attr,
            generation,
        }) = self.lookup_cache.remove(&(parent_ino, name.to_os_string()))
        {
            reply.entry(&ttl, &attr, generation);
            return;
        }

        let name = name.to_string_lossy().into_owned();
        send_reply! {
            self => reply.entry(
                Lookup { parent_ino, name } => Entry { ttl.borrow(), attr.borrow(), generation }
            );
        }
    }

    fn getattr(&mut self, _req: &fuser::Request, ino: u64, reply: ReplyAttr) {
        send_reply! {
            self => reply.attr(
                GetAttr { ino } => Attr { ttl.borrow(), attr.borrow() }
            );
        }
    }

    fn read(
        &mut self,
        _req: &fuser::Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        send_reply! {
            self => reply.data(
                Read { ino, offset, size, flags } => Data { data.as_ref() }
            );
        }
    }

    fn readdir(
        &mut self,
        _req: &fuser::Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let parent_ino = ino;
        on_reply! {
            self => reply(
                ReadDir { ino, offset }
                    => Directory { dir_entries }
                    => {
                        println!("Got to dir entry");
                        for DirEntry { ino, offset, kind, name, lookup_cache } in dir_entries {
                            println!("{:?}", name);
                            self.lookup_cache.insert((parent_ino, name.clone().into()), lookup_cache);
                            if reply.add(ino, offset, kind, name) {
                                break
                            }
                        }

                        reply.ok();
                    }
            );
        }
        println!("Finished reply");
    }

    fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        send_reply! {
            self => reply.opened(
                Open { ino, flags } => Opened { file_handle, flags }
            );
        }
    }

    fn write(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        write_flags: u32,
        flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let data = data.to_owned();
        send_reply! {
            self => reply.written(
                Write { ino, offset, data, write_flags, flags } => Written { size }
            );
        }
    }
}

struct Sender<T: Serialize>(ChannelId, PhantomData<T>);

impl<T: Serialize> Sender<T> {
    fn send(&self, val: T) -> Result<(), ()> {
        let bytes = bincode::serialize(&val).unwrap();

        let len = (bytes.len() as u32).to_le_bytes();
        GUEST_PLUGIN_MANAGER.channel_write(self.0, len.as_ptr(), 4);
        GUEST_PLUGIN_MANAGER.channel_write(self.0, bytes.as_ptr(), bytes.len());

        Ok(())
    }
}

struct Receiver<T: Deserialize<'static>>(ChannelId, PhantomData<T>);

impl Receiver<Reply> {
    fn recv(&self) -> Result<Reply, ()> {
        loop {
            match MESSAGE_QUEUE.pop() {
                Some(bytes) => break bincode::deserialize(&bytes).map_err(|_| ()),
                None => {
                    println!("Nothing recieved, sleeping...");
                    //std::thread::yield_now();
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
    }
}

//fn channel<T: Serialize + Deserialize<'static>>(channel: ChannelId) -> (Sender<T>, Receiver<T>) {
//    (Sender(channel, PhantomData), Receiver(channel, PhantomData))
//}

fn mount(channel: ChannelId) {
    let mountpoint = "/home/jmcleod/dev/panda/build/fuse_mount";
    let options = vec![
        MountOption::FSName("hello".to_string()),
        MountOption::AutoUnmount,
    ];

    let (request, reply) = (Sender(channel, PhantomData), Receiver(channel, PhantomData));

    //other_thread::start(incoming_request, response);

    fuser::mount2(
        HyperFilesystem {
            request,
            reply,
            lookup_cache: Default::default(),
        },
        mountpoint,
        &options,
    )
    .unwrap();
    println!("Unmounted");
}

use crossbeam_queue::SegQueue;
use panda::plugins::guest_plugin_manager::*; //GUEST_PLUGIN_MANAGER;

static MESSAGE_QUEUE: SegQueue<Vec<u8>> = SegQueue::new();

extern "C" fn message_recv(_channel: u32, ptr: *const u8, len: usize) {
    unsafe {
        println!("message_recv in hyperfuse");
        let bytes = std::slice::from_raw_parts(ptr, len);
        MESSAGE_QUEUE.push(bytes.to_owned());
    }
}

#[cfg(feature = "x86_64")]
const PATH: &str = "/home/jmcleod/dev/igloo-internal/pie_idea/guest_code/target/x86_64-unknown-linux-musl/release/guest_daemon";

#[cfg(feature = "arm")]
const PATH: &str = "/home/jmcleod/dev/igloo-internal/pie_idea/guest_code/target/arm-unknown-linux-musleabi/release/guest_daemon";

#[cfg(feature = "i386")]
const PATH: &str = "/home/jmcleod/dev/igloo-internal/pie_idea/guest_code/target/i686-unknown-linux-musl/release/guest_daemon";

#[cfg(feature = "x86_64")]
const GUEST_PLUGIN_PATH: &str = "/home/jmcleod/dev/igloo-internal/pie_idea/guest_code/target/x86_64-unknown-linux-musl/release/hyperfuse_guest";

#[cfg(feature = "arm")]
const GUEST_PLUGIN_PATH: &str = "/home/jmcleod/dev/igloo-internal/pie_idea/guest_code/target/arm-unknown-linux-musleabi/release/hyperfuse_guest";

#[cfg(feature = "i386")]
const GUEST_PLUGIN_PATH: &str = "/home/jmcleod/dev/igloo-internal/pie_idea/guest_code/target/i686-unknown-linux-musl/release/hyperfuse_guest";

use std::{ffi::CStr, os::raw::c_char, path::PathBuf};
fn guest_plugin_path(name: &str) -> Option<PathBuf> {
    extern "C" {
        fn panda_guest_plugin_path(name: *const c_char) -> *mut c_char;
    }

    let name = CString::new(name).ok()?;
    let path_result = unsafe { panda_guest_plugin_path(name.as_ptr()) };

    if path_result.is_null() {
        None
    } else {
        let path = unsafe { CStr::from_ptr(path_result) };
        let path = path.to_str().ok().map(PathBuf::from);

        unsafe {
            panda::sys::free(path_result as _);
        }

        path
    }
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    pretty_env_logger::init_custom_env("HYPERFUSE_LOG");

    //let guest_plugin_path = guest_plugin_path("hyperfuse");

    let plugin_name = CString::new("linjector".as_bytes()).unwrap();
    let plugin_arg = CString::new(format!("guest_binary={}", PATH).as_bytes()).unwrap();
    unsafe {
        let path = panda::sys::panda_plugin_path(plugin_name.as_ptr());
        panda::sys::panda_add_arg(plugin_name.as_ptr(), plugin_arg.as_ptr());
        panda::sys::panda_load_plugin(path, plugin_name.as_ptr());
    }
    println!("after load_plugin in hyperfuse");

    GUEST_PLUGIN_MANAGER.ensure_init();
    let channel = GUEST_PLUGIN_MANAGER.add_guest_plugin(GuestPlugin::new(
        "hyperfuse".into(),
        Path::new(GUEST_PLUGIN_PATH),
        message_recv,
    ));
    println!("hyperfuse established channel with fd {}", channel);

    std::thread::spawn(move || {
        println!("new hyperfuse thread");
        mount(channel);
    });
    println!("returning after new thread hyperfuse");

    true
}
