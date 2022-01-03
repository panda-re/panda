use cached::{stores::TimedCache, Cached};
use fuser::{
    Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    ReplyWrite,
};
use libc::ENOENT;
use panda::prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::borrow::Borrow;
use std::ffi::{OsStr, OsString};
use std::marker::PhantomData;

mod types;
use types::*;

struct HyperFilesystem {
    reply: Receiver<Reply>,
    request: Sender<types::Request>,

    link_target_cache: TimedCache<u64, Vec<u8>>,
    lookup_cache: TimedCache<(u64, OsString), LookupCacheEntry>,
}

macro_rules! on_reply {
    (
        $self:ident => $reply:ident (
            $type:ident { $($field:ident),* }

            => $reply_ty:ident $({ $(
                    $reply_field:ident
                ),*})?

                // tuple type
                $(( $(
                    $reply_field_tuple:ident
                ),*))?

            => $code:block
        ) $(;)?
    ) => {
        $self.request.send(Request::$type { $( $field ),* }).unwrap();

        match $self.reply.recv() {
            Ok(Reply::$reply_ty
               // struct variant
               $({ $( $reply_field ),* })?
               // tuple variant
               $(( $( $reply_field_tuple ),* ))?
            ) => $code,
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

            => $reply_ty:ident
                // struct type
                $({$(
                    $reply_field:ident $( . $reply_field_method:ident () )?
                ),*})?
                // tuple type
                $(($(
                    $reply_field_tup:ident $( . $reply_field_method_tup:ident () )?
                ),*))?
        ) $(;)?
    ) => {
        println!("{}(...)", stringify!($method));
        on_reply! {
            $self => $reply (
                $type { $($field),* }

                => $reply_ty
                    // struct type
                    $({ $(
                        $reply_field
                    ),*})?
                    // tuple type
                    $(( $(
                        $reply_field_tup
                    ),*))?

                => {
                    // struct type
                    $(
                        $(
                            let $reply_field = $reply_field $( .$reply_field_method () )?;
                        )*
                        $reply.$method( $($reply_field),* );
                    )?
                    $(
                        $(
                            let $reply_field_tup = $reply_field_tup $( .$reply_field_method_tup () )?;
                        )*
                        $reply.$method( $($reply_field_tup),* );
                    )?
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
        }) = self
            .lookup_cache
            .cache_get(&(parent_ino, name.to_os_string()))
        {
            reply.entry(ttl, attr, *generation);
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
                Read { ino, offset, size, flags } => Data(data.as_ref())
            );
        }
    }

    fn readlink(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: ReplyData) {
        if let Some(data) = self.link_target_cache.cache_get(&ino) {
            reply.data(&data);
            return;
        }

        send_reply! {
            self => reply.data(
                ReadLink { ino } => Data(data.as_ref())
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
                        for DirEntry { ino, offset, kind, name, link_target, lookup_cache } in dir_entries {
                            if let Some(LinkTarget { path, parent_ino, target_name, target_lookup }) = link_target {
                                self.link_target_cache.cache_set(ino, path);
                                self.lookup_cache.cache_set((parent_ino, target_name.into()), target_lookup);
                            }
                            self.lookup_cache.cache_set((parent_ino, name.clone().into()), lookup_cache);
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

struct Sender<T: Serialize>(Channel, PhantomData<T>);

impl<T: Serialize> Sender<T> {
    fn send(&mut self, val: T) -> Result<(), ()> {
        bincode::serialize_into(&mut self.0, &val).map_err(|_| ())
    }
}

struct Receiver<T: DeserializeOwned>(PhantomData<T>);

impl<T: DeserializeOwned> Receiver<T> {
    fn recv(&self) -> Result<Reply, ()> {
        loop {
            match MESSAGE_QUEUE.pop() {
                Some(bytes) => break bincode::deserialize(&bytes).map_err(|_| ()),
                None => {
                    println!("Nothing recieved, sleeping...");
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
    }
}

fn split_channel<InType, OutType>(channel: Channel) -> (Sender<OutType>, Receiver<InType>)
where
    InType: DeserializeOwned,
    OutType: Serialize,
{
    (Sender(channel, PhantomData), Receiver(PhantomData))
}

fn mount(channel: Channel) {
    // TODO: make this programatically configurable via a plugin-to-plugin API
    let mountpoint = std::env::var("HYPERFUSE_MOUNT")
        .expect("HYPERFUSE_MOUNT is not set but is required by 'hyperfuse' plugin");

    let options = vec![
        MountOption::FSName("hello".to_string()),
        MountOption::AutoUnmount,
    ];

    let (request, reply) = split_channel(channel);

    fuser::mount2(
        HyperFilesystem {
            request,
            reply,
            link_target_cache: TimedCache::with_lifespan(1),
            lookup_cache: TimedCache::with_lifespan(1),
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

#[channel_recv]
fn message_recv(_: u32, bytes: Vec<u8>) {
    MESSAGE_QUEUE.push(bytes.to_owned());
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    pretty_env_logger::init_custom_env("HYPERFUSE_LOG");

    let channel = load_guest_plugin("hyperfuse_guest", message_recv);

    std::thread::spawn(move || mount(channel));

    true
}
