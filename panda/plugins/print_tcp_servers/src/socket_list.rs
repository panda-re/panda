use crate::send_request;
use once_cell::sync::Lazy;
use panda::plugins::guest_plugin_manager::*;
use std::sync::Mutex;

use tcp_shared_types::{Request, SocketInfo};

type SocketListCb = Box<dyn FnOnce(Vec<SocketInfo>) + Send + 'static>;

static SOCKET_LIST_CHANNEL: Lazy<Channel> = Lazy::new(|| Channel::new(recv_socket_info));

static SOCKET_INFO_CALLBACK: Lazy<Mutex<Option<SocketListCb>>> = Lazy::new(|| Mutex::new(None));

#[channel_recv]
fn recv_socket_info(_: u32, data: &[u8]) {
    if let Some(callback) = take_callback() {
        callback(bincode::deserialize(data).unwrap());
    }
}

fn take_callback() -> Option<SocketListCb> {
    SOCKET_INFO_CALLBACK.lock().unwrap().take()
}

fn set_callback(cb: SocketListCb) {
    SOCKET_INFO_CALLBACK.lock().unwrap().replace(cb);
}

pub(crate) fn on_get_socket_list<CallbackFn>(new_callback: CallbackFn)
where
    CallbackFn: FnOnce(Vec<SocketInfo>) + Send + 'static,
{
    let callback = if let Some(existing_callback) = take_callback() {
        // pending callback, chain them
        let replacement_callback = move |sockets: Vec<SocketInfo>| {
            existing_callback(sockets.clone());
            new_callback(sockets);
        };

        Box::new(replacement_callback) as SocketListCb
    } else {
        // no callback pending, queue a request for listing
        send_request(Request::GetSocketList {
            channel_id: SOCKET_LIST_CHANNEL.id(),
        });

        Box::new(new_callback) as SocketListCb
    };

    set_callback(callback);
}
