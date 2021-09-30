use crossbeam_queue::SegQueue;
use panda::prelude::*;
use parking_lot::RwLock;
use std::collections::HashMap;
use lazy_static::lazy_static;
use std::sync::atomic::{AtomicU32, Ordering};

pub type ChannelId = u32;
pub type PluginCB = extern "C" fn(*const u8, usize);

static NEXT_PLUGIN_NUMBER: AtomicU32 = AtomicU32::new(0);

lazy_static!{
static ref PLUGINS: RwLock<HashMap<ChannelId, Plugin>> =
    RwLock::new(HashMap::new());
}

struct Plugin {
    name: String,
    channel_ids: Vec<ChannelId>,
    msg_receive_cb: PluginCB,
    MessageQueue: SegQueue<Vec<u8>>,
}

pub fn add_plugin(p_name: &str, cb: PluginCB) -> ChannelId {
    let mut plugins = PLUGINS.write();
    let channel_id = NEXT_PLUGIN_NUMBER.load(Ordering::SeqCst);
    if plugins.insert(channel_id, Plugin{
        name: p_name.to_owned(),
        channel_ids: Vec::new(),
        msg_receive_cb: cb,
        MessageQueue: SegQueue::new() 
    }).is_none() {
        panic!("We've somehow added a duplicate ID");
    }
    NEXT_PLUGIN_NUMBER.fetch_add(1, Ordering::SeqCst);
    channel_id
}

pub fn poll_plugin_message(channel_id: ChannelId) -> Option<Vec<u8>> {
    let pm = PLUGINS.read();
    if let Some(plugin) = pm.get(&channel_id){
        if let Some(msg) = plugin.MessageQueue.pop() {
            Some(msg)
        } else {
            None
        }
    } else {
        panic!("poll_plugin_message for plugin with incorrect ID");
    }
}

pub fn publish_message_from_guest(channel_id: ChannelId, msg: Vec<u8>) {
    let pm = PLUGINS.read();
    if let Some(plugin) = pm.get(&channel_id){
        let buf_ptr = msg.as_ptr();
        (plugin.msg_receive_cb)(buf_ptr, msg.len())
    }
}

pub fn publish_message_to_guest(channel_id: ChannelId, msg: Vec<u8>) {
    let pm = PLUGINS.read();
    if let Some(plugin) = pm.get(&channel_id){
        plugin.MessageQueue.push(msg)
    }
}

pub fn get_channel_from_name(p_name: &str) -> Option<ChannelId>{
    let pm = PLUGINS.read();
    for (_,value) in &*pm{
        if value.name == p_name {
            return Some(value.channel_ids[0]);
        }
    }
    None
}