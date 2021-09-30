use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice::from_raw_parts;

use super::plugin::{
    add_plugin, publish_message_to_guest, ChannelId, PluginCB
};

#[repr(C)]
pub struct GuestPlugin {
    pub name: *const c_char,
    pub elf_path: *const c_char,
    pub msg_receive_cb: PluginCB,
}

// returns channel ID
#[no_mangle]
pub extern "C" fn add_guest_plugin(plugin: GuestPlugin) -> ChannelId {
    let _elf_path = unsafe {
        CStr::from_ptr(plugin.elf_path)
            .to_string_lossy()
            .into_owned()
    };
    let name = unsafe {
        CStr::from_ptr(plugin.name)
            .to_string_lossy()
            .into_owned()
    };
    add_plugin(&name, plugin.msg_receive_cb)
}

#[no_mangle]
pub unsafe extern "C" fn channel_write(
    channel: ChannelId,
    out: *mut u8,
    out_len: usize,
) {
    publish_message_to_guest(channel, from_raw_parts(out, out_len).to_vec())
}

#[no_mangle]
pub extern "C" fn get_channel_from_name(channel_name: *const c_char) -> ChannelId {
    let name = unsafe {
        CStr::from_ptr(channel_name)
            .to_string_lossy()
            .into_owned()
    };
    super::plugin::get_channel_from_name(&name).unwrap()
}