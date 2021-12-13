use super::channels::add_channel;
use super::daemon_manager::load_binary;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice::from_raw_parts;

use super::channels::{publish_message_to_guest, ChannelCB, ChannelId};

#[repr(C)]
pub struct GuestPlugin {
    pub plugin_name: *const c_char,
    pub guest_binary_path: *const c_char,
    pub msg_receive_cb: ChannelCB,
}

// returns channel ID
#[no_mangle]
pub extern "C" fn add_guest_plugin(plugin: GuestPlugin) -> ChannelId {
    let name = unsafe { CStr::from_ptr(plugin.plugin_name).to_string_lossy() };
    let binary_path = if plugin.guest_binary_path.is_null() {
        match crate::guest_plugin_path(&name) {
            Some(path) => path.to_string_lossy().into_owned(),
            None => panic!(
                "No guest plugin path was provided but plugin {0:?} \
                    could not be found, ensure {0:?} has been built.",
                name
            ),
        }
    } else {
        unsafe {
            CStr::from_ptr(plugin.guest_binary_path)
                .to_string_lossy()
                .into_owned()
        }
    };
    load_binary(&binary_path);
    add_channel(Some(&name), plugin.msg_receive_cb)
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
pub extern "C" fn get_channel_from_name(
    channel_name: *const c_char,
) -> ChannelId {
    let name =
        unsafe { CStr::from_ptr(channel_name).to_string_lossy().into_owned() };
    super::channels::get_channel_from_name(&name).unwrap()
}

