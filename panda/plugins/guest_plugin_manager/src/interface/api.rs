use super::channels::add_channel;
use super::daemon_manager::load_binary;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice::from_raw_parts;

use super::channels::{publish_message_to_guest, ChannelCB, ChannelId};

#[repr(C)]
pub struct GuestPlugin {
    /// A unique name for the given plugin, provided as a non-null C string
    pub plugin_name: *const c_char,

    /// An optional path to load the guest agent binary. If null, a lookup will be
    /// performed to find the binary from the given name. If non-null must be a valid
    /// C string.
    pub guest_binary_path: *const c_char,

    /// A callback for when this guest plugin sends a message to the host
    pub msg_receive_cb: ChannelCB,
}

/// Adds a guest plugin to be loaded, returns a channel ID representing the
/// main channel of the to-be-loaded plugin. Writes to this channel ID before plugin
/// load will be queued and will thus be available when the plugin begins reading.
#[no_mangle]
pub extern "C" fn add_guest_plugin(plugin: GuestPlugin) -> ChannelId {
    let path_temp;
    let name = unsafe { CStr::from_ptr(plugin.plugin_name).to_string_lossy() };
    let binary_path = if plugin.guest_binary_path.is_null() {
        match crate::guest_plugin_path(&name) {
            Some(path) => {
                path_temp = path;
                path_temp.to_string_lossy()
            }
            None => panic!(
                "No guest plugin path was provided but plugin {0:?} \
                    could not be found, ensure {0:?} has been built.",
                name
            ),
        }
    } else {
        unsafe { CStr::from_ptr(plugin.guest_binary_path).to_string_lossy() }
    };
    load_binary(&binary_path);
    add_channel(Some(&name), plugin.msg_receive_cb)
}

/// Writes bytes from a buffer to the given channel ID, queuing them up for the next
/// guest plugin read. The buffer is copied into a new allocation before being added
/// to the queue, so the act of writing has no strict lifetime requirements.
#[no_mangle]
pub unsafe extern "C" fn channel_write(
    channel: ChannelId,
    buf: *const u8,
    buf_len: usize,
) {
    publish_message_to_guest(channel, from_raw_parts(buf, buf_len).to_vec())
}

/// Given the name of a plugin or channel, return the associated channel, panicking
/// if a channel of the given name cannot be found. Channel name should be passed
/// as a null-terminated string.
///
/// The provided string has no lifetime requirements, but must be a non-null pointer
/// to a valid C string.
#[no_mangle]
pub extern "C" fn get_channel_from_name(
    channel_name: *const c_char,
) -> ChannelId {
    let name = unsafe { CStr::from_ptr(channel_name).to_string_lossy() };
    super::channels::get_channel_from_name(&name).unwrap()
}
