use panda::sys;
use std::path::PathBuf;
use std::ffi::{CStr, CString};

pub fn plugin_path(plugin: &str) -> PathBuf {
    let plugin = CString::new(plugin).unwrap();
    let path = unsafe {
        CStr::from_ptr(sys::panda_plugin_path(plugin.as_ptr()))
    };
    
    PathBuf::from(path.to_string_lossy().into_owned())
}
