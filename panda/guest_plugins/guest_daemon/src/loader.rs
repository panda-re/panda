use memfd::MemfdOptions;
use std::{io::Write, os::unix::prelude::AsRawFd, process::Command};

pub(crate) fn load_plugin(payload: Vec<u8>) {
    let plugin_file = MemfdOptions::new().create("pluginfd").unwrap();
    let fd = plugin_file.as_raw_fd();
    let mut plugin_file = plugin_file.into_file();

    plugin_file.write_all(&payload).unwrap();

    Command::new(format!("/proc/self/fd/{}", fd))
        .spawn()
        .unwrap();
}
