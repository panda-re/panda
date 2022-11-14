use memfd::MemfdOptions;
use std::{
    fs,
    io::Write,
    os::unix::{fs::OpenOptionsExt, prelude::AsRawFd},
    process::Command,
};

pub(crate) fn load_plugin(payload: Vec<u8>) {
    let (path, mut file) = if let Ok(plugin_file) = MemfdOptions::new().create("pluginfd") {
        let fd = plugin_file.as_raw_fd();

        (format!("/proc/self/fd/{}", fd), plugin_file.into_file())
    } else {
        match fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o777)
            .custom_flags(libc::O_CLOEXEC)
            .open("/tmp/plugin_file")
        {
            Ok(file) => (String::from("/tmp/plugin_file"), file),
            Err(err) => {
                eprintln!("Failed to write to /tmp");
                panic!("{:?}", err);
            }
        }
    };

    file.write_all(&payload).unwrap();
    let _ = file.flush();
    let _ = file.sync_all();

    let mut file = Some(file);

    if path.starts_with("/tmp") {
        drop(file.take());
    }

    eprintln!("Running guest plugin...");
    Command::new(path)
        .spawn()
        .expect("Failed to run guest plugin");
}
