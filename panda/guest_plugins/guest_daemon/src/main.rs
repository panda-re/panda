use panda_channels::{get_main_raw_channel, hypercall, RawChannel};
use std::{io::Write, thread, time::Duration};

mod loader;

enum PacketKind {
    LoadPlugin = 0,
}

struct Packet {
    kind: PacketKind,
    payload: Vec<u8>,
}

fn read_packet(reader: &mut RawChannel) -> Option<Packet> {
    //let plugin_file = MemfdOptions::new()
    //    .close_on_exec(true)
    //    .create("pluginfd")
    //    .unwrap();
    //let fd = plugin_file.as_raw_fd();
    //let mut plugin_file = plugin_file.into_file();
    let mut temp_buf = vec![0u8; 4096 as _];
    temp_buf.fill(1);

    let mut payload = vec![];
    loop {
        // println!("top of loop");
        // let mut header = [0u8; 8];
        match reader.read_packet(&mut temp_buf) {
            0 => break,
            _ => {
                payload.write_all(&temp_buf).unwrap();
                //plugin_file.write_all(&payload).unwrap();
            }
        }
    }

    if payload.is_empty() {
        return None;
    }

    println!("got to bottom. executing");

    //println!("fd: {}", fd);
    //let fds = std::fs::read_dir("/proc/self/fd")
    //    .unwrap()
    //    .map(|entry| entry.unwrap().path())
    //    .collect::<Vec<_>>();
    //dbg!(&fds);
    //println!("path: /proc/self/fd/{}", fd);

    //dbg!(Path::new(&format!("/proc/self/fd/{}", fd)).exists());
    //Command::new(format!("/proc/self/fd/{}", fd))
    //    .spawn()
    //    .unwrap();

    Some(Packet {
        kind: PacketKind::LoadPlugin,
        payload,
    })
}

fn main() {
    eprintln!("at main.rs in guest_daemon");

    eprintln!("Daemonizing...");
    daemonize_me::Daemon::new()
        .start()
        .expect("Failed to daemonize");
    eprintln!("Finished daemonizing");

    while !hypercall::start() {
        thread::yield_now();
    }

    let mut channel = get_main_raw_channel("guest_daemon").unwrap();

    loop {
        match read_packet(&mut channel) {
            Some(Packet {
                kind: PacketKind::LoadPlugin,
                payload,
            }) => loader::load_plugin(payload),
            None => {
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
