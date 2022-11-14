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
    let mut temp_buf = vec![0u8; 4096 as _];
    temp_buf.fill(1);

    let mut payload = vec![];
    loop {
        match reader.read_packet(&mut temp_buf) {
            0 => break,
            _ => {
                payload.write_all(&temp_buf).unwrap();
            }
        }
    }

    if payload.is_empty() {
        return None;
    }

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
