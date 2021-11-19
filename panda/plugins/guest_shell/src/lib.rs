use panda::prelude::*;
use panda::plugin_import;
use panda::plugins::guest_plugin_manager::*;

use std::ffi::CString;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::{Mutex, Arc};
use std::thread;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};


use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};

use crossbeam_queue::SegQueue;

static MESSAGE_QUEUE: SegQueue<Vec<u8>> = SegQueue::new();

#[derive(Copy, Clone)]
struct Sender<T: Serialize>(ChannelId, PhantomData<T>);

impl<T: Serialize> Sender<T> {
    fn send(&self, val: T) -> Result<(), ()> {
        let bytes = bincode::serialize(&val).unwrap();

        let len = (bytes.len() as u32).to_le_bytes();
        GUEST_PLUGIN_MANAGER.channel_write(self.0, len.as_ptr(), 4);
        GUEST_PLUGIN_MANAGER.channel_write(self.0, bytes.as_ptr(), bytes.len());

        Ok(())
    }
}
#[derive(Copy, Clone)]
struct Receiver<T: Deserialize<'static>>(ChannelId, PhantomData<T>);

impl Receiver<String> {
    fn recv(&self) -> Result<String, ()> {
        loop {
            match MESSAGE_QUEUE.pop() {
                Some(bytes) => break bincode::deserialize(&bytes).map_err(|_| ()),
                None => std::thread::yield_now(),
            }
        }
    }
}

fn handle_client(mut stream: TcpStream, channel: u32) {
    let mut data = [0 as u8; 1000]; // using 50 byte buffer
    let (request, reply) = (Sender::<String>(channel, PhantomData), Receiver::<String>(channel, PhantomData));
    while match stream.read(&mut data) {
        Ok(size) => {
            // echo everything!
            request.send(String::from_utf8_lossy(&data[0..size]).into_owned()).unwrap();
            stream.write(&reply.recv().unwrap().as_bytes());
            true
        },
        Err(_) => {
            println!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
}

fn serve(channel: u32) {
    let listener = TcpListener::bind("0.0.0.0:1337").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 1337");
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| {
                    // connection succeeded
                    handle_client(stream, channel)
                });
            }
            Err(e) => {
                println!("Error: {}", e);
                /* connection failed */
            }
        }
    }
    // close the socket server
    drop(listener);
}

extern "C" fn message_recv(_channel: u32, ptr: *const u8, len: usize) {
    unsafe {
        // println!("message_recv in hyperfuse");
        let bytes = std::slice::from_raw_parts(ptr, len);
        MESSAGE_QUEUE.push(bytes.to_owned());
    }
}



#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    GUEST_PLUGIN_MANAGER.ensure_init();
    let channel = GUEST_PLUGIN_MANAGER.add_guest_plugin(GuestPlugin::new(
        "guest_shell".into(),
        Path::new("/home/luke/workspace/igloo/pie_idea/guest_code/target/release/rusty_shell"),
        message_recv,
    ));
    println!("guest_plugin established channel with fd {}", channel);
    println!("after load_plugin in guest_plugin");

    println!("Initialized!");
    thread::spawn(move || {serve(channel)});
    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}