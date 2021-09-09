use std::net::{TcpListener, TcpStream};

pub fn wait_for_gdb() -> TcpStream {
    println!("Waiting for GDB connection on port 4444...");
    let listener = TcpListener::bind("127.0.0.1:4444")
        .unwrap()
        .incoming()
        .next()
        .unwrap()
        .unwrap();
    println!("GDB client connected");

    listener
}
