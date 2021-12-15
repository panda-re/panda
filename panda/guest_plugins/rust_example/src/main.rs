use panda_channels::Channel;
use std::io::{Read, Write};

fn main() {
    // This print won't be visible outside of the serial log
    println!("Hello, world!");

    // Get the main channel for our plugin by name
    let mut channel = Channel::main("rust_example").unwrap();

    // Write some text to the channel using the standard std::io::Write interface
    channel.write_all(b"Hello rust_example channel").unwrap();

    // Or use formatting utilties to do so
    writeln!(&mut channel, "today's lucky number is: {}", 3).unwrap();

    // The channel can also be read from
    let mut buf = [0; 4];
    channel.read_exact(&mut buf).unwrap();

    let num = u32::from_le_bytes(buf);
    writeln!(&mut channel, "the number you sent the guest was: {}", num).unwrap();
}
