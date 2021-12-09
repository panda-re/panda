use channels::Channel;
use std::io::Write;

fn main() {
    // This print won't be visible outside of the serial log
    println!("Hello, world!");

    // Get the main channel for our plugin by name
    let mut channel = Channel::main("rust_example").unwrap();

    // Write some text to the channel using the standard std::io::Write interface
    channel.write_all(b"Hello rust_example channel").unwrap();

    // Or use formatting utilties to do so
    writeln!(&mut channel, "today's lucky number is: {}", 3).unwrap();
}
