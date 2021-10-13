#![feature(asm)]

mod hypercall;
use std::process::Command;

use hypercall::{HyperCall, HcCmd};

/// Read a line of input from the hypervisor
fn read_line() -> String {
    let mut buf = vec![0u8; 1024];

    let len = loop {
        let ret = HyperCall::from_mut_buf(HcCmd::Read, &mut buf).call() as isize;

        if ret > 0 {
            break ret
        } else {
            std::thread::yield_now();
        }
    };

    buf.truncate(len as usize);

    String::from_utf8(buf).unwrap()
}

/// Write a buffer or string across the hypervisor
fn write(output: impl AsRef<[u8]>) {
    HyperCall::from_buf(HcCmd::Write, output.as_ref()).call();
}

fn main() {
    HyperCall::new(HcCmd::Start).call();

    loop {
        let input = read_line();

        let args: Vec<&str> = input.trim().split_whitespace().collect();

        if let [program, args @ ..] = &args[..] {
            match Command::new(program).args(args).output() {
                Ok(output) => {
                    write(&output.stdout);
                    write("[CMD_FINISHED]");
                }
                Err(_) => break,
            }
        }
    }

    HyperCall::new(HcCmd::Stop).call();
}
