//use std::io::{stdout, Write, BufReader};
use std::fs::File;
use std::io::Write;
//use std::env;
use curl::easy::Easy;

pub fn download_symbol_table(file: &str, kernel: &str) -> bool {
    let mut f = File::create(file).expect("Could not create file");
    let mut buf = Vec::new();
    let mut easy = Easy::new();
    let url = "https://panda.re/volatility3_profiles/".to_owned() + kernel;
    println!("Grabbing file from: {}", url);
    easy.url(&url).unwrap();
    {
        let mut transfer = easy.transfer();
        transfer
            .write_function(|data| {
                buf.extend_from_slice(data);
                Ok(data.len())
            })
            .unwrap();
        transfer.perform().unwrap();
    }
    if buf.len() > 0 {
        f.write_all(&buf);
        println!("OK");
        true
    } else {
        println!("FAIL: could not read {} from server", kernel);
        false
    }
}
