use panda::os::name;
use std::fs::File;
use std::io::Write;
use curl::easy::Easy;

pub fn get_symtab_name() -> String {
    let os_name = name().unwrap();
    let n: Vec<&str> = os_name.split(":").collect();
    let s1: Vec<&str> = n[0].split("-").collect();
    let s2: Vec<&str> = n[1].split("-").collect();
    s1[2].to_owned() + ":" + s2[0] + "-" + s2[1] + "-" + s2[2] + ":" + s1[1]
}

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
        f.write_all(&buf).expect("Failed to write to file");
        println!("OK");
        true
    } else {
        println!("FAIL: could not read {} from server", kernel);
        false
    }
}
