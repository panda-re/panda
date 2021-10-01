use libc::c_int;
use std::time::Duration;

use fuser::{FileAttr, FileType};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Request {
    Lookup {
        parent_ino: u64,
        name: String,
    },
    GetAttr {
        ino: u64,
    },
    Read {
        ino: u64,
        offset: i64,
        size: u32,
        flags: i32,
    },
    ReadDir {
        ino: u64,
        offset: i64,
    },
    Open {
        ino: u64,
        flags: i32,
    },
    Write {
        ino: u64,
        offset: i64,
        data: Vec<u8>,
        write_flags: u32,
        flags: i32,
    },
    Create {
        parent: u64,
        name: String,
        mode: u32,
        umask: u32,
        flags: u32,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Reply {
    Entry {
        ttl: Duration,
        attr: FileAttr,
        generation: u64,
    },
    Attr {
        ttl: Duration,
        attr: FileAttr,
    },
    Data {
        data: Vec<u8>,
    },
    Directory {
        dir_entries: Vec<DirEntry>,
    },
    Opened {
        file_handle: u64,
        flags: u32,
    },
    Written {
        size: u32,
    },
    Created {
        ttl: Duration,
        attr: FileAttr,
        generation: u64,
        fh: u64,
        flags: u32,
    },
    Error(c_int),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DirEntry {
    pub ino: u64,
    pub offset: i64,
    pub kind: FileType,
    pub name: String,
}
