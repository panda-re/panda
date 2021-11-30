use panda::prelude::*;
use panda::syscall_injection::{syscall, syscall_no_return};

// i386
// const MMAP2: target_ulong = 192;
// const WRITE: target_ulong = 4;
// const FORK: target_ulong = 2;
// const EXECVE: target_ulong = 11;
// const MEMFD_CREATE: target_ulong = 356;

// x86_64
const GETPID: target_ulong = 39;
const MMAP: target_ulong = 9;
const WRITE: target_ulong = 1;
const EXECVE: target_ulong = 59;
const MEMFD_CREATE: target_ulong = 319;
const CHDIR: target_ulong = 80;
const SETSID: target_ulong = 112;

const NULL: target_ulong = 0;
const NEG_1: target_ulong = u32::MAX as target_ulong;
pub const PAGE_SIZE: target_ulong = 1024;

const PROT_READ: target_ulong = 4;
const PROT_WRITE: target_ulong = 2;
const MAP_ANON: target_ulong = 0x20;
const MAP_SHARED: target_ulong = 0x2;

pub async fn do_mmap() -> target_ulong {
    syscall(
        MMAP,
        (
            0u64,
            PAGE_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANON,
            NEG_1,
            NULL,
        ),
    )
    .await
}

const MFD_CLOEXEC: target_ulong = 1;

pub async fn do_memfd_create(mmap_addr: target_ulong) -> target_ulong {
    // we use the mmap_addr for the name because we've zeroed it
    // so it will be a '\0' literal name
    syscall(MEMFD_CREATE, (mmap_addr, MFD_CLOEXEC)).await
}

pub async fn do_write(
    mem_fd: target_ulong,
    mmap_addr: target_ulong,
    len: target_ulong,
) -> target_long {
    syscall(WRITE, (mem_fd, mmap_addr, len)).await as target_long
}

pub async fn do_execve(
    path: target_ulong,
    argv: target_ulong,
    envp: target_ulong,
) -> target_ulong {
    syscall_no_return(EXECVE, (path, argv, envp)).await
}

pub async fn getpid() -> target_ulong {
    syscall(GETPID, ()).await
}

pub async fn chdir(addr: target_ulong) -> target_ulong {
    syscall(CHDIR, (addr,)).await
}

pub async fn setsid() -> target_ulong {
    syscall(SETSID, ()).await
}
