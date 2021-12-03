use panda::prelude::*;
use panda::syscall_injection::{syscall, syscall_no_return};

// i386
// const MMAP2: target_ulong = 192;
// const WRITE: target_ulong = 4;
// const FORK: target_ulong = 2;
// const EXECVE: target_ulong = 11;
// const MEMFD_CREATE: target_ulong = 356;

#[cfg(feature = "x86_64")]
#[path = "syscalls/x86_64.rs"]
mod sys_nums;

#[cfg(feature = "i386")]
#[path = "syscalls/i386.rs"]
mod sys_nums;

#[cfg(feature = "arm")]
#[path = "syscalls/arm.rs"]
mod sys_nums;

use sys_nums::*;

const NULL: target_ulong = 0;
const NEG_1: target_ulong = u32::MAX as target_ulong;
pub const PAGE_SIZE: target_ulong = 1024;

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

pub const O_CREAT: i32 = 0o100;
pub const O_RDWR: i32 = 0o002;
pub const O_CLOEXEC: i32 = 0o2000000;
pub const O_TRUNC: i32 = 0o1000;

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

pub async fn close(fd: target_ulong) -> target_ulong {
    syscall(CLOSE, (fd,)).await
}

pub async fn open(
    path_ptr: target_ulong,
    flags: i32,
    mode: target_ulong,
) -> target_ulong {
    syscall(OPEN, (path_ptr, flags as target_long as target_ulong, mode)).await
}
