use panda::prelude::*;

pub(crate) const GETPID: target_ulong = 0xAC;
pub(crate) const MMAP: target_ulong = 222;
pub(crate) const WRITE: target_ulong = 64;
pub(crate) const EXECVE: target_ulong = 221;
pub(crate) const MEMFD_CREATE: target_ulong = 279;
pub(crate) const CHDIR: target_ulong = 49;
pub(crate) const SETSID: target_ulong = 157;
pub(crate) const OPEN: target_ulong = 0x400;
pub(crate) const CLOSE: target_ulong = 0x39;

pub(crate) const PROT_READ: target_ulong = 1;
pub(crate) const PROT_WRITE: target_ulong = 2;

pub(crate) const MAP_SHARED: target_ulong = 1;
pub(crate) const MAP_ANON: target_ulong = 0x20;
