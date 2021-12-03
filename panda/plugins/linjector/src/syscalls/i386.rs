use panda::prelude::*;

pub(crate) const GETPID: target_ulong = 20;
pub(crate) const MMAP: target_ulong = 90;
pub(crate) const WRITE: target_ulong = 4;
pub(crate) const EXECVE: target_ulong = 11;
pub(crate) const MEMFD_CREATE: target_ulong = 356;
pub(crate) const CHDIR: target_ulong = 12;
pub(crate) const SETSID: target_ulong = 66;
pub(crate) const OPEN: target_ulong = 5;
pub(crate) const CLOSE: target_ulong = 6;

pub(crate) const PROT_READ: target_ulong = 1;
pub(crate) const PROT_WRITE: target_ulong = 2;

pub(crate) const MAP_SHARED: target_ulong = 0x1;
pub(crate) const MAP_ANON: target_ulong = 0x20;
