use panda::prelude::*;

pub(crate) const GETPID: target_ulong = 39;
pub(crate) const MMAP: target_ulong = 9;
pub(crate) const WRITE: target_ulong = 1;
pub(crate) const EXECVE: target_ulong = 59;
pub(crate) const MEMFD_CREATE: target_ulong = 319;
pub(crate) const CHDIR: target_ulong = 80;
pub(crate) const SETSID: target_ulong = 112;
pub(crate) const OPEN: target_ulong = 2;
pub(crate) const CLOSE: target_ulong = 3;

pub(crate) const PROT_READ: target_ulong = 1;
pub(crate) const PROT_WRITE: target_ulong = 2;

pub(crate) const MAP_SHARED: target_ulong = 0x1;
pub(crate) const MAP_ANON: target_ulong = 0x20;
