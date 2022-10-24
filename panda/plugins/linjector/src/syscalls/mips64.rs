use panda::prelude::*;

pub(crate) const GETPID: target_ulong = 5038;
pub(crate) const MMAP: target_ulong = 5009;
pub(crate) const WRITE: target_ulong = 5001;
pub(crate) const EXECVE: target_ulong = 5057;
pub(crate) const MEMFD_CREATE: target_ulong = 5314;
pub(crate) const CHDIR: target_ulong = 5078;
pub(crate) const SETSID: target_ulong = 5110;
pub(crate) const OPEN: target_ulong = 5002;
pub(crate) const CLOSE: target_ulong = 5003;

pub(crate) const PROT_READ: target_ulong = 1;
pub(crate) const PROT_WRITE: target_ulong = 2;

pub(crate) const MAP_SHARED: target_ulong = 1;
pub(crate) const MAP_ANON: target_ulong = 0x800;
