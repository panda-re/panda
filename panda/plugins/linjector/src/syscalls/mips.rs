use panda::prelude::*;

pub(crate) const GETPID: target_ulong = 4020;
pub(crate) const MMAP: target_ulong = 4090;
pub(crate) const WRITE: target_ulong = 4004;
pub(crate) const EXECVE: target_ulong = 4011;
pub(crate) const MEMFD_CREATE: target_ulong = 4354;
pub(crate) const CHDIR: target_ulong = 4012;
pub(crate) const SETSID: target_ulong = 4066;
pub(crate) const OPEN: target_ulong = 4005;
pub(crate) const CLOSE: target_ulong = 4006;

pub(crate) const PROT_READ: target_ulong = 1;
pub(crate) const PROT_WRITE: target_ulong = 2;

pub(crate) const MAP_SHARED: target_ulong = 0x1;
pub(crate) const MAP_ANON: target_ulong = 0x800;
