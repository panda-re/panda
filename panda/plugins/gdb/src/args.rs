use panda::prelude::*;

#[derive(PandaArgs)]
#[name = "gdb"]
pub struct Args {
    #[cfg(not(any(feature = "ppc", feature = "mips", feature = "mipsel", feature = "i386")))]
    #[arg(default = "invalid")]
    pub file: String,

    #[arg(default = 0)]
    pub base: u64,

    pub ghidra_elf: bool,
    pub on_entry: bool,
    pub on_start: bool,
    pub absolute_addrs: bool,
}

impl Args {
    /// Get the base address to relocate the binary to
    pub fn base_addr(&self) -> target_ptr_t {
        if self.ghidra_elf {
            0x100_000
        } else {
            self.base as target_ptr_t
        }
    }

    /// Initialize the arguments. This will cause lazy_static to run the constructor.
    pub fn init(&self) {}
}

lazy_static::lazy_static!{
    pub static ref ARGS: Args = Args::from_panda_args();
}
