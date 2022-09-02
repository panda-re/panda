use panda::sys;

#[cfg(any(feature = "x86_64", feature = "i386"))]
pub(crate) static EXCEPTIONS: &'static [i32] = &[sys::EXCP0D_GPF as i32];

#[cfg(feature = "arm")]
pub static EXCEPTIONS: &'static [i32] = &[sys::EXCP_DATA_ABORT as i32, 
                                      sys::EXCP_PREFETCH_ABORT as i32];
#[cfg(feature = "mips")]
pub static EXCEPTIONS: &'static [i32] = &[sys::EXCP_TLBF, 
                                    sys::EXCP_TLBS,
                                    sys::EXCP_AdEL, 
                                    sys::EXCP_AdES,
                                    sys::EXCP_TLBL];
#[cfg(not(any(
    feature = "x86_64",
    feature = "i386",
    feature = "arm",
    feature = "mips"
)))]
pub static EXCEPTIONS: &'static [i32] = &[];