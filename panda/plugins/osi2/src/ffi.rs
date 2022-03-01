use panda::prelude::*;

#[no_mangle]
pub extern "C" fn kaslr_offset(cpu: &mut CPUState) -> target_ptr_t {
    crate::kaslr_offset(cpu)
}
