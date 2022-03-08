use panda::prelude::*;
use panda::sys::get_cpu;
use std::{ffi::CStr, ffi::CString, os::raw::c_char};
use volatility_profile::*;

use crate::symbol_table;

#[no_mangle]
pub extern "C" fn kaslr_offset(cpu: &mut CPUState) -> target_ptr_t {
    crate::kaslr_offset(cpu)
}

#[no_mangle]
pub unsafe extern "C" fn enum_from_name(name: *const c_char) -> Option<&'static VolatilityEnum> {
    let name = CStr::from_ptr(name).to_str().ok()?;

    symbol_table().enum_from_name(name)
}

#[no_mangle]
pub unsafe extern "C" fn base_type_from_name(
    name: *const c_char,
) -> Option<&'static VolatilityBaseType> {
    let name = CStr::from_ptr(name).to_str().ok()?;

    symbol_table().base_type_from_name(name)
}

#[no_mangle]
pub unsafe extern "C" fn symbol_from_name(
    name: *const c_char,
) -> Option<&'static VolatilitySymbol> {
    let name = CStr::from_ptr(name).to_str().ok()?;

    symbol_table().symbol_from_name(name)
}

#[no_mangle]
pub unsafe extern "C" fn type_from_name(name: *const c_char) -> Option<&'static VolatilityStruct> {
    let name = CStr::from_ptr(name).to_str().ok()?;

    symbol_table().type_from_name(name)
}

#[no_mangle]
pub extern "C" fn addr_of_symbol(symbol: &VolatilitySymbol) -> target_ptr_t {
    (symbol.address as target_ptr_t) + kaslr_offset(unsafe { &mut *get_cpu() })
}

#[no_mangle]
pub extern "C" fn value_of_symbol(symbol: &VolatilitySymbol) -> target_ptr_t {
    symbol.address as target_ptr_t
}

/// Gets the name of the symbol as a C-compatible string, or null if the symbol cannot
/// be found. Must be freed via `free_osi2_str`.
#[no_mangle]
pub extern "C" fn name_of_symbol(symbol: &VolatilitySymbol) -> *mut c_char {
    let name = symbol_table()
        .symbols
        .iter()
        .find_map(|(key, val)| (val == symbol).then(move || key));

    name.cloned()
        .map(|name| CString::new(name).ok())
        .flatten()
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn symbol_value_from_name(name: *const c_char) -> target_ptr_t {
    if let Some(sym) = symbol_from_name(name) {
        sym.address as target_ptr_t
    } else {
        panic!("Invalid symbol name, could not retrieve volatility symbol")
    }
}

#[no_mangle]
pub unsafe extern "C" fn symbol_addr_from_name(name: *const c_char) -> target_ptr_t {
    symbol_value_from_name(name) + kaslr_offset(&mut *get_cpu())
}

#[no_mangle]
pub unsafe extern "C" fn offset_of_field(
    vol_struct: &VolatilityStruct,
    name: *const c_char,
) -> target_long {
    let name = CStr::from_ptr(name)
        .to_str()
        .ok()
        .expect("Field name is invalid UTF-8, field could not be retrieved");

    vol_struct.fields[name].offset as target_long
}

#[no_mangle]
pub unsafe extern "C" fn size_of_struct(vol_struct: &VolatilityStruct) -> target_ulong {
    vol_struct.size as target_ulong
}

#[no_mangle]
pub extern "C" fn current_cpu_offset(cpu: &mut CPUState) -> target_ulong {
    crate::current_cpu_offset(cpu)
}

#[no_mangle]
pub unsafe extern "C" fn free_osi2_str(string: *mut c_char) {
    if !string.is_null() {
        drop(CString::from_raw(string));
    }
}
