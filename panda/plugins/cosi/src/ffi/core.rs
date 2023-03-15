use panda::prelude::*;
use panda::sys::get_cpu;
use std::{ffi::CStr, ffi::CString, os::raw::c_char};
use volatility_profile::*;

use crate::symbol_table;

/// Get the KASLR offset of the system, calculating and caching it if it has not already
/// been found. For systems without KASLR this will be 0.
#[no_mangle]
pub extern "C" fn kaslr_offset(cpu: &mut CPUState) -> target_ptr_t {
    crate::kaslr_offset(cpu)
}

/// Get a reference to an opaque object for accessing information about a given enum
/// based on the volatility symbols currently loaded by OSI2
#[no_mangle]
pub unsafe extern "C" fn enum_from_name(name: *const c_char) -> Option<&'static VolatilityEnum> {
    let name = CStr::from_ptr(name).to_str().ok()?;

    symbol_table().enum_from_name(name)
}

/// Get a reference to an opaque object for accessing information about a given base type
/// from the volatility symbols currently loaded by OSI2
#[no_mangle]
pub unsafe extern "C" fn base_type_from_name(
    name: *const c_char,
) -> Option<&'static VolatilityBaseType> {
    let name = CStr::from_ptr(name).to_str().ok()?;

    symbol_table().base_type_from_name(name)
}

/// Get a reference to an opaque object for accessing information about a given symbol
/// present in the volatility symbols currently loaded by OSI2
#[no_mangle]
pub unsafe extern "C" fn symbol_from_name(
    name: *const c_char,
) -> Option<&'static VolatilitySymbol> {
    let name = CStr::from_ptr(name).to_str().ok()?;

    symbol_table().symbol_from_name(name)
}

/// Get a reference to an opaque object for accessing information about a given type
/// present in the volatility symbols currently loaded by OSI2
#[no_mangle]
pub unsafe extern "C" fn type_from_name(name: *const c_char) -> Option<&'static VolatilityStruct> {
    let name = CStr::from_ptr(name).to_str().ok()?;

    symbol_table().type_from_name(name)
}

/// Get the address from a given symbol, accounting for KASLR
#[no_mangle]
pub extern "C" fn addr_of_symbol(symbol: &VolatilitySymbol) -> target_ptr_t {
    (symbol.address as target_ptr_t) + kaslr_offset(unsafe { &mut *get_cpu() })
}

/// Get the raw value from a given symbol (unlike `addr_of_symbol` this does not account
/// for KASLR)
#[no_mangle]
pub extern "C" fn value_of_symbol(symbol: &VolatilitySymbol) -> target_ptr_t {
    symbol.address as target_ptr_t
}

/// Gets the name of the symbol as a C-compatible string, or null if the symbol cannot
/// be found. Must be freed via `free_cosi_str`.
#[no_mangle]
pub extern "C" fn name_of_symbol(symbol: &VolatilitySymbol) -> *mut c_char {
    let name = symbol_table()
        .symbols
        .iter()
        .find_map(|(key, val)| (val == symbol).then_some(key));

    name.cloned()
        .and_then(|name| CString::new(name).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Gets the name of the struct as a C-compatible string, or null if the symbol cannot
/// be found. Must be freed via `free_cosi_str`.
#[no_mangle]
pub extern "C" fn name_of_struct(ty: &VolatilityStruct) -> *mut c_char {
    let name = symbol_table()
        .user_types
        .iter()
        .find_map(|(key, val)| (val == ty).then_some(key));

    name.cloned()
        .and_then(|name| CString::new(name).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Gets the name of the nth field in alphabetical order, returning null past the end
#[no_mangle]
pub extern "C" fn get_field_by_index(ty: &VolatilityStruct, index: usize) -> *mut c_char {
    ty.fields
        .keys()
        .nth(index)
        .and_then(|name| CString::new(name.clone()).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Gets the name of the enum as a C-compatible string, or null if the symbol cannot
/// be found. Must be freed via `free_cosi_str`.
#[no_mangle]
pub extern "C" fn name_of_enum(ty: &VolatilityEnum) -> *mut c_char {
    let name = symbol_table()
        .enums
        .iter()
        .find_map(|(key, val)| (val == ty).then_some(key));

    name.cloned()
        .and_then(|name| CString::new(name).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Gets the name of the base type as a C-compatible string, or null if the symbol cannot
/// be found. Must be freed via `free_cosi_str`.
#[no_mangle]
pub extern "C" fn name_of_base_type(ty: &VolatilityBaseType) -> *mut c_char {
    let name = symbol_table()
        .base_types
        .iter()
        .find_map(|(key, val)| (val == ty).then_some(key));

    name.cloned()
        .and_then(|name| CString::new(name).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Gets the size of the base type in bytes
#[no_mangle]
pub extern "C" fn size_of_base_type(ty: &VolatilityBaseType) -> target_ptr_t {
    ty.size as target_ptr_t
}

/// Check if an integral base type is signed
#[no_mangle]
pub extern "C" fn is_base_type_signed(ty: &VolatilityBaseType) -> bool {
    ty.signed
}

/// Get the raw value of a symbol, not accounting for aslr
#[no_mangle]
pub unsafe extern "C" fn symbol_value_from_name(name: *const c_char) -> target_ptr_t {
    if let Some(sym) = symbol_from_name(name) {
        sym.address as target_ptr_t
    } else {
        panic!("Invalid symbol name, could not retrieve volatility symbol for '{}'", CStr::from_ptr(name).to_str().expect("could not covert to str"));
    }
}

/// Given a symbol name, get the address of the symbol accounting for kaslr
#[no_mangle]
pub unsafe extern "C" fn symbol_addr_from_name(name: *const c_char) -> target_ptr_t {
    symbol_value_from_name(name) + kaslr_offset(&mut *get_cpu())
}

/// Get the offset of a given field within a struct in bytes
#[no_mangle]
pub unsafe extern "C" fn offset_of_field(
    vol_struct: &VolatilityStruct,
    name: *const c_char,
) -> target_long {
    let name = CStr::from_ptr(name)
        .to_str()
        .expect("Field name is invalid UTF-8, field could not be retrieved");

    //println!("Reading field: {}", name);
    vol_struct.fields[name].offset as target_long
}

/// Get the name of a given field as a string
///
/// Must be freed using `free_cosi_str`
#[no_mangle]
pub unsafe extern "C" fn type_of_field(
    vol_struct: &VolatilityStruct,
    name: *const c_char,
) -> *mut c_char {
    let name = CStr::from_ptr(name)
        .to_str()
        .expect("Field name is invalid UTF-8, field could not be retrieved");

    vol_struct
        .fields
        .get(name)
        .and_then(|field| field.type_val.as_ref())
        .map(ToString::to_string)
        .map(CString::new)
        .and_then(Result::ok)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Get the size in bytes of a specific struct type
#[no_mangle]
pub unsafe extern "C" fn size_of_struct(vol_struct: &VolatilityStruct) -> target_ulong {
    vol_struct.size as target_ulong
}

/// Get the CPU offset for the currently executing CPU
#[no_mangle]
pub extern "C" fn current_cpu_offset(cpu: &mut CPUState) -> target_ulong {
    crate::current_cpu_offset(cpu)
}

/// Free a string allocated by cosi
#[no_mangle]
pub unsafe extern "C" fn free_cosi_str(string: *mut c_char) {
    if !string.is_null() {
        drop(CString::from_raw(string));
    }
}
