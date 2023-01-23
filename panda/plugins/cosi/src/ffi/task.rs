//use crate::{get_osiproc_info, get_osithread_info, CosiProc, OsiThread};
use crate::structs::{CosiFiles, CosiMappings, CosiModule, CosiProc, CosiThread};

use panda::{prelude::*, sys::get_cpu};
use std::{ffi::CString, os::raw::c_char};

/// Gets a reference to the current process which can be freed with `free_process`
#[no_mangle]
pub extern "C" fn get_current_cosiproc(cpu: &mut CPUState) -> Option<Box<CosiProc>> {
    CosiProc::get_current_cosiproc(cpu).map(Box::new)
}

/// Free an allocated reference to a process
#[no_mangle]
pub extern "C" fn free_process(proc: Option<Box<CosiProc>>) {
    drop(proc);
}

/// Get the name of a process from a reference to it as a C string. Must be freed using
/// the `free_cosi_str` function.
#[no_mangle]
pub extern "C" fn cosi_proc_name(proc: &CosiProc) -> *mut c_char {
    CString::new((*proc.name).clone())
        .ok()
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Gets the files accessible to the given process
///
/// Must be freed via `free_cosi_files`
#[no_mangle]
pub extern "C" fn cosi_proc_files(proc: &CosiProc) -> Option<Box<CosiFiles>> {
    CosiFiles::new(unsafe { &mut *get_cpu() }, proc.task.files).map(Box::new)
}

/// Get the current thread, must be freed using `free_thread`
#[no_mangle]
pub extern "C" fn get_current_cosithread(cpu: &mut CPUState) -> Option<Box<CosiThread>> {
    CosiThread::get_current_cosithread(cpu).map(Box::new)
}

/// Free an allocated reference to a thread
#[no_mangle]
pub extern "C" fn free_thread(thread: Option<Box<CosiThread>>) {
    drop(thread);
}

/// Gets a list of the current processes. Must be freed with `cosi_free_proc_list`
#[no_mangle]
pub extern "C" fn cosi_get_proc_list(cpu: &mut CPUState) -> Option<Box<Vec<CosiProc>>> {
    crate::get_process_list(cpu).map(Box::new)
}

/// Get a reference to an individual process in a cosi proc list
#[no_mangle]
pub extern "C" fn cosi_proc_list_get(list: &Vec<CosiProc>, index: usize) -> Option<&CosiProc> {
    list.get(index)
}

/// Get the length of a cosi proc list
#[no_mangle]
pub extern "C" fn cosi_proc_list_len(list: &Vec<CosiProc>) -> usize {
    list.len()
}

/// Free a cosi proc list
#[no_mangle]
pub extern "C" fn cosi_free_proc_list(_list: Option<Box<Vec<CosiProc>>>) {}

/// Gets a list of the children of a given process. Must be freed using `cosi_free_proc_list`
#[no_mangle]
pub extern "C" fn cosi_proc_children(
    cpu: &mut CPUState,
    proc: &CosiProc,
) -> Option<Box<Vec<CosiProc>>> {
    crate::get_process_children(cpu, proc).map(Box::new)
}

/// Get a list of the memory mappings for the given process
#[no_mangle]
pub extern "C" fn cosi_proc_get_mappings(
    cpu: &mut CPUState,
    proc: &CosiProc,
) -> Option<Box<CosiMappings>> {
    proc.get_mappings(cpu).map(Box::new)
}

/// Get the module behind the index of a CosiMappings
#[no_mangle]
pub extern "C" fn cosi_mappings_get(list: &CosiMappings, index: usize) -> Option<&CosiModule> {
    list.modules.get(index)
}

/// Get the number of modules in the CosiMappings
#[no_mangle]
pub extern "C" fn cosi_mappings_len(list: &CosiMappings) -> usize {
    list.modules.len()
}

/// Free the CosiMappings
#[no_mangle]
pub extern "C" fn cosi_free_mappings(_mappings: Option<Box<CosiMappings>>) {}

/// Get the name of a module from a reference to it as a C string. Must be freed using
/// the `free_cosi_str` function.
#[no_mangle]
pub extern "C" fn cosi_module_name(module: &CosiModule) -> *mut c_char {
    CString::new((*module.name).clone())
        .ok()
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Get the file path of a module from a reference to it as a C string. Must be freed using
/// the `free_cosi_str` function.
#[no_mangle]
pub extern "C" fn cosi_module_file(module: &CosiModule) -> *mut c_char {
    CString::new((*module.file).clone())
        .ok()
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}
