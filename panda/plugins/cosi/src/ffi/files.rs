use std::ffi::{c_char, CString};

use crate::structs::{CosiFile, CosiFiles};
use panda::prelude::*;

/// Get the information for files available to the current process.
///
/// Must be freed using `free_cosi_files`.
#[no_mangle]
pub extern "C" fn get_current_files(cpu: &mut CPUState) -> Option<Box<CosiFiles>> {
    CosiFiles::get_current_files(cpu).map(Box::new)
}

/// Get the number of files in a given CosiFiles
#[no_mangle]
pub extern "C" fn cosi_files_len(files: &CosiFiles) -> usize {
    files.files.len()
}

/// From a given CosiFiles get a specific file by index if it exists
#[no_mangle]
pub extern "C" fn cosi_files_get(files: &CosiFiles, index: usize) -> Option<&CosiFile> {
    files.files.get(index)
}

/// Get a reference to a file from the file descriptor if it exists
#[no_mangle]
pub extern "C" fn cosi_files_file_from_fd(files: &CosiFiles, fd: u32) -> Option<&CosiFile> {
    files.file_from_fd(fd)
}

/// frees a CosiFiles struct
#[no_mangle]
pub extern "C" fn free_cosi_files(files: Option<Box<CosiFiles>>) {
    drop(files);
}

/// Get the name of a given CosiFile
///
/// Must be freed using `free_cosi_str`
#[no_mangle]
pub extern "C" fn cosi_file_name(file: &CosiFile) -> *mut c_char {
    CString::new((*file.name).clone())
        .ok()
        .map(CString::into_raw)
        .unwrap_or_else(std::ptr::null_mut)
}
