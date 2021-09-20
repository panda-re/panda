use panda::prelude::*;
use panda::plugins::osi::OSI;

use std::ffi::CStr;
use gdbstub::outputln;

pub(crate) fn print(cpu: &mut CPUState) {
    let mut proc = OSI.get_current_process(cpu);
    let mappings = OSI.get_mappings(cpu, &mut *proc);

    println!("Memory map:");
    for mapping in mappings.iter() {
        let start = mapping.base;
        let end = mapping.base + mapping.size;

        let name = if !mapping.file.is_null() {
            // SAFETY: ptr must be non-null (checked) and must be valid (can assume so due to OSI)
            let file = unsafe { CStr::from_ptr(mapping.file) };
            let file = file.to_string_lossy();

            file.to_string()
        } else if !mapping.name.is_null() {
            let name = unsafe { CStr::from_ptr(mapping.name) };
            let name = name.to_string_lossy();

            name.to_string()
        } else {
            "[unnamed]".to_owned()
        };

        println!("{:x}-{:x} {:x}    {}", start, end, mapping.modd, name);
    }
}

pub(crate) fn print_to_gdb(cpu: &mut CPUState, mut out: impl std::fmt::Write) {
    let mut proc = OSI.get_current_process(cpu);
    let mappings = OSI.get_mappings(cpu, &mut *proc);

    outputln!(out);
    outputln!(out, "Memory map:");
    for mapping in mappings.iter() {
        let start = mapping.base;
        let end = mapping.base + mapping.size;

        let name = if !mapping.file.is_null() {
            // SAFETY: ptr must be non-null (checked) and must be valid (can assume so due to OSI)
            let file = unsafe { CStr::from_ptr(mapping.file) };
            let file = file.to_string_lossy();

            file.to_string()
        } else if !mapping.name.is_null() {
            let name = unsafe { CStr::from_ptr(mapping.name) };
            let name = name.to_string_lossy();

            name.to_string()
        } else {
            "[unnamed]".to_owned()
        };

        outputln!(out, "{:x}-{:x} {:x}    {}", start, end, mapping.modd, name);
    }
}
