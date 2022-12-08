use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};

use panda::mem::{read_guest_type, virtual_memory_read_into};
use panda::plugins::osi2::{symbol_from_name, type_from_name};
use panda::prelude::*;
use panda::GuestType;
use std::{ffi::CStr, ffi::CString, os::raw::c_char};

use once_cell::sync::{Lazy, OnceCell};
use volatility_profile::VolatilityJson;

use panda::plugins::osi2::{osi_static, OsiType};

use panda::plugins::syscalls2::Syscalls2Callbacks;

static SYMBOL_TABLE: OnceCell<VolatilityJson> = OnceCell::new();

/// Interface for other plugins to interact with
mod ffi;
mod kaslr;
mod structs;

use kaslr::kaslr_offset;

use ffi::offset_of_field;

use structs::*;

#[derive(PandaArgs)]
#[name = "osi2"]
struct Args {
    #[arg(
        required,
        about = "Path to a volatility 3 symbol table to use (.xz compressed json)"
    )]
    profile: String,
}

const ARGS: Lazy<Args> = Lazy::new(Args::from_panda_args);

fn symbol_table() -> &'static VolatilityJson {
    SYMBOL_TABLE.get_or_init(|| VolatilityJson::from_compressed_file(&ARGS.profile))
}

static READY_FOR_KASLR_SEARCH: AtomicBool = AtomicBool::new(false);

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    // Ensure symbol table is initialized
    let _ = symbol_table();

    let first_syscall = panda::PppCallback::new();

    first_syscall.on_all_sys_enter(move |_, _, _| {
        READY_FOR_KASLR_SEARCH.store(true, Ordering::SeqCst);

        first_syscall.disable();
    });

    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}

fn current_cpu_offset(cpu: &mut CPUState) -> target_ulong {
    let symbol_table = symbol_table();

    let cpu_offset = match symbol_table.symbol_from_name("__per_cpu_offset") {
        Some(symbol) => symbol.address as target_ptr_t,
        None => return 0,
    };

    let kaslr_offset = kaslr_offset(cpu);
    let cpu_num = cpu.cpu_index as target_ptr_t;
    let offset_in_array = size_of::<target_ulong>() as target_ptr_t * cpu_num;

    let cpu_offset_ptr = kaslr_offset + cpu_offset + offset_in_array;
    let cpu_offset: target_ulong = read_guest_type(cpu, cpu_offset_ptr).unwrap();

    cpu_offset
}

osi_static! {
    #[per_cpu]
    #[symbol = "current_task"]
    static CURRENT_TASK: TaskStruct;
}

fn print_cosiproc_info(cpu: &mut CPUState) -> bool {
    match CosiProc::get_current_process(cpu) {
        Some(res) => {
            if res.asid != 0 {
                println!("asid: {:x}", res.asid);
            } else {
                println!("asid: Err");
            }
            println!("start_time: {:x}", res.task.start_time);
            println!("name: {}", res.name);
            println!("pid, {:x}", res.task.pid);
            println!("ppid, {:x}", res.ppid);
            println!("taskd, {:x}", res.taskd);
        }
        None => println!("Could not read current proc"),
    };
    true
}

fn print_osithread_info(cpu: &mut CPUState) -> bool {
    match CosiThread::get_current_thread(cpu) {
        Some(res) => {
            println!("tid: {:x}", res.tid);
            println!("pid: {:x}", res.pid);
        }
        None => println!("Could not read current proc"),
    };
    true
}

fn print_current_cosifile_info(cpu: &mut CPUState) -> bool {
    match CosiFiles::get_current_files(cpu) {
        Some(res) => {
            for i in res.files {
                println!("file name: {} | fd: {}", i.name, i.fd);
            }
        }
        None => println!("Could not read files from current proc"),
    }
    true
}

fn print_current_cosimappings_info(cpu: &mut CPUState) -> bool {
    match CosiProc::get_current_process(cpu) {
        Some(res) => match res.get_mappings(cpu) {
            Some(mapping) => {
                for mdl in mapping.modules.iter() {
                    println!("modd: {:x} | base: {:x} | size: {:x} | file: {} | name: {}", mdl.modd, mdl.base, mdl.size, mdl.file, mdl.name)
                }
            },
            None => println!("Could not read memory mapping"),
        },
        None => println!("Could not read current process"),
    }
    true
}

#[panda::asid_changed]
fn asid_changed(cpu: &mut CPUState, _old_asid: target_ulong, _new_asid: target_ulong) -> bool {
    println!("\n\nOSI2 INFO START");

    print_cosiproc_info(cpu);
    print_osithread_info(cpu);
    print_current_cosifile_info(cpu);
    print_current_cosimappings_info(cpu);

    println!("OSI2 INFO END\n\n");

    true
}
