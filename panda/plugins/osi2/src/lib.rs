use std::mem::size_of;

use panda::mem::{read_guest_type, virtual_memory_read_into};
use panda::plugins::osi2::{symbol_from_name, type_from_name};
use panda::prelude::*;

use once_cell::sync::OnceCell;
use volatility_profile::VolatilityJson;

static SYMBOL_TABLE: OnceCell<VolatilityJson> = OnceCell::new();

/// Interface for other plugins to interact with
mod ffi;
mod kaslr;

use kaslr::kaslr_offset;

// TODO: needs to not be a hardcoded path
#[cfg(feature = "i386")]
const FILENAME: &str = "/home/jmcleod/dev/ubuntu:4.4.0-170-generic:32.json.xz";

#[cfg(feature = "x86_64")]
const FILENAME: &str = "/home/jmcleod/dev/ubuntu:4.15.0-72-generic:64.json.xz";

fn symbol_table() -> &'static VolatilityJson {
    SYMBOL_TABLE.get_or_init(|| VolatilityJson::from_compressed_file(FILENAME))
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    println!("initializing osi2");

    // Ensure symbol table is initialized
    let _ = symbol_table();

    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}

fn current_cpu_offset(cpu: &mut CPUState) -> target_ulong {
    let symbol_table = symbol_table();

    let cpu_offset = symbol_table
        .symbol_from_name("__per_cpu_offset")
        .expect("Could not find symbol for __per_cpu_offset in volatility profile")
        .address as target_ptr_t;

    let kaslr_offset = kaslr_offset(cpu);
    let cpu_num = cpu.cpu_index as target_ptr_t;
    let offset_in_array = size_of::<target_ulong>() as target_ptr_t * cpu_num;

    let cpu_offset_ptr = kaslr_offset + cpu_offset + offset_in_array;
    let cpu_offset: target_ulong = read_guest_type(cpu, cpu_offset_ptr).unwrap();

    cpu_offset
}

/// Max length of process command (`comm` field in task_struct)
const TASK_COMM_LEN: usize = 16;

fn current_process_name(cpu: &mut CPUState) -> String {
    // it's zero at the moment, but we do determine it
    let _kaslr_offset = kaslr_offset(cpu);

    let cur_task = symbol_from_name("current_task").unwrap();
    let task_struct = type_from_name("task_struct").unwrap();
    let comm_offset = task_struct.offset_of("comm") as target_ptr_t;

    let task_addr = cur_task.addr() + current_cpu_offset(cpu);
    let current_task_ptr = read_guest_type::<target_ptr_t>(cpu, task_addr).unwrap();

    let mut comm_data = [0; TASK_COMM_LEN];
    let comm_ptr = current_task_ptr + comm_offset;
    virtual_memory_read_into(cpu, comm_ptr, &mut comm_data).unwrap();

    // Find null terminator, if it exists, with a max length of sizeof(comm)
    let task_comm_len = comm_data
        .iter()
        .position(|&x| x == 0u8)
        .unwrap_or(TASK_COMM_LEN);

    String::from_utf8_lossy(&comm_data[..task_comm_len]).into_owned()
}

#[panda::asid_changed]
fn asid_changed(cpu: &mut CPUState, _old_asid: target_ulong, _new_asid: target_ulong) -> bool {
    println!("found process {}", current_process_name(cpu));
    false
}
