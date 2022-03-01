use panda::mem::{read_guest_type, virtual_memory_read};
use panda::prelude::*;

use once_cell::sync::OnceCell;
use volatility_profile::VolatilityJson;

static SYMBOL_TABLE: OnceCell<VolatilityJson> = OnceCell::new();

/// Interface for other plugins to interact with
mod ffi;
mod kaslr;

use kaslr::kaslr_offset;

// TODO: needs to not be a hardcoded path
const FILENAME: &str = "/home/jmcleod/dev/ubuntu:4.4.0-170-generic:32.json.xz";

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

fn current_process_name(cpu: &mut CPUState) -> String {
    // it's zero at the moment, but we do determine it
    let _kaslr_offset = kaslr_offset(cpu);

    let symbol_table = symbol_table();
    let cur_task = symbol_table.symbol_from_name("current_task").unwrap();
    let task_struct = symbol_table.type_from_name("task_struct").unwrap();
    let comm_offset = task_struct.fields.get("comm").unwrap().offset as target_ulong;
    let cpu_offset = symbol_table
        .symbol_from_name("__per_cpu_offset")
        .unwrap()
        .address as target_ptr_t;
    let cpu_0_offset: target_ulong = read_guest_type(cpu, cpu_offset).unwrap();
    let current_task_ptr: target_ptr_t =
        read_guest_type(cpu, cur_task.address as target_ulong + cpu_0_offset).unwrap();
    let mut comm_data = virtual_memory_read(cpu, current_task_ptr + comm_offset, 16).unwrap();

    let string_end = comm_data.iter().position(|x| *x == 0u8).unwrap_or(0x10);

    comm_data.truncate(string_end);

    String::from_utf8(comm_data).unwrap()
}

#[panda::asid_changed]
fn asid_changed(cpu: &mut CPUState, _old_asid: target_ulong, _new_asid: target_ulong) -> bool {
    println!("found process {}", current_process_name(cpu));
    false
}
