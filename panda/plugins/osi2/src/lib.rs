use std::mem::size_of;

use panda::mem::{read_guest_type, virtual_memory_read_into};
use panda::plugins::osi2::{symbol_from_name, type_from_name};
use panda::prelude::*;

use once_cell::sync::{Lazy, OnceCell};
use volatility_profile::VolatilityJson;

static SYMBOL_TABLE: OnceCell<VolatilityJson> = OnceCell::new();

/// Interface for other plugins to interact with
mod ffi;
mod kaslr;

use kaslr::kaslr_offset;

#[derive(PandaArgs)]
#[name = "osi2"]
struct Args {
    #[arg(required, about = "Path to a volatility 3 symbol table to use")]
    profile: String,
}

const ARGS: Lazy<Args> = Lazy::new(Args::from_panda_args);

fn symbol_table() -> &'static VolatilityJson {
    SYMBOL_TABLE.get_or_init(|| VolatilityJson::from_compressed_file(&ARGS.profile))
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    println!("initializing osi2");

    // Ensure symbol table is initialized
    let _ = symbol_table();

    let wait_for_kernel = panda::Callback::new();

    wait_for_kernel.before_block_exec(move |cpu, _| {
        if panda::in_kernel_mode/*code_linux*/(cpu) {
            wait_for_kernel.disable();

            println!("kaslr_offset: {}", kaslr_offset(cpu));
        }
    });

    println!("osi2 symbol table loaded");

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

use panda::plugins::osi2::{osi_static, OsiType};

#[derive(OsiType, Debug)]
#[osi(type_name = "task_struct")]
struct TaskStruct {
    comm: [u8; TASK_COMM_LEN],
}

osi_static! {
    #[per_cpu]
    #[symbol = "current_task"]
    static CURRENT_TASK: TaskStruct;
}

#[panda::asid_changed]
fn asid_changed(cpu: &mut CPUState, _old_asid: target_ulong, _new_asid: target_ulong) -> bool {
    let _kaslr = kaslr_offset(cpu);

    let comm_data = CURRENT_TASK.comm(cpu).unwrap();
    let task_comm_len = comm_data
        .iter()
        .position(|&x| x == 0u8)
        .unwrap_or(TASK_COMM_LEN);

    let proc_name = String::from_utf8_lossy(&comm_data[..task_comm_len]).into_owned();

    println!("found process {}", proc_name);

    false
}
