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

#[derive(Debug)]
struct Version {
    a: target_ptr_t,
    b: target_ptr_t,
    c: target_ptr_t,
}

// Digging around in kernel source for 3.7 traced these fields' types, kuid_t and kgid_t,
// through a few definitions and found they were both structs which hold a single value of type
// git_t or uid_t which are, in that kernel version, just unsigned ints
#[derive(OsiType, Debug)]
#[osi(type_name = "cred")]
struct Cred {
    uid: target_ptr_t, // type unsigned int
    gid: target_ptr_t, // type unsigned int
    euid: target_ptr_t, // type unsigned int
    egid: target_ptr_t, // type unsigned int
}

#[derive(OsiType, Debug)]
#[osi(type_name = "mm")]
struct Mm {
    size: target_ptr_t,
    pgd: target_ptr_t, // type *unnamed_bunch_of_stuff_3
    arg_start: target_ptr_t, // type long unsigned int
    start_brk: target_ptr_t, // type long unsigned int
    brk: target_ptr_t, // type long unsigned int
    start_strack: target_ptr_t, // type long unsigned int
}

#[derive(OsiType, Debug)]
#[osi(type_name = "task_struct")]
struct TaskStruct {
    size: target_ptr_t,

    // Only one of tasks or next_task will exist as a field
    tasks: target_ptr_t, // type list_head
    next_task: target_ptr_t, // type ??

    pid: target_ptr_t, // type int
    tgid: target_ptr_t, //type int
    group_leader: target_ptr_t, // type *task_struct
    thread_group: target_ptr_t, // type list_head

    // Only one of real_parent or p_opptr will exist as a field
    real_parent: target_ptr_t, // type *task_struct 
    p_opptr: target_ptr_t, // type ??

    // Only one of parent or p_pptr will exist as a field
    parent: target_ptr_t, // type *task_struct
    p_pptr: target_ptr_t, // type ??

    mm: target_ptr_t, // type *mm_struct
    stack: target_ptr_t, // type *void
    real_cred: target_ptr_t, // type *cred
    cred: target_ptr_t, // type *cred
    comm: [u8; TASK_COMM_LEN], // type char[]
    files: target_ptr_t, // type *files_struct
    start_time: target_ptr_t, // type long long unsigned int

}

osi_static! {
    #[per_cpu]
    #[symbol = "current_task"]
    static CURRENT_TASK: TaskStruct;
}

#[panda::asid_changed]
fn asid_changed(cpu: &mut CPUState, _old_asid: target_ulong, _new_asid: target_ulong) -> bool {
    let comm_data = CURRENT_TASK.comm(cpu).unwrap();
    let p_opptr = CURRENT_TASK.p_opptr(cpu).unwrap();
    let task_comm_len = comm_data
        .iter()
        .position(|&x| x == 0u8)
        .unwrap_or(TASK_COMM_LEN);

    let proc_name = String::from_utf8_lossy(&comm_data[..task_comm_len]).into_owned();

    println!("found process {}", proc_name);

    false
}
