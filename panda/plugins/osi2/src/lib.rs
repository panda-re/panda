use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};

use panda::mem::read_guest_type;
use panda::plugins::syscalls2::Syscalls2Callbacks;
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
