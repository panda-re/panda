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
    #[arg(required, about = "Path to a volatility 3 symbol table to use (.xz compressed json)")]
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
struct CredStruct {
    uid: target_ptr_t, // type unsigned int
    gid: target_ptr_t, // type unsigned int
    euid: target_ptr_t, // type unsigned int
    egid: target_ptr_t, // type unsigned int
}

#[derive(OsiType, Debug)]
#[osi(type_name = "mm_struct")]
struct MmStruct {
    //size: target_ptr_t,
    pgd: u32, // type *unnamed_bunch_of_stuff_3
    arg_start: target_ptr_t, // type long unsigned int
    start_brk: target_ptr_t, // type long unsigned int
    brk: target_ptr_t, // type long unsigned int
    start_stack: target_ptr_t, // type long unsigned int
}

#[derive(OsiType, Debug)]
#[osi(type_name = "task_struct")]
struct TaskStruct {
    //size: target_ptr_t,

    // Only one of tasks or next_task will exist as a field
    tasks: target_ptr_t, // type list_head
    //next_task: target_ptr_t, // type ??

    pid: u32, // type int
    tgid: u32, //type int
    group_leader: target_ptr_t, // type *task_struct
    thread_group: target_ptr_t, // type list_head

    // Only one of real_parent or p_opptr will exist as a field
    real_parent: target_ptr_t, // type *task_struct 
    //p_opptr: target_ptr_t, // type ??

    // Only one of parent or p_pptr will exist as a field
    parent: target_ptr_t, // type *task_struct
    //p_pptr: target_ptr_t, // type ??

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

#[derive(OsiType, Debug)]
#[osi(type_name = "vm_area_struct")]
struct VmAreaStruct {
    vm_mm: target_ptr_t, // type *mm_struct
    vm_start: target_ptr_t, // type long unsigned int
    vm_end: target_ptr_t, // type long unsigned int
    vm_next: target_ptr_t, // type *vm_area_struct
    vm_file: target_ptr_t, // type *file
    vm_flags: target_ptr_t, // type long unsigned int
}

#[derive(OsiType, Debug)]
#[osi(type_name = "callback_head")]
struct CallbackHead {
    func: target_ptr_t, // type *function
    next: target_ptr_t, // type *callback_head
}

#[derive(OsiType, Debug)]
#[osi(type_name = "dentry")]
struct Dentry {
    //TODO because it's a lot of bullshit I don't want to think about
}

#[derive(OsiType, Debug)]
#[osi(type_name = "vfsmount")]
struct VfsMount {
    mnt_flags: i32, // type int
    mnt_root: target_ptr_t, // type *dentry
    //TODO: see Dentry
    //mnt_sb: SuperBlock, // type SuperBlock
}

#[derive(OsiType, Debug)]
#[osi(type_name = "path")]
struct Path {
    dentry: target_ptr_t, // type *dentry
    mnt: target_ptr_t, // type *vfsmount
}

#[derive(OsiType, Debug)]
#[osi(type_name = "file")]
struct File {
    //f_path: Path, // type Path
    f_path: target_ptr_t, // placeholder for compilation until I can figure out what to do
    f_pos: target_ptr_t, // type long long int
}

#[derive(OsiType, Debug)]
#[osi(type_name = "fdtable")]
struct Fdtable {
    close_on_exec: target_ptr_t, // type *long unsigned int
    fd: target_ptr_t, // type **file
    full_fds_bits: target_ptr_t, // type *long unsigned int
    max_fds: u32, // type unsigned int
    open_fds: target_ptr_t, // type *long unsigned int
    //rcu: CallbackHead, // type callbackhead
    rcu: target_ptr_t, // placeholder for compilation until I can figure out what to do
}

#[derive(OsiType, Debug)]
#[osi(type_name = "files_struct")]
struct FilesStruct {
    fdt: target_ptr_t, // type *fdtable
    //fdtab: Fdtable, // type fdtable
}


fn print_osiproc_info(cpu: &mut CPUState) -> bool {
    // From osi_linux.cpp: p->asid = taskd->mm->pgd
    // so presumably we can just follow task_struct->mm->pgd to get that information
    // relatedly, from osi_linux.cpp, this will error occasionally and that should be
    // seen as "fine"
    let mm_ptr = CURRENT_TASK.mm(cpu).unwrap();
    let mm = MmStruct::osi_read(cpu, mm_ptr).ok();
    let asid:u32 = match mm {
        Some(res) => res.pgd,
        None => 0,
    };
    if asid != 0 {
    println!("asid: {:x}", asid);
    } else {
        println!("asid: ERR");
    }

    let start_time = CURRENT_TASK.start_time(cpu).unwrap();
    println!("Start time: {:x}", start_time);
    
    let comm_data = CURRENT_TASK.comm(cpu).unwrap();
    let task_comm_len = comm_data
        .iter()
        .position(|&x| x == 0u8)
        .unwrap_or(TASK_COMM_LEN);

    let proc_name = String::from_utf8_lossy(&comm_data[..task_comm_len]).into_owned();
    println!("name: {}", proc_name);

    // unimplemented in osi_linux as of yet
    println!("pages: TODO");

    let pid = CURRENT_TASK.pid(cpu).unwrap();
    println!("pid : {:x}", pid);

    let parent_ptr = CURRENT_TASK.parent(cpu).unwrap();
    let parent = TaskStruct::osi_read(cpu, parent_ptr).unwrap();
    let ppid = parent.pid;
    println!("ppid: {:x}", ppid);

    // from osi_linux.cpp line166, p->taskd is being set to kernel_profile->get_group_leader
    // so presumably we can just read task_struct->group_leader to get that info?
    let taskd = CURRENT_TASK.group_leader(cpu).unwrap();
    println!("taskd: {:x}", taskd);

    true
}

fn print_osithread_info(cpu: &mut CPUState) -> bool {
    let tid = CURRENT_TASK.pid(cpu).unwrap();
    println!("tid: {:x}", tid);
    let pid = CURRENT_TASK.tgid(cpu).unwrap();
    println!("pid: {:x}", pid);

    true
}

fn print_files_info(cpu: &mut CPUState) -> bool {
    let files_ptr = CURRENT_TASK.files(cpu).unwrap();
    let files = FilesStruct::osi_read(cpu, files_ptr).ok();
    let fdt = match files {
        Some(res) => res.fdt,
        None => 0,
    };
    if fdt == 0 {
        println!("No files found");
        return false
    } else {
        let fdtable = Fdtable::osi_read(cpu, fdt).ok();
        // Here is where we want to start getting at the relevant info, but that needs to go through 
        // CallbackHead which I'm still not sure of
    }

    true
}

#[panda::asid_changed]
fn asid_changed(cpu: &mut CPUState, _old_asid: target_ulong, _new_asid: target_ulong) -> bool {
    println!("\n\nOSI2 INFO START");

    print_osiproc_info(cpu);
    
    print_osithread_info(cpu);

    println!("OSI2 INFO END\n\n");

    true
}