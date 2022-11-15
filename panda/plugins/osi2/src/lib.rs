use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};

use panda::GuestType;
use panda::mem::{read_guest_type, virtual_memory_read_into};
use panda::plugins::osi2::{symbol_from_name, type_from_name};
use panda::prelude::*;
use std::{ffi::CStr, ffi::CString, os::raw::c_char};

use once_cell::sync::{Lazy, OnceCell};
use volatility_profile::VolatilityJson;

use panda::plugins::osi2::{osi_static, OsiType};

use panda::plugins::syscalls2::Syscalls2Callbacks;

static SYMBOL_TABLE: OnceCell<VolatilityJson> = OnceCell::new();

/// Interface for other plugins to interact with
mod ffi;
mod kaslr;
//mod structs;

//use structs;
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

//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// Move the below into its own file one day :')%%%%%%%%%%%%%%%%
//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

/// Max length of process command (`comm` field in task_struct)
const TASK_COMM_LEN: usize = 16;

//#################################################################
//#################### Task related structures ####################
//#################################################################

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

#[derive(Debug)]
struct OsiProc {
    asid: u32,
    start_time: target_ptr_t,
    name: String,
    pid: u32,
    ppid: u32,
    taskd: target_ptr_t,
}

#[derive(Debug)]
struct OsiThread {
    tid: u32,
    pid: u32,
}

//#################################################################
//#################### File related structures ####################
//#################################################################
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
#[osi(type_name = "qstr")]
struct Qstr {
    name: target_ptr_t, // type *char
}

#[derive(OsiType, Debug)]
#[osi(type_name = "dentry")]
struct Dentry {
    d_parent: target_ptr_t, // type *dentry
    d_name: target_ptr_t, // type qstr (struct qstr { union { struct {HASH_LEN_DECLARE;}; u64 hash_len; } const unsigned char *name;})
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
    #[osi(osi_type)]
    f_path: Path, // type Path
    //f_path: target_ptr_t, // placeholder for compilation until I can figure out what to do
    f_pos: target_ptr_t, // type long long int
}

#[derive(OsiType, Debug)]
#[osi(type_name = "fdtable")]
struct Fdtable {
    close_on_exec: target_ptr_t, // type *long unsigned int
    fd: target_ptr_t, // type **file
    full_fds_bits: target_ptr_t, // type *long unsigned int
    max_fds: u32, // type unsigned int
    open_fds: target_ptr_t, // type *long unsigned int | used as a bit vector, if nth bit is set, fd n is open

    //rcu: CallbackHead, // type callbackhead
    rcu: target_ptr_t, // placeholder for compilation until I can figure out what to do
}

#[derive(OsiType, Debug)]
#[osi(type_name = "files_struct")]
struct FilesStruct {
    fd_array: [target_ptr_t; 64], // type *file[] | default length is defined as BITS_IN_LONG, might need to make this smarter/dependant on the system
    fdt: target_ptr_t, // type *fdtable
    //fdtab: Fdtable, // type fdtable
}
//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// Move the above into its own file one day :')%%%%%%%%%%%%%%%%
//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

fn get_osiproc_info(cpu: &mut CPUState) -> Option<OsiProc> {
    let mut ret = OsiProc {asid: 0, start_time: 0, name: String::from(""), pid: 0, ppid: 0, taskd: 0,};

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

    let start_time = CURRENT_TASK.start_time(cpu).unwrap();
    ret.start_time = start_time;
    
    let comm_data = CURRENT_TASK.comm(cpu).unwrap();
    let task_comm_len = comm_data
        .iter()
        .position(|&x| x == 0u8)
        .unwrap_or(TASK_COMM_LEN);

    let proc_name = String::from_utf8_lossy(&comm_data[..task_comm_len]).into_owned();
    ret.name = proc_name;

    let pid = CURRENT_TASK.pid(cpu).unwrap();
    ret.pid = pid;

    let parent_ptr = CURRENT_TASK.parent(cpu).unwrap();
    let parent = TaskStruct::osi_read(cpu, parent_ptr).unwrap();
    let ppid = parent.pid;
    ret.ppid = ppid;

    // from osi_linux.cpp line166, p->taskd is being set to kernel_profile->get_group_leader
    // so presumably we can just read task_struct->group_leader to get that info?
    let taskd = CURRENT_TASK.group_leader(cpu).unwrap();
    ret.taskd = taskd;

    Some(ret)
}

fn get_osithread_info(cpu: &mut CPUState) -> Option<OsiThread> {
    let  mut ret = OsiThread { tid: 0, pid: 0};
    ret.tid = CURRENT_TASK.pid(cpu).unwrap();
    ret.pid = CURRENT_TASK.tgid(cpu).unwrap();

    Some(ret)
}



#[derive(Debug)]
struct OsiFile {
    fs_struct: target_ptr_t,
    name: String,
    f_pos: target_ptr_t,
    fd: u32,

}


#[derive(Debug)]
struct OsiFiles {
    files: Vec<OsiFile>,
}

// remimplement read_dentry_name from osi_linux.h
fn read_dentry_name(cpu: &mut CPUState, dentry: target_ptr_t) -> String {
    let mut ret = "".to_owned();
    
    let mut current_dentry_parent = dentry;
    let mut current_dentry: target_ptr_t = 0;

    while current_dentry_parent != current_dentry {
        current_dentry = current_dentry_parent;
        let mut dentry_struct = Dentry{ d_parent: 0, d_name: 0};
        match Dentry::osi_read(cpu, current_dentry).ok() {
            Some(res) => dentry_struct = res,
            None => continue,
        }
        current_dentry_parent = dentry_struct.d_parent;
        let mut name_ptr: target_ptr_t = 0;
        match Qstr::osi_read(cpu, dentry_struct.d_name).ok() {
            Some(res) => name_ptr = res.name,
            None => continue,
        }
         // reads the pointer which points to the start of the name we want
        // this maybe works? Who can say
        let name = unsafe {CStr::from_ptr(name_ptr as *const c_char).to_str().unwrap()};
        ret = ret.to_owned() + name
    }

    return ret
}

fn get_osi_file_info(cpu: &mut CPUState, file: File, ptr: target_ptr_t, fd: u32) -> Option<OsiFile> {
    // Want to get the file name here, which means we need file->path (type *dentry)
    // and then follow path->mnt->mnt_root (type *dentry) as well as path->dentry (type *dentry)
    // Then, for each dentry we read, we need to read dentry->name (type qstr) to get the name, as well as dentry->d_parent (type *dentry)
    // to repeat this process
    let mut ret = OsiFile { fs_struct: ptr, name: "".to_string(), f_pos: 0, fd: fd};
    let path = file.f_path;
    
    // read file->path->dentry to get a pointer to the first dentry we want to read;
    let mut name = read_dentry_name(cpu, path.dentry);
    // next read name stuff from vfsmount too
    let mnt = VfsMount::osi_read(cpu, path.mnt).unwrap();
    let name2 = read_dentry_name(cpu, mnt.mnt_root);
    ret.name = name.to_owned() + &name2;

    ret.f_pos = file.f_pos;

    return Some(ret)
}

fn get_osifiles_info(cpu: &mut CPUState) -> Option<OsiFiles> {
    let mut ret = OsiFiles { files: Vec::<OsiFile>::new()};

    let files_ptr = CURRENT_TASK.files(cpu).unwrap();
    println!("Reading FileStruct");
    let files = FilesStruct::osi_read(cpu, files_ptr).ok();

    let fd_array = match files {
        Some(res) => {
            println!("Read FileStruct | fdt {:x}", res.fdt);
            res.fd_array
        },
        None => return None,
    };
    println!("Did not return none");

    let mut fds = Vec::<File>::new();
    let mut idx: u32 = 0;
    for fd in fd_array {
        //println!("Checking idx {} | fd {}", idx, fd);
        let mut p = Path { dentry: 0, mnt: 0};
        let mut f = File { f_path: p, f_pos: 0};
        match File::osi_read(cpu, fd).ok() {
            Some(res) => {
                println!("Outstanding, I could actually read this");
                match get_osi_file_info(cpu, res, fd, idx) {
                    Some(f_info) => ret.files.push(f_info),
                    None => (),
                };
                
            }
            None => (),
        };
        idx = idx + 1;
    }
    Some(ret)
    // The old ways, fit only to be abandoned in light of the glory of the One True Way of Doing Things
    /*
    let fdt = match files {
        Some(res) => res.fdt,
        None => 0,
    };
    if fdt == 0 {
        println!("No files found");
        return None
    } else {
        let fdt_check = Fdtable::osi_read(cpu, fdt).ok();
        let check = match fdt_check {
            Some(ref res) => 1,
            None => 0,
        };
        if check == 0 {
            println!("Fdtable could not be read");
            return None
        } else {
            let fdtable = fdt_check.unwrap();
            let fd_max = fdtable.max_fds;
            println!("max fds: {}", fd_max);
            let mut ptr = fdtable.fd;
            let mut fds = Vec::<File>::new();
            for i in 0..fd_max {
                let idx = (i as usize) * size_of::<target_ptr_t>();
                ptr = ptr + (idx as u64);
                match target_ptr_t::read_from_guest(cpu, ptr).ok() {
                    Some(res) => {
                        let mut f = File{ f_path: 0, f_pos: 0};
                        match File::osi_read(cpu, res).ok() {
                            Some(file_read) => f = file_read,
                            None => break,
                        };
                        let f_info = get_osi_file_info(cpu, f, res, idx as u32);
                        match f_info {
                            Some(succ) => ret.files.push(succ),
                            None => (),
                        }
                    },
                    None => break,
             
                }
            }
        }
    }
    Some(ret)
    */
}

fn print_osiproc_info(cpu: &mut CPUState) -> bool {
    let proc = match get_osiproc_info(cpu) { 
        Some(res) => {
            if res.asid != 0 {
                println!("asid: {:x}", res.asid);
            } else {
                println!("asid: Err");
            }
            println!("start_time: {:x}", res.start_time);
            println!("name: {}", res.name);
            println!("pid, {:x}", res.pid);
            println!("ppid, {:x}", res.ppid);
            println!("taskd, {:x}", res.taskd);
        },
        None => println!("Could not read current proc"),
    };
    true
}

fn print_osithread_info(cpu: &mut CPUState) -> bool {
    let thread = match get_osithread_info(cpu) {
        Some(res) => {
            println!("tid: {:x}", res.tid);
            println!("pid: {:x}", res.pid);
        }
        None => println!("Could not read current proc"),
    };
    true
}

fn print_osifile_info(cpu: &mut CPUState) -> bool {
    match get_osifiles_info(cpu) {
        Some(res) => {
            for i in res.files {
                println!("file name: {} | fd: {}", i.name, i.fd);
                println!("\tfile struct ptr: {:x}", i.fs_struct);
                println!("\tfile position: {:x}", i.f_pos);
            }
        },
        None => println!("Could not read files from current proc"),
    }
    true
}

/*
#[panda::asid_changed]
fn asid_changed(cpu: &mut CPUState, _old_asid: target_ulong, _new_asid: target_ulong) -> bool {
    println!("\n\nOSI2 INFO START");

    print_osiproc_info(cpu);
    
    print_osithread_info(cpu);

    print_osifile_info(cpu);

    println!("OSI2 INFO END\n\n");

    true
}*/