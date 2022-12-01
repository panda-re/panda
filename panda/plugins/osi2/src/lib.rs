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

fn get_osiproc_info(cpu: &mut CPUState) -> Option<CosiProc> {
    let mut ret = OsiProc {
        asid: 0,
        start_time: 0,
        name: String::from(""),
        pid: 0,
        ppid: 0,
        taskd: 0,
    };

    // From osi_linux.cpp: p->asid = taskd->mm->pgd
    // so presumably we can just follow task_struct->mm->pgd to get that information
    // relatedly, from osi_linux.cpp, this will error occasionally and that should be
    // seen as "fine"
    let mm_ptr = CURRENT_TASK.mm(cpu).unwrap();
    let mm = MmStruct::osi_read(cpu, mm_ptr).ok();
    let asid: u32 = match mm {
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

fn get_osithread_info(cpu: &mut CPUState) -> Option<CosiThread> {
    let mut ret = OsiThread { tid: 0, pid: 0 };
    ret.tid = CURRENT_TASK.pid(cpu).unwrap();
    ret.pid = CURRENT_TASK.tgid(cpu).unwrap();

    Some(ret)
}

pub fn read_string_from_guest(cpu: &mut CPUState, start_ptr: target_ptr_t) -> String {
    let mut ptr = start_ptr;
    let mut char_read = 1u8;
    let step = 1;
    let mut collect = "".to_owned();

    while char_read != 0u8 {
        char_read = u8::read_from_guest(cpu, ptr).unwrap();
        ptr = ptr + 1;
        collect.push(char_read as char);
    }

    collect
}

// remimplement read_dentry_name from osi_linux.h
fn read_dentry_name(cpu: &mut CPUState, dentry: target_ptr_t, is_mnt: bool) -> String {
    let mut ret = "".to_owned();

    let mut current_dentry_parent = dentry;
    let mut current_dentry: target_ptr_t = 0xdead00af;

    while current_dentry_parent != current_dentry {
        current_dentry = current_dentry_parent;

        let mut qd_name = Qstr {
            unnamed_field_0: 0,
            name: 0,
        };
        let mut dentry_struct = Dentry {
            d_parent: 0,
            d_name: qd_name,
        };
        match Dentry::osi_read(cpu, current_dentry).ok() {
            Some(res) => dentry_struct = res,
            None => continue,
        }

        current_dentry_parent = dentry_struct.d_parent;

        let mut name_ptr = dentry_struct.d_name.name;

        //let name = read_string_from_guest(cpu, name_ptr);
        let name = cpu.mem_read_string(name_ptr);
        let mut term = "/";

        if ret == "" || is_mnt {
            term = &"";
        }
        if &name == "/" || current_dentry == current_dentry_parent {
            ret = name.to_owned() + &ret
        } else {
            ret = name.to_owned() + term + &ret
        }
    }

    match ret.as_str() {
        "/" => "".to_owned(),
        _ => ret,
    }
}

/*
fn get_osi_file_info(
    cpu: &mut CPUState,
    file: File,
    ptr: target_ptr_t,
    fd: u32,
) -> Option<CosiFile> {
    // Want to get the file name here, which means we need file->path (type *dentry)
    // and then follow path->mnt->mnt_root (type *dentry) as well as path->dentry (type *dentry)
    // Then, for each dentry we read, we need to read dentry->name (type qstr) to get the name, as well as dentry->d_parent (type *dentry)
    // to repeat this process

    let mut ret = OsiFile {
        fs_struct: ptr,
        name: "".to_string(),
        f_pos: 0,
        fd: fd,
    };
    let path = file.f_path;

    // read file->path->dentry to get a pointer to the first dentry we want to read;
    let mut name = read_dentry_name(cpu, path.dentry, false);

    // next read name stuff from vfsmount too
    let mnt = VfsMount::osi_read(cpu, path.mnt).ok()?;

    let mount_vol = symbol_table().type_from_name("mount").unwrap();
    let off = mount_vol.fields["mnt"].offset as u64;
    let mount_struct = Mount::osi_read(cpu, path.mnt - off).ok()?;
    let name2 = read_dentry_name(cpu, mount_struct.mnt_mountpoint, true);

    ret.name = name2.to_owned() + &name;

    ret.f_pos = file.f_pos;

    return Some(ret);
} */

fn get_osifiles_info(cpu: &mut CPUState) -> Option<CosiFiles> {
    /*let mut ret = OsiFiles {
        files: Vec::new(),
    }; */
    let file_vec = Vec<CosiFiles>::new();
    let files_ptr = CURRENT_TASK.files(cpu).unwrap();
    let files = FilesStruct::osi_read(cpu, files_ptr).ok()?;
    let fdtab = files.fdt;

    let fdtable = Fdtable::osi_read(cpu, fdtab).ok()?;

    let max_fds = fdtable.max_fds as u32;
    let open_fds_ptr = fdtable.open_fds;
    let open_fds = u32::read_from_guest(cpu, open_fds_ptr).unwrap();
    let mut fd_ptr = fdtable.fd;

    //let mut fds = Vec::<File>::new();
    let step = size_of::<target_ptr_t>() as u64;
    for idx in 0..max_fds {
        let fd = target_ptr_t::read_from_guest(cpu, fd_ptr).unwrap();
        if fd == 0 {
            break;
        }
        let bv_check = open_fds >> idx;
        if bv_check == 0 {
            break;
        }

        if bv_check % 2 == 0 {
            fd_ptr = fd_ptr + step;
            continue;
        }
        /*
        let mut p = Path { dentry: 0, mnt: 0 };
        let mut f = File {
            f_path: p,
            f_pos: 0,
        }; */
            match CosiFile::new(cpu, fd, idx) {
                Some(f_info) => file_vec.push(f_info),
                None => {
                    println!("Failed to read info for fd {idx}");
                    ()
                }
            };
        fd_ptr = fd_ptr + step;
    }
    Some(CosiFiles { files: file_vec,})
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
        }
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
            }
        }
        None => println!("Could not read files from current proc"),
    }
    true
}

#[panda::asid_changed]
fn asid_changed(cpu: &mut CPUState, _old_asid: target_ulong, _new_asid: target_ulong) -> bool {
    println!("\n\nOSI2 INFO START");

    print_osiproc_info(cpu);
    print_osithread_info(cpu);
    print_osifile_info(cpu);

    println!("OSI2 INFO END\n\n");

    true
}
