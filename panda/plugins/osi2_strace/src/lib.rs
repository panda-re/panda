use once_cell::sync::OnceCell;
use panda::{
    abi::syscall::{SYSCALL_ARGS, SYSCALL_RET},
    plugins::{
        osi2::{self, OsiType},
        syscalls2::Syscalls2Callbacks,
    },
    prelude::*,
    PppCallback,
};
use std::{
    collections::HashMap,
    io::Write,
    mem,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};

mod c_type_parser;
use c_type_parser::Type;

mod osi_arg_type;
use osi_arg_type::OsiArgType;

mod syscall_exception;

#[derive(OsiType, Debug)]
#[osi(type_name = "syscall_metadata")]
struct SyscallMetadata {
    args: target_ptr_t,
    types: target_ptr_t,
    name: target_ptr_t,
    nb_args: i32,
    syscall_nr: i32,
}

#[derive(Debug, Clone)]
struct SyscallArg {
    name: String,
    arg_type: OsiArgType,
}

#[derive(Debug, Clone)]
struct SyscallInfo {
    name: String,
    args: Vec<SyscallArg>,
    fn_addr: Option<target_ptr_t>,
}

osi2::osi_static! {
    #[symbol = "syscalls_metadata"]
    static SYSCALLS_METADATA: target_ptr_t;
}

static SYSCALL_INFO: OnceCell<Vec<Option<SyscallInfo>>> = OnceCell::new();

//fn override_type() -> Option<OsiArgType> {
//
//}

enum Event {
    Enter,
    Exit,
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    println!("Initializing osi2_strace");
    osi2::OSI2.ensure_init();

    let first_bb = panda::Callback::new();

    first_bb.before_block_exec(move |cpu, _| {
        if SYSCALL_INFO.get().is_some() {
            first_bb.disable();
            return;
        }

        if !panda::in_kernel_mode(cpu) {
            return;
        }

        let ptr_size = mem::size_of::<target_ptr_t>() as target_ptr_t;

        let sys_meta_start = osi2::symbol_addr_from_name("__start_syscalls_metadata");
        let sys_meta_end = osi2::symbol_addr_from_name("__stop_syscalls_metadata");

        let sys_call_table = osi2::symbol_addr_from_name("sys_call_table");

        let syscall_count = (sys_meta_end - sys_meta_start) / ptr_size;

        let mut converted_types = HashMap::new();
        let mut syscall_info = Vec::with_capacity(syscall_count as usize);
        let ptr = SYSCALLS_METADATA.read(cpu).unwrap();
        for i in 0..syscall_count {
            let current_syscall;
            if let Ok(ptr) = target_ptr_t::osi_read(cpu, ptr + (ptr_size * i)) {
                if let Ok(meta) = SyscallMetadata::osi_read(cpu, ptr) {
                    let name = cpu.mem_read_string(meta.name);

                    let mut args = Vec::with_capacity(meta.nb_args as usize);
                    for j in 0..(meta.nb_args as target_ptr_t) {
                        let arg_name = if let Ok(ptr) =
                            target_ptr_t::osi_read(cpu, meta.args + (j * ptr_size))
                        {
                            let arg_name = cpu.mem_read_string(ptr);
                            arg_name
                        } else {
                            String::from("[arg]")
                        };

                        let arg_type = if let Ok(ptr) =
                            target_ptr_t::osi_read(cpu, meta.types + (j * ptr_size))
                        {
                            let arg_type = cpu.mem_read_string(ptr);
                            arg_type
                        } else {
                            String::from("[type]")
                        };

                        let arg_type =
                            converted_types
                                .entry(arg_type)
                                .or_insert_with_key(|arg_type| {
                                    Type::parse(arg_type.trim())
                                        .map(OsiArgType::from)
                                        .unwrap_or_else(|err| {
                                            log::warn!(
                                                "failed to parse {:?} ({:?})",
                                                arg_type,
                                                err
                                            );
                                            OsiArgType::Fallback
                                        })
                                });

                        args.push(SyscallArg {
                            name: arg_name,
                            arg_type: arg_type.clone(),
                        });
                        //args.push(format!("{} {}", arg_type, arg_name));
                    }

                    //println!("{}: {}({})", meta.syscall_nr, name, args.join(", "));

                    let fn_addr = target_ptr_t::osi_read(
                        cpu,
                        sys_call_table + ((meta.syscall_nr as target_ptr_t) * ptr_size),
                    )
                    .ok();

                    current_syscall = Some(SyscallInfo {
                        name,
                        args,
                        fn_addr,
                    });
                } else {
                    current_syscall = None;
                }
            } else {
                current_syscall = None;
            }

            syscall_info.push(current_syscall);
        }

        //println!("syscalls: {:#x?}", syscall_info);
        SYSCALL_INFO.set(syscall_info).unwrap();

        first_bb.disable();

        let last_callno = Arc::new(AtomicU64::new(0));
        let last_callno_exit = Arc::clone(&last_callno);

        let last_handled = Arc::new(AtomicBool::new(true));
        let last_handled_exit = Arc::clone(&last_handled);

        PppCallback::new().on_all_sys_enter(move |cpu, _pc, callno| {
            if !last_handled.swap(false, Ordering::SeqCst) {
                println!();
            }

            last_callno.store(callno as u64, Ordering::SeqCst);

            let syscall = SYSCALL_INFO
                .get()
                .unwrap()
                .get(callno as usize)
                .cloned()
                .flatten();

            if let Some(syscall) = syscall {
                let mut regs = SYSCALL_ARGS.iter().cloned();

                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();

                let count = syscall.args.iter().position(|x| x.name == "count");
                let count = count.map(|count| SYSCALL_ARGS[count].read(cpu));

                let mut is_first = true;
                write!(stdout, "{}(", syscall.name);
                for arg in &syscall.args {
                    if !is_first {
                        write!(stdout, ", ");
                    }

                    write!(stdout, "{}=", arg.name);
                    is_first = false;

                    if arg.name == "buf" && arg.arg_type.is_const() && count.is_some() {
                        let ptr = regs.next().unwrap().read(cpu);
                        let count = count.unwrap();

                        if let Some(mem) = cpu.try_mem_read(ptr, count as usize) {
                            let escaped = mem
                                .into_iter()
                                .map(std::ascii::escape_default)
                                .flatten()
                                .collect::<Vec<u8>>();

                            let escaped = String::from_utf8(escaped).unwrap();

                            write!(stdout, "\"{}\"", escaped);

                            continue;
                        }
                    }
                    arg.arg_type.read_display(cpu, &mut stdout, &mut regs);
                }
                write!(stdout, ")");
                stdout.flush();
                //println!("{}(...) - {:?}", syscall.name, syscall.args);
            } else {
                println!("UNK_sys_{}(...)", callno);
            }
        });

        let last_callno = last_callno_exit;
        let last_handled = last_handled_exit;

        PppCallback::new().on_all_sys_return(move |cpu, _, callno| {
            if callno as u64 == last_callno.load(Ordering::SeqCst) {
                last_handled.store(true, Ordering::SeqCst);
                let ret_val = panda::regs::get_reg(cpu, SYSCALL_RET) as u32 as i32;
                if ret_val.is_negative() {
                    // error case
                    if let Some(name) = errno_name(ret_val) {
                        println!(" = {} ({})", ret_val, name);
                    } else {
                        println!(" = {}", ret_val);
                    }
                } else {
                    println!(" = {}", ret_val);
                }
            }
        });
    });

    true
}

fn errno_name(err: i32) -> Option<&'static str> {
    macro_rules! errnos {
        ($(
            #define $name:ident $num:literal
        )*) => {
            match err.abs() {
            $(
                $num => Some(stringify!($name)),

            )*
                _ => None,
            }
        }
    }

    errnos! {
        #define EPERM        1  /* Operation not permitted */
        #define ENOENT       2  /* No such file or directory */
        #define ESRCH        3  /* No such process */
        #define EINTR        4  /* Interrupted system call */
        #define EIO          5  /* I/O error */
        #define ENXIO        6  /* No such device or address */
        #define E2BIG        7  /* Argument list too long */
        #define ENOEXEC      8  /* Exec format error */
        #define EBADF        9  /* Bad file number */
        #define ECHILD      10  /* No child processes */
        #define EAGAIN      11  /* Try again */
        #define ENOMEM      12  /* Out of memory */
        #define EACCES      13  /* Permission denied */
        #define EFAULT      14  /* Bad address */
        #define ENOTBLK     15  /* Block device required */
        #define EBUSY       16  /* Device or resource busy */
        #define EEXIST      17  /* File exists */
        #define EXDEV       18  /* Cross-device link */
        #define ENODEV      19  /* No such device */
        #define ENOTDIR     20  /* Not a directory */
        #define EISDIR      21  /* Is a directory */
        #define EINVAL      22  /* Invalid argument */
        #define ENFILE      23  /* File table overflow */
        #define EMFILE      24  /* Too many open files */
        #define ENOTTY      25  /* Not a typewriter */
        #define ETXTBSY     26  /* Text file busy */
        #define EFBIG       27  /* File too large */
        #define ENOSPC      28  /* No space left on device */
        #define ESPIPE      29  /* Illegal seek */
        #define EROFS       30  /* Read-only file system */
        #define EMLINK      31  /* Too many links */
        #define EPIPE       32  /* Broken pipe */
        #define EDOM        33  /* Math argument out of domain of func */
        #define ERANGE      34  /* Math result not representable */
    }
}
