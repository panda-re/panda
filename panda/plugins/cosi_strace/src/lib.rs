use once_cell::sync::{Lazy, OnceCell};

use panda::{
    plugins::cosi::{self, OsiType},
    prelude::*,
};

#[cfg(not(feature = "ppc"))]
use panda::{
    abi::syscall::{SYSCALL_ARGS, SYSCALL_RET},
    plugins::syscalls2::Syscalls2Callbacks,
    PppCallback,
};
use std::{
    collections::HashMap,
    fs::File,
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

cosi::osi_static! {
    #[symbol = "syscalls_metadata"]
    static SYSCALLS_METADATA: target_ptr_t;
}

static SYSCALL_INFO: OnceCell<Vec<Option<SyscallInfo>>> = OnceCell::new();

#[derive(PandaArgs)]
#[name = "cosi_strace"]
struct Args {
    #[arg(default = "[no]")]
    dump_prototypes: String,
}

// Prototype differences:
//
// Different:
// * sys_clone - different arg order (CONFIG_CLONE_BACKWARDS)
// * sys_signalstack - `struct signalstack*` vs `stack_t*`
//
// Missing:
// * sys_ioperm
// * sys_sigreturn
// * sys_rt_signreturn
// * sys_mbind
// * sys_get_mempolicy
// * sys_set_mempolicy
// * sys_migrate_pages
// * sys_move_pages
// * All syscalls newer than 376 (sys_mlock2)

static ARGS: Lazy<Args> = Lazy::new(Args::from_panda_args);

#[cfg(feature = "ppc")]
#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    panic!("cosi_strace not supported from this architecture")
}

#[cfg(not(feature = "ppc"))]
#[panda::init]
#[allow(unused_must_use)]
fn init(_: &mut PluginHandle) -> bool {
    println!("Initializing cosi_strace");
    cosi::OSI2.ensure_init();
    Lazy::force(&ARGS);

    let first_bb = panda::Callback::new();

    first_bb.before_block_exec(move |cpu, _| {
        if SYSCALL_INFO.get().is_some() {
            first_bb.disable();
            return;
        }

        if !panda::in_kernel_mode(cpu) {
            return;
        }

        let mut proto_file = if ARGS.dump_prototypes != "[no]" {
            File::create(&ARGS.dump_prototypes)
                .map_err(|_| {
                    log::warn!("Prototypes file could not be created");
                })
                .ok()
        } else {
            None
        };

        let ptr_size = mem::size_of::<target_ptr_t>() as target_ptr_t;

        println!("Finding kaslr offset...");
        dbg!(cosi::kaslr_offset(cpu));

        let sys_call_table = cosi::symbol_addr_from_name("sys_call_table");
        let sys_ni_syscall = cosi::symbol_addr_from_name("sys_ni_syscall");

        let mut converted_types = HashMap::new();
        let mut syscall_info = vec![];

        let sys_meta_offset = cosi::symbol_addr_from_name("syscalls_metadata");
        let sys_meta_ptr_ptr = cosi::kaslr_offset(cpu) + sys_meta_offset;

        eprintln!("sys_meta_offset: {:#x?}", sys_meta_offset);
        eprintln!("sys_meta_ptr_ptr: {:#x?}", sys_meta_ptr_ptr);

        let ptr = SYSCALLS_METADATA.read(cpu).unwrap();

        let mut i = 0;

        loop {
            let current_syscall;
            if let Ok(ptr) = target_ptr_t::osi_read(cpu, ptr + (ptr_size * i)) {
                if ptr == 0 {
                    current_syscall = None;
                } else if let Ok(meta) = SyscallMetadata::osi_read(cpu, ptr) {
                    let name = cpu.mem_read_string(meta.name);

                    let mut args = Vec::with_capacity(meta.nb_args as usize);
                    let mut args_str = Vec::with_capacity(meta.nb_args as usize);
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

                        args_str.push(format!(
                            "{}{}{}",
                            arg_type.replace(" *", " __user *"),
                            if arg_type.contains(' ') && arg_type.ends_with('*') {
                                ""
                            } else {
                                " "
                            },
                            arg_name
                        ));

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
                    }

                    if let Some(f) = proto_file.as_mut() {
                        writeln!(
                            f,
                            "{} long {}({});",
                            meta.syscall_nr,
                            name,
                            if args_str.is_empty() {
                                "void".into()
                            } else {
                                args_str.join(", ")
                            }
                        )
                        .unwrap();
                    }

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
                    println!("metadata read fail {} @ {:#x?}", i, ptr);
                    current_syscall = None;
                }
            } else {
                println!("ptr read fail {}", i);
                current_syscall = None;
            }

            if current_syscall.is_none() {
                let this_syscall =
                    target_ptr_t::osi_read(cpu, sys_call_table + (i * ptr_size)).ok();
                let next_syscall =
                    target_ptr_t::osi_read(cpu, sys_call_table + ((i + 1) * ptr_size)).ok();

                if this_syscall != Some(sys_ni_syscall)
                    && target_ptr_t::osi_read(cpu, ptr + (ptr_size * (i + 1)))
                        .ok()
                        .map(|x| x == 0)
                        .unwrap_or(true)
                    && next_syscall != Some(sys_ni_syscall)
                {
                    break;
                }

                if let Some(f) = proto_file.as_mut() {
                    writeln!(
                        f,
                        "// no metadata for syscall {}{}",
                        i,
                        if this_syscall == Some(sys_ni_syscall) {
                            " (not implemented)"
                        } else {
                            ""
                        }
                    )
                    .unwrap();
                }
            }

            syscall_info.push(current_syscall);

            i += 1;
        }

        SYSCALL_INFO.set(syscall_info).unwrap();

        first_bb.disable();

        if proto_file.is_none() {
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
        }
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
