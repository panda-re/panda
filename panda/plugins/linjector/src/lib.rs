#![feature(generators, generator_trait)]
use panda::sys::{get_cpu, qemu_loglevel, CPUX86State};
use panda::syscall_injection::{fork, run_injector_next_syscall};
use panda::{current_asid, current_pc, current_sp, Callback, PppCallback};
use panda::{
    mem::virtual_memory_read,
    mem::virtual_memory_write,
    plugins::osi::OSI,
    plugins::syscalls2::SYSCALLS,
    prelude::*,
    regs::Reg::*,
    syscall_injection::{run_injector, syscall, syscall_regs::SyscallRegs},
};

use std::ops::Generator;
use std::pin::Pin;
use std::{
    cmp::min,
    sync::atomic::{AtomicUsize, Ordering},
};

use once_cell::sync::OnceCell;

static ELF_TO_INJECT: OnceCell<Vec<u8>> = OnceCell::new();
static ELF_READ_POS: AtomicUsize = AtomicUsize::new(0);

#[derive(PandaArgs)]
#[name = "linjector"] // plugin name
struct Args {
    #[arg(default = "guest_daemon")]
    guest_binary: String,
    #[arg(default = true)]
    require_root: bool,
}

lazy_static::lazy_static! {
    static ref ARGS: Args = Args::from_panda_args();
}

// i386
// const MMAP2: target_ulong = 192;
// const WRITE: target_ulong = 4;
// const FORK: target_ulong = 2;
// const EXECVE: target_ulong = 11;
// const MEMFD_CREATE: target_ulong = 356;
// x86_64
const MMAP: target_ulong = 9;
const WRITE: target_ulong = 1;
const FORK: target_ulong = 57;
const EXECVE: target_ulong = 59;
const MEMFD_CREATE: target_ulong = 319;

const NULL: target_ulong = 0;
const NEG_1: target_ulong = u32::MAX as target_ulong;
const PAGE_SIZE: target_ulong = 1024;
// const PROT_READ: target_ulong = 0x1; /* Page can be read.  */
// const PROT_WRITE: target_ulong = 0x2; /* Page can be written.  */
// const PROT_EXEC: target_ulong = 0x4; /* Page can be executed.  */
//const MAP_SHARED: target_ulong = 0x1;
//const MAP_ANON: target_ulong = 0x20;
//const MAP_PRIVATE: target_ulong = 0x2;
// andrew's script values
const PROT_READ: target_ulong = 4;
const PROT_WRITE: target_ulong = 2;
const MAP_ANON: target_ulong = 0x20;
const MAP_SHARED: target_ulong = 0x2;

const GETPID: target_ulong = 24;

const DUP: target_ulong = 32;
const DUP2: target_ulong = 63;
const MLOCK: target_ulong = 150;

// async fn do_mmap() -> target_ulong {
//     (
//         MMAP,
//         (
//             0u64,
//             PAGE_SIZE,
//             PROT_READ | PROT_WRITE,
//             MAP_SHARED | MAP_ANON,
//             NEG_1,
//             NULL,
//         ),
//     )
// }

const MFD_CLOEXEC: target_ulong = 1;

async fn do_memfd_create(mmap_addr: target_ulong) -> target_ulong {
    // we use the mmap_addr for the name because we've zeroed it
    // so it will be a '\0' literal name
    syscall(MEMFD_CREATE, (mmap_addr, MFD_CLOEXEC)).await
}

async fn do_write(
    mem_fd: target_ulong,
    mmap_addr: target_ulong,
    len: target_ulong,
) -> target_ulong {
    syscall(WRITE, (mem_fd, mmap_addr, len)).await
}

async fn do_fork() -> target_ulong {
    syscall(FORK, ()).await
}

async fn do_execve(
    path: target_ulong,
    argv: target_ulong,
    envp: target_ulong,
) -> target_ulong {
    syscall(EXECVE, (path, argv, envp)).await
}

// fn setup_sys_return_handler(
//     pc: target_ulong,
//     asid: target_ulong,
//     gen: Pin<&mut || -> (u64, (u64, u64, u64, u64, u64, u64))>,
// ) {
//     let sys_return = PppCallback::new();
//     let saved_regs = Vec::new();
//     let syscall_regs: OnceCell<SyscallRegs> = OnceCell::new();
//     sys_return.on_all_sys_return(move |cpu: &mut CPUState, pc, num| {
//         if asid != current_asid(cpu) {
//             return;
//         }
//         let saved_regs = syscall_regs.get_or_init(|| SyscallRegs::backup());
//         if let GneratorState::Yielded(n) = gen.resume(){

//         }
//     });
// }

#[panda::on_all_sys_enter]
fn initial_sys_enter(
    cpu: &mut CPUState,
    pc: SyscallPc,
    syscall_num: target_ulong,
) {
    let sys_enter_pc = pc.pc();
    let mut do_parent_syscall_handling = || {
        // yield do_mmap();
        return (0u64, (0u64, 0u64, 0u64, 0u64, 0u64, 0u64));
    };
    let asid = current_asid(cpu);
    let a = Pin::new(&mut do_parent_syscall_handling);
    // setup_sys_return_handler(sys_enter_pc, asid, a);
    SYSCALLS.remove_callback_on_all_sys_enter(initial_sys_enter);
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    println!("linjector asdf hit");
    lazy_static::initialize(&ARGS);
    ELF_TO_INJECT.get_or_init(|| std::fs::read(&ARGS.guest_binary).unwrap());
    println!("got args {} {}", ARGS.guest_binary, ARGS.require_root);
    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {}
