use panda::sys::{get_cpu, qemu_loglevel, CPUX86State};
use panda::{current_asid, current_pc, current_sp, PppCallback};
use panda::{
    mem::virtual_memory_read,
    mem::virtual_memory_write,
    plugins::osi::OSI,
    plugins::syscalls2::SYSCALLS,
    prelude::*,
    regs::Reg::*,
    syscall_injection::{run_injector, syscall},
};

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

async fn do_mmap() -> target_ulong {
    syscall(
        MMAP,
        (
            0u64,
            PAGE_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANON,
            NEG_1,
            NULL,
        ),
    )
    .await
}

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

const GETPID: target_ulong = 24;

fn read_2_bytes_at_pc(_cpu: &mut CPUState, pc: target_ulong) {
    let a = virtual_memory_read(_cpu, pc, 2).unwrap();
    println!("opcode@PC 0: {:x} 1: {:x}", a[0], a[1]);
}

const DUP: target_ulong = 32;
const DUP2: target_ulong = 63;
const MLOCK: target_ulong = 150;

#[panda::on_all_sys_enter]
fn on_sys_enter(_cpu: &mut CPUState, pc: SyscallPc, syscall_num: target_ulong) {
    if OSI.get_current_process(_cpu).get_name() != "cat" {
        return;
    }
    println!("Got syscall {}", syscall_num);
    println!(
        "SYSCALLS PC is {:x} CURRENT_PC is {:x}",
        pc.pc(),
        current_pc(_cpu)
    );
    read_2_bytes_at_pc(_cpu, pc.pc());
    let asid = current_asid(_cpu);
    let cpc = current_pc(_cpu);
    read_2_bytes_at_pc(_cpu, pc.pc());
    read_2_bytes_at_pc(_cpu, cpc);

    let file_data = ELF_TO_INJECT.get().unwrap();

    let sys_enter = PppCallback::new();
    let sys_return = PppCallback::new();

    run_injector(pc, async move {
        // unsafe {
        // qemu_loglevel |= 1 << 1;
        // }
        let cpu = unsafe { &mut *get_cpu() };
        // println!("current asid: {:x}", current_asid(cpu));
        // if ARGS.require_root {
        //     let is_root = syscall(GETPID, ()).await == 0 as target_ulong;
        //     if !is_root {

        //         SYSCALLS.add_callback_on_all_sys_enter(on_sys_enter);
        //         return;
        //     } else {
        //         println!("Got root!");

        //     }
        // }

        println!("In injector");
        println!("current asid: {:x}", current_asid(cpu));

        // let dupfd = syscall(DUP, (0u64,)).await;
        // let dupfd = syscall(DUP2, (0u64, 10u64)).await;
        // println!("got new FD {}", dupfd);
        // let round_address = 0x7fffffffe000u64;
        // let not_round = 0x00007fffffffeaa8u64;
        // let mlock_ret = syscall(MLOCK, (round_address, u64::MAX)).await;
        // println!("mlock_ret: {}", mlock_ret as i64);
        // only problematic in multi-cpu systems
        // mmap a region
        let mmap_addr = do_mmap().await;
        println!("Got mmap addr {:#x}", mmap_addr);
        println!("{}", mmap_addr as i64);
        println!("current asid: {:x}", current_asid(cpu));
        // zero it out
        // virtual_memory_write(cpu, mmap_addr, &[0u8; PAGE_SIZE as usize]);
        // let mmap_addr = panda::current_sp(cpu) + 0x1000;
        // virtual_memory_write(cpu, mmap_addr, &[0u8; 20]);
        let mem_fd = do_memfd_create(mmap_addr).await;
        println!("Got fd {:#x}", mem_fd);
        println!("{}", mmap_addr as i64);
        println!("current asid: {:x}", current_asid(cpu));
        loop {
            match ELF_READ_POS.fetch_add(PAGE_SIZE as usize, Ordering::SeqCst) {
                x if x < file_data.len() => {
                    let size =
                        min(PAGE_SIZE as isize, (file_data.len() - x) as isize);
                    println!(
                        "Writing {} bytes [{}-{}] total: {}...",
                        PAGE_SIZE,
                        x,
                        x + PAGE_SIZE as usize,
                        file_data.len()
                    );
                    println!("current asid: {:x}", current_asid(cpu));
                    virtual_memory_write(
                        cpu,
                        mmap_addr,
                        &file_data[x..x + size as usize],
                    );
                    do_write(mem_fd, mmap_addr, PAGE_SIZE).await;
                }
                _ => break,
            }
        }
        println!("forking...");
        panda::hook::start_block_exec(move |cpu, _, hook| {
            println!("RAX: {:x}", panda::regs::get_reg(cpu, RAX));
        })
        .at_addr(pc.pc() + 2);

        // let pid = syscall(GETPID, ()).await;
        // println!("PID is {}", pid);

        let fork_ret = do_fork().await;
        println!("fork ret {:x}", fork_ret);

        // let is_parent = fork_ret != 0 as target_ulong;
        // println!("is_parent is {}", is_parent);

        // // /proc/self/fd/#

        // let execbuf = [
        //     47u8,
        //     112,
        //     114,
        //     111,
        //     99,
        //     47,
        //     115,
        //     101,
        //     108,
        //     102,
        //     47,
        //     102,
        //     100,
        //     47,
        //     48 + mem_fd as u8,
        //     0,
        // ];
        // virtual_memory_write(cpu, mmap_addr, &execbuf);
        // println!("execve()");
        // let end_mmap_buf =
        //     mmap_addr as target_ulong + (execbuf.len() - 1) as target_ulong;
        // do_execve(mmap_addr, end_mmap_buf, end_mmap_buf).await;
        // println!("finished");
        // // // unsafe {
        // //     qemu_loglevel = 0;
        // }
    });

    // let r = unsafe { _cpu.env_ptr as *mut CPUX86State };
    // let HF_CS64_SHIFT: u64 = 15;
    // let HF_CS64_MASK = 1 << HF_CS64_SHIFT;

    // let syscall_addr = unsafe {
    //     // if HF_CS64_MASK & (*r).eflags != 0 {
    //     // println!("lstar");
    //     (*r).lstar
    //     // } else {
    //     //     println!("cstar");
    //     //     (*r).cstar
    //     // }
    // };

    // panda::hook::before_block_exec(move |cpu, _, hook| {
    //     if asid == current_asid(cpu) {
    //         println!("Hit PC for LSTAR {:x}", pc.pc());
    //         println!("RAX: {:x}", panda::regs::get_reg(cpu, RAX));
    //         println!("RDI: {:x}", panda::regs::get_reg(cpu, RDI));
    //         println!("RSI: {:x}", panda::regs::get_reg(cpu, RSI));
    //         println!("RDX: {:x}", panda::regs::get_reg(cpu, RDX));
    //         println!("RCX: {:x}", panda::regs::get_reg(cpu, RCX));
    //         println!("R8: {:x}", panda::regs::get_reg(cpu, R8));
    //         println!("R9: {:x}", panda::regs::get_reg(cpu, R9));
    //     }
    // })
    // .at_addr(syscall_addr);
    SYSCALLS.remove_callback_on_all_sys_enter(on_sys_enter);
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
