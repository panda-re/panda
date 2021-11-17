use panda::current_asid;
use panda::sys::get_cpu;
use panda::{
    mem::virtual_memory_write,
    plugins::syscalls2::SYSCALLS,
    prelude::*,
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

const MMAP2: target_ulong = 192;
const NULL: target_ulong = 0;
const NEG_1: target_ulong = target_ulong::MAX;
const PAGE_SIZE: target_ulong = 0x1000;
const PROT_READ: target_ulong = 0x1; /* Page can be read.  */
const PROT_WRITE: target_ulong = 0x2; /* Page can be written.  */
const PROT_EXEC: target_ulong = 0x4; /* Page can be executed.  */
const MAP_SHARED: target_ulong = 0x1;
const MAP_ANON: target_ulong = 0x20;

async fn do_mmap() -> target_ulong {
    syscall(
        MMAP2,
        (
            NULL,
            PAGE_SIZE,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_SHARED | MAP_ANON,
            NEG_1,
            NULL,
        ),
    )
    .await
}

const MEMFD_CREATE: target_ulong = 356;
const MFD_CLOEXEC: target_ulong = 1;

async fn do_memfd_create(mmap_addr: target_ulong) -> target_ulong {
    // we use the mmap_addr for the name because we've zeroed it
    // so it will be a '\0' litera,l name
    syscall(MEMFD_CREATE, (mmap_addr, MFD_CLOEXEC)).await
}

const WRITE: target_ulong = 4;

async fn do_write(
    mem_fd: target_ulong,
    mmap_addr: target_ulong,
    len: target_ulong,
) -> target_ulong {
    syscall(WRITE, (mem_fd, mmap_addr, len)).await
}

const FORK: target_ulong = 2;

async fn do_fork() -> target_ulong {
    syscall(FORK, ()).await
}

const EXECVE: target_ulong = 11;

async fn do_execve(
    path: target_ulong,
    argv: target_ulong,
    envp: target_ulong,
) -> target_ulong {
    syscall(EXECVE, (path, argv, envp)).await
}

#[panda::on_all_sys_enter]
fn on_sys_enter(
    _cpu: &mut CPUState,
    pc: SyscallPc,
    _syscall_num: target_ulong,
) {
    let file_data = ELF_TO_INJECT.get().unwrap();
    run_injector(pc, async move {
        if ARGS.require_root {
            let is_root = syscall(24, ()).await == 0 as target_ulong;
            if !is_root {
                SYSCALLS.add_callback_on_all_sys_enter(on_sys_enter);
                return;
            }
        }
        let cpu = unsafe { &mut *get_cpu() };
        println!("In injector");
        println!("current asid: {:x}", current_asid(cpu));
        // only problematic in multi-cpu systems
        // mmap a region
        let mmap_addr = do_mmap().await;
        println!("Got mmap addr {:#x}", mmap_addr);
        println!("current asid: {:x}", current_asid(cpu));
        // zero it out
        virtual_memory_write(cpu, mmap_addr, &[0u8; PAGE_SIZE as usize]);
        let mem_fd = do_memfd_create(mmap_addr).await;
        println!("Got fd {:#x}", mem_fd);
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

        let is_parent = do_fork().await == 0 as target_ulong;
        println!("is_parent is {}", is_parent);

        let execbuf = [
            47u8,
            112,
            114,
            111,
            99,
            47,
            115,
            101,
            108,
            102,
            47,
            102,
            100,
            47,
            48 + mem_fd as u8,
            0,
        ];
        virtual_memory_write(cpu, mmap_addr, &execbuf);
        println!("execve()");
        let end_mmap_buf =
            mmap_addr as target_ulong + (execbuf.len() - 1) as target_ulong;
        do_execve(mmap_addr, end_mmap_buf, end_mmap_buf).await;
        println!("finished");
    });
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
