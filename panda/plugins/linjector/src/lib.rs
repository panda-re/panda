use panda::current_asid;
use panda::enums::MemRWStatus;
use panda::sys::get_cpu;
use panda::syscall_injection::{fork, syscall_no_return};
use panda::{
    mem::virtual_memory_write,
    plugins::osi::OSI,
    plugins::syscalls2::SYSCALLS,
    prelude::*,
    syscall_injection::{run_injector, syscall},
};

use once_cell::sync::OnceCell;

static ELF_TO_INJECT: OnceCell<Vec<u8>> = OnceCell::new();

#[derive(PandaArgs)]
#[name = "linjector"] // plugin name
struct Args {
    #[arg(default = "guest_daemon")]
    guest_binary: String,

    #[arg(default = "[any]")]
    proc_name: String,

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
const GETPID: target_ulong = 39;
const MMAP: target_ulong = 9;
const WRITE: target_ulong = 1;
const EXECVE: target_ulong = 59;
const MEMFD_CREATE: target_ulong = 319;

const NULL: target_ulong = 0;
const NEG_1: target_ulong = u32::MAX as target_ulong;
const PAGE_SIZE: target_ulong = 1024;

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
) -> target_long {
    syscall(WRITE, (mem_fd, mmap_addr, len)).await as target_long
}

async fn do_execve(
    path: target_ulong,
    argv: target_ulong,
    envp: target_ulong,
) -> target_ulong {
    syscall_no_return(EXECVE, (path, argv, envp)).await
}

async fn getpid() -> target_ulong {
    syscall(GETPID, ()).await
}

#[panda::on_all_sys_enter]
fn on_sys_enter(cpu: &mut CPUState, pc: SyscallPc, syscall_num: target_ulong) {
    if ARGS.proc_name != "[any]" {
        let proc = OSI.get_current_process(cpu);
        let proc_name = proc.get_name();
        if proc_name == ARGS.proc_name {
            log::trace!("Injecting into process {:?}", proc_name);
        } else {
            log::trace!("Not injecting into process {:?}", proc_name);
            return;
        }
    }

    log::trace!("Attempting injection into syscall {}", syscall_num);
    let file_data = ELF_TO_INJECT.get().unwrap();

    run_injector(pc, async move {
        let cpu = unsafe { &mut *get_cpu() };
        if ARGS.require_root {
            if getpid().await == 0 {
                log::debug!("Got root!");
            } else {
                // Set the injector back up for next syscall
                log::trace!("Not root, retrying next syscall...");
                SYSCALLS.add_callback_on_all_sys_enter(on_sys_enter);
                return;
            }
        }

        log::debug!("In injector");
        log::debug!("current asid: {:x}", current_asid(cpu));

        // mmap a region so we have a buffer in the guest to use
        let mmap_addr = do_mmap().await;
        log::debug!("Got mmap addr {:#x}", mmap_addr);

        if (mmap_addr as target_long).is_negative() {
            log::error!("linjector mmap error: {}", mmap_addr as target_long);
        }

        // Create a memory file descriptor for loading our binary into
        let mem_fd = do_memfd_create(mmap_addr).await;
        log::debug!("Got memory fd {:#x}", mem_fd);

        if (mem_fd as target_long).is_negative() {
            log::error!("linjector mem_fd error: {}", mem_fd as target_long);
        }

        // Write our file to our memory fd
        let mut elf_write_pos = 0;
        while elf_write_pos < file_data.len() {
            // Calculate max size to attempt to copy to our guest buffer
            let attempt_write_size =
                usize::min(PAGE_SIZE as usize, file_data.len() - elf_write_pos);

            // Calculate the end of the range we're attempting to copy
            let end_write = elf_write_pos + attempt_write_size;

            log::debug!(
                "Writing {} bytes [{}-{}]... (file len: {})",
                PAGE_SIZE,
                elf_write_pos,
                end_write,
                file_data.len(),
            );

            // Copy to guest buffer
            virtual_memory_write(
                cpu,
                mmap_addr,
                &file_data[elf_write_pos..end_write],
            );

            // Write guest buffer to memory file descriptor
            let written = do_write(mem_fd, mmap_addr, PAGE_SIZE).await;

            if written < 0 {
                log::error!("Write returned error {}", written);
            } else {
                elf_write_pos += written as usize;
            }
        }

        log::debug!("Finished writing to memfd");
        log::debug!("Forking...");

        // Fork and have the child process
        fork(async move {
            log::debug!("Child process began");
            // allow the child process to resume
        })
        .await;

        // everything here needs to be moved to the child process + daemonized
        {
            // Path should be "/proc/self/fd/#" where # is the memory file descriptor we
            // loaded our executable into,
            let path = format!("/proc/self/fd/{}", mem_fd);

            log::debug!("fd path: {:?}", path);

            // Add null terminator
            let mut path = path.into_bytes();
            path.push(0);

            log::debug!("Writing path to guest...");

            // Copy the path to the guest buffer we mmap'd
            let write_result = virtual_memory_write(cpu, mmap_addr, &path);

            if !matches!(write_result, MemRWStatus::MemTxOk) {
                log::error!("Write to guest status: {:?}", write_result);
            }

            // Execute the host binary
            log::debug!("Performing execve");
            do_execve(mmap_addr, 0, 0).await;
        }
    });

    SYSCALLS.remove_callback_on_all_sys_enter(on_sys_enter);
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    pretty_env_logger::init_custom_env("LINJECTOR_LOG");
    lazy_static::initialize(&ARGS);
    ELF_TO_INJECT.get_or_init(|| std::fs::read(&ARGS.guest_binary).unwrap());

    log::info!("linjector loaded");
    if ARGS.require_root {
        log::info!("linjector requiring root");
    } else {
        log::info!("linjector not requiring root");
    }

    log::info!("linjector loading binary {:?}", ARGS.guest_binary);

    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {}
