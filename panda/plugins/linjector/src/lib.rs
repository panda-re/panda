use panda::{
    current_asid,
    enums::MemRWStatus,
    mem::virtual_memory_write,
    plugins::osi::OSI,
    plugins::syscalls2::SYSCALLS,
    prelude::*,
    sys::get_cpu,
    syscall_injection::{fork, run_injector},
};

mod args;
mod syscalls;

use syscalls::{
    chdir, do_execve, do_memfd_create, do_mmap, do_write, getpid, setsid,
    PAGE_SIZE,
};

/// mmap a buffer and ensure it's paged in, then return the address to it
async fn get_guest_buffer() -> target_ptr_t {
    // mmap in a new page
    let mmap_addr = do_mmap().await;
    log::debug!("mmap addr {:#x}", mmap_addr);

    if (mmap_addr as target_long).is_negative() {
        log::error!("linjector mmap error: {}", mmap_addr as target_long);
    }

    // Ensure the page is mapped in
    let chdir_return = chdir(mmap_addr).await;
    log::debug!("Chdir return: {:#x}", chdir_return);

    mmap_addr as target_ptr_t
}

fn current_process_name(cpu: &mut CPUState) -> String {
    let proc = OSI.get_current_process(cpu);
    proc.get_name().into_owned()
}

#[panda::on_all_sys_enter]
fn on_sys_enter(cpu: &mut CPUState, pc: SyscallPc, syscall_num: target_ulong) {
    // Only check process name when a target process name is provided
    if args::proc_name() != "[any]" {
        let proc_name = current_process_name(cpu);

        // Only inject into this process if the process matches the provided name
        if proc_name == args::proc_name() {
            log::trace!("Injecting into process {:?}", proc_name);
        } else {
            log::trace!("Not injecting into process {:?}", proc_name);
            return;
        }
    }

    log::trace!("Attempting injection into syscall {}", syscall_num);
    let file_data = args::elf_to_inject();

    // Inject our syscall chain into the current system call. This injector
    // copies our ELF to a memory file descriptor then forks and runs it as
    // a daemon process.
    run_injector(pc, async move {
        let cpu = unsafe { &mut *get_cpu() };
        if args::require_root() {
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
        let guest_buf = get_guest_buffer().await;

        // Create a memory file descriptor for loading our binary into
        let mem_fd = do_memfd_create(guest_buf).await;
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
                guest_buf,
                &file_data[elf_write_pos..end_write],
            );

            // Write guest buffer to memory file descriptor
            let written = do_write(mem_fd, guest_buf, PAGE_SIZE).await;

            if written < 0 {
                log::error!("Write returned error {}", written);
            } else {
                elf_write_pos += written as usize;
            }
        }

        log::debug!("Finished writing to memfd");
        log::debug!("Forking...");

        // Fork and have the child process spawn the injected elf
        fork(async move {
            log::debug!("Child process began");

            // Daemonize child process
            let session_id = setsid().await;
            log::debug!("Session id: {:#x}", session_id);

            // Get a new buffer for writing the path to our memfd
            let guest_path_buf = get_guest_buffer().await;

            // Path should be "/proc/self/fd/#" where # is the memory file descriptor we
            // loaded our executable into,
            let path = format!("/proc/self/fd/{}", mem_fd);
            log::debug!("fd path: {:?}", path);

            // Convert to bytes and add null terminator
            let mut path = path.into_bytes();
            path.push(0);

            // Copy the path to the guest buffer we mmap'd
            log::debug!("Writing path to guest...");
            let write_result = virtual_memory_write(cpu, guest_path_buf, &path);

            if !matches!(write_result, MemRWStatus::MemTxOk) {
                log::error!("Write to guest status: {:?}", write_result);
            }

            // Execute the host binary
            log::debug!("Performing execve");
            do_execve(guest_path_buf, 0, 0).await;
        })
        .await;

        // Allow the original process to resume executing
    });

    // Once we inject to a process stop looking for syscalls to inject into
    SYSCALLS.remove_callback_on_all_sys_enter(on_sys_enter);
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    args::ensure_init();

    pretty_env_logger::init_custom_env("LINJECTOR_LOG");
    args::load_elf();

    log::info!("linjector loaded");
    if args::require_root() {
        log::info!("linjector requiring root");
    } else {
        log::info!("linjector not requiring root");
    }

    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {}
