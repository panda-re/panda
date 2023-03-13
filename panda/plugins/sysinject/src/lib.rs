use panda::mem::{virtual_memory_read, virtual_memory_write};
use panda::prelude::*;
use panda::sys::cpu_loop_exit_restore;
use panda::{abi, regs, Callback};
use std::process::abort;
use std::slice;
use std::mem::transmute;

#[no_mangle]
pub extern "C" fn sys_access(
    cpu: &mut CPUState,
    //pathname: target_ulong,
    //mode: target_ulong,
    args: *const target_ulong,
) {
    //let args: *const target_ulong = unsafe {transmute([pathname, mode])};
    // sys_access syscall num is 4033 for mips
    #[cfg(feature = "mips")] {
        inject_syscall(cpu, 4033, 2, args);
    }

    // and 33 for arm/x86
    #[cfg(any(feature = "i386", feature = "arm"))] {
        inject_syscall(cpu, 33, 2, args);
    }
}

/// Inject a system call. Arguments are passed in as a raw array of target_ulong
#[no_mangle]
pub extern "C" fn inject_syscall(
    cpu: &mut CPUState,
    callno: target_ulong,
    nargs: usize,
    raw_args: *const target_ulong,
) {
    let mut args: Vec<target_ulong> = vec![];
    #[allow(unused_variables)]
    let mut instr_len: usize = 0;

    #[allow(unused_variables)]
    let mut prev_instr_len: usize = 0;

    #[allow(unused_variables)]
    let mut orig_addr: target_ulong = 0;

    let targs = unsafe { slice::from_raw_parts(raw_args, nargs) };
    args = targs.to_vec();

    // Separating out x86_64 argument parsing because instructions are not all length 4, and we pass that data in from outside
    // (because I didn't want to figure out capstone from the rust side, although that would be preferable)
    // We assume the first two arguments passed in are the length of the current instruction, and the length of the previous instruction.
    //#[cfg(feature = "x86_64")]
    //{
    //    let targs = unsafe { slice::from_raw_parts(raw_args, nargs + 2) };
    //    instr_len = targs[0] as usize;
    //    prev_instr_len = targs[1] as usize;
    //    args = targs[2..].to_vec();
    //}

    //Back up all GPRs since we are doing this non-cooperatively
    let backed_up_regs: Vec<_> = regs::Reg::iter()
        .map(|reg| (reg, regs::get_reg(cpu, reg)))
        .collect();
    //Create a vector in case we have stack based arguments
    let mut backed_up_stack: Vec<(abi::StorageLocation, target_ulong)> = Vec::new();

    if nargs > abi::syscall::SYSCALL_ARGS_LEN {
        eprintln!(
            "Too many syscall arguments: {}, maximum is: {} !",
            nargs,
            abi::syscall::SYSCALL_ARGS_LEN
        );
        abort();
    }

    //Setup syscall and state
    for i in 0..nargs {
        println!("inject_syscall arg {}: {:x}", i, args[i]);
        let arg = abi::syscall::SYSCALL_ARGS[i];
        if let abi::StorageLocation::StackOffset(_) = arg {
            backed_up_stack.push((arg, arg.read(cpu)));
        }
        arg.write(cpu, args[i]);
    }

    #[allow(unused_variables)]
    let orig_inst: Vec<u8>;

    #[cfg(any(feature = "arm", feature = "aarch64"))]
    {
        orig_inst = virtual_memory_read(cpu, regs::get_pc(cpu), 4)
            .expect("Failed to read original instruction");
    }

    // 64 bit support not ready yet, leaving this in incase we need to work on it later.
    // But as with arm, we need to overwrite instructions, since attempts to use the backwards
    // compatability of the int 0x80 method of syscall invocation has not worked for me
    // might be worth trying that again, though, incase I missed something
    //#[cfg(feature = "x86_64")] {
    //    orig_addr = regs::get_pc(cpu);
    //    //orig_addr = regs::get_pc(cpu) + (prev_instr_len as target_ulong);
    //    orig_inst = virtual_memory_read(cpu, orig_addr, instr_len)
    //        .expect("Failed to read original instruction");
    //}

    regs::set_reg(cpu, abi::syscall::SYSCALL_NUM_REG, callno);

    #[cfg(any(feature = "mips", feature = "mipsel", feature = "mips64"))]
    {
        cpu.exception_index = 17;
    }

    // Source: qemu/qemu/blob/master/target/arm/cpu.h line 38: #define EXCP_SWI 2
    // Have: exception index == 2 | syscall_nr == [correct]
    // Need: immediate value 0 to tell CPU the swi is a syscall
    #[cfg(any(feature = "arm", feature = "aarch64"))]
    {
        //println!("Setting cpu exception index to 2");
        cpu.exception_index = 2;
        virtual_memory_write(cpu, regs::get_pc(cpu) - 4, b"\x00\x00\x00\xef");
    }

    // i386 relies on `int 0x80` for syscalls, emulate that behavior here
    #[cfg(feature = "i386")]
    {
        println!("Setting exception 0x80\n");
        cpu.exception_index = 0x80;
    }

    //  64 bit not supported, leaving in incase we need to work on it in the future.
    //    #[cfg(feature = "x86_64")] {
    //        print!("[sysinject_rs] Original bytes:");
    //        for i in orig_inst.iter() {
    //            print!("0x{:x} ", i);
    //        }
    //        println!("");
    //        let mut new_instr = b"\x0f\x05".to_vec();
    //        for i in 0..instr_len-2 {
    //            new_instr = [new_instr.as_slice(), b"\x90".as_slice()].concat();
    //        }
    //        virtual_memory_write(cpu, orig_addr,  new_instr.as_slice());
    //        let dummy_read = virtual_memory_read(cpu, orig_addr, instr_len).expect("Failed to read new instruction");
    //        print!("[sysinject_rs] Edited bytes:");
    //        for i in dummy_read.iter() {
    //            print!("0x{:x} ", i);
    //        }
    //        println!("");
    //    }

    let injected_asid = panda::current_asid(cpu);

    //Callback to detect when we return from the syscall so we can cleanup guest
    //state
    let abe_callback = Callback::new();
    abe_callback.after_block_exec(move |cpu, _, _| {
        if panda::current_asid(cpu) == injected_asid {
            if !panda::in_kernel_mode(cpu) {
                //We are heading back to userland from our syscall, restore
                //state

                //Restore registers
                for (reg, value) in &backed_up_regs {
                    regs::set_reg(cpu, *reg, *value);
                }

                //Restore stack args if we had them
                for (loc, value) in &backed_up_stack {
                    loc.write(cpu, *value);
                }

                //We have to backup one instruction
                #[cfg(any(feature = "mips", feature = "mipsel", feature = "mips64"))]
                {
                    regs::set_pc(cpu, regs::get_pc(cpu) - 4);
                }

                // Do not need to back up any instructions in rust, but do need to re-write the original instruction back over the inserted syscall instruction
                #[cfg(any(feature = "arm", feature = "aarch64"))]
                {
                    virtual_memory_write(cpu, regs::get_pc(cpu) - 4, &orig_inst);
                }

                // Do not need to back up instructions, or otherwise handle anything for i386

                //    64 bit still not supported, see previous.
                //                #[cfg(feature = "x86_64")] {
                //                    println!("resetting pc to {:x}", regs::get_pc(cpu));
                //                    //let dr = virtual_memory_read(cpu, regs::get_pc(cpu) - (instr_len as target_ulong), instr_len).expect("Failed to read old new instruction");
                //                    let dr = virtual_memory_read(cpu, regs::get_pc(cpu), instr_len).expect("Failed to read old new instruction");
                //                    print!("[sysinject_rs] Bytes before re-write:");
                //                    for i in dr.iter() {
                //                        print!("0x{:x} ", i);
                //                    }
                //                    println!("");
                //                    virtual_memory_write(cpu, orig_addr, &orig_inst);
                //                    //let dr2 = virtual_memory_read(cpu, regs::get_pc(cpu) - (instr_len as target_ulong), instr_len).expect("Failed to read new old instruction");
                //                    let dr2 = virtual_memory_read(cpu, orig_addr, instr_len).expect("Failed to read new old instruction");
                //                    print!("[sysinject_rs] Bytes after re-write:");
                //                    for i in dr2.iter() {
                //                        print!("0x{:x} ", i);
                //                    }
                //                    //println!("[x86_64] Do not need to reset PC");
                //                    println!("Resetting PC to {:x}", orig_addr);
                //                    regs::set_pc(cpu, orig_addr);
                //
                //                }

                //Disable callback
                abe_callback.disable();
            }
        }
    });

    //TODO: we should implement a means of getting back to the caller after the syscall finishes
    unsafe {
        cpu_loop_exit_restore(cpu, (orig_addr as usize) - instr_len);
    }
    println!("Got past cpu_loop_exit_restore"); //should be unreachable
    abort();
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    #[cfg(any(feature = "x86_64", feature = "aarch64", feature = "mips64", feature = "mipsl"))]{
        return false;
    }
    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
}
