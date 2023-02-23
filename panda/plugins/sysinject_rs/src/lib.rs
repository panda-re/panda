use panda::prelude::*;
use panda::sys::cpu_loop_exit_restore;
use panda::{abi,regs,Callback};
use panda::mem::{virtual_memory_read, virtual_memory_write};
use std::slice;
use std::process::abort;

/// Inject a system call. Arguments are passed in as a raw array of target_ulong
#[no_mangle]
pub extern "C" fn inject_syscall(cpu: &mut CPUState, callno: target_ulong, nargs: usize, raw_args: *const target_ulong) {
    let args = unsafe { slice::from_raw_parts(raw_args, nargs) };

    //Back up all GPRs since we are doing this non-cooperatively
    let backed_up_regs: Vec<_> = regs::Reg::iter().map({|reg|
                                (reg,regs::get_reg(cpu,reg))}).collect();
    //Create a vector in case we have stack based arguments
    let mut backed_up_stack: Vec<(abi::StorageLocation, target_ulong)> = Vec::new();

    if nargs > abi::syscall::SYSCALL_ARGS_LEN {
        eprintln!("Too many syscall arguments: {}, maximum is: {} !", nargs, abi::syscall::SYSCALL_ARGS_LEN);
        abort();
    }

    //Setup syscall and state
    for i in 0..nargs {
        println!("inject_syscall arg {}: {:x}",i,args[i]);
        let arg = abi::syscall::SYSCALL_ARGS[i];
        if let abi::StorageLocation::StackOffset(_) = arg {
            backed_up_stack.push((arg,arg.read(cpu)));
        }
        arg.write(cpu,args[i]);
    }

    #[allow(unused_variables)]
        let orig_inst: Vec<u8>;

    #[cfg(any(feature = "arm", feature = "aarch64"))] {
        orig_inst = virtual_memory_read(cpu, regs::get_pc(cpu), 4)
            .expect("Failed to read original instruction");
    }
    regs::set_reg(cpu, abi::syscall::SYSCALL_NUM_REG, callno);

    //TODO will need to break out much of what follows here into separate 
    //functions to properly handle multiple architectures
    #[cfg(any(feature = "mips", feature = "mipsel", feature = "mips64"))] {
        cpu.exception_index = 17;
    }

    // Source: qemu/qemu/blob/master/target/arm/cpu.h line 38: #define EXCP_SWI 2
    // Have: exception index == 2 | syscall_nr == [correct]
    // Need: immediate value 0 to tell CPU the swi is a syscall
    #[cfg(any(feature = "arm", feature = "aarch64"))] {
        println!("Setting cpu exception index to 2");
        cpu.exception_index = 2;
        print!("[sysinject_rs] Original bytes:");
        for i in orig_inst.iter() {
            print!("0x{:x} ", i);
        }
        println!("");
        virtual_memory_write(cpu, regs::get_pc(cpu) - 4,  b"\x00\x00\x00\xef");
        let dummy_read = virtual_memory_read(cpu, regs::get_pc(cpu) - 4, 4).expect("Failed to read new instruction");
        print!("[sysinject_rs] Edited bytes:");
        for i in dummy_read.iter() {
            print!("0x{:x} ", i);
        }
        println!("");
        
    }

    #[cfg(feature = "i386")] {
        cpu.exception_index = 0x80;
    }

    let injected_asid = panda::current_asid(cpu);
    println!("Injected asid found");

    //Callback to detect when we return from the syscall so we can cleanup guest
    //state 
    let abe_callback = Callback::new();
        abe_callback.after_block_exec(move |cpu, _, _| {
            if (panda::current_asid(cpu) == injected_asid) && ! panda::in_kernel_mode(cpu) { 
                println!("BEGINNING OF CALLBACK");
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
                #[cfg(any(feature = "mips", feature = "mipsel", feature = "mips64"))] {
                    println!("resetting pc to {:x}", regs::get_pc(cpu)-4);
                    regs::set_pc(cpu, regs::get_pc(cpu)-4); //TODO arch-specific
                }
                #[cfg(any(feature = "arm", feature = "aarch64"))] {
                    println!("resetting pc to {:x}", regs::get_pc(cpu));
                    let dr = virtual_memory_read(cpu, regs::get_pc(cpu) - 4, 4).expect("Failed to read old new instruction");
                    print!("[sysinject_rs] Bytes before re-write:");
                    for i in dr.iter() {
                        print!("0x{:x} ", i);
                    }
                    println!("");
                    virtual_memory_write(cpu, regs::get_pc(cpu) - 4, &orig_inst);
                    let dr2 = virtual_memory_read(cpu, regs::get_pc(cpu) - 4, 4).expect("Failed to read new old instruction");
                    print!("[sysinject_rs] Bytes after re-write:");
                    for i in dr2.iter() {
                        print!("0x{:x} ", i);
                    }
                    println!("");
                    regs::set_pc(cpu, regs::get_pc(cpu));

                }
                //Disable callback
                abe_callback.disable();
            }
        });

    //TODO: we should implement a means of getting back to the caller after the syscall finishes
    println!("Doing the loop exit restore thing");
    unsafe { cpu_loop_exit_restore(cpu, regs::get_pc(cpu) as usize); }
    eprintln!("Got past cpu_loop_exit_restore"); //should be unreachable
    abort();
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    println!("Loaded sysinject");
    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Unloading sysinject");
}
