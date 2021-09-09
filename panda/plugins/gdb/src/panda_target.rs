use crate::{monitor_commands, target_state::{STATE, BreakStatus}};
use gdbstub::{
    target::{Target, TargetResult, TargetError, ext},
    target::ext::base::singlethread::{
        SingleThreadOps,
        StopReason,
        ResumeAction,
    },
    arch::Arch,
    outputln,
};

use panda::plugins::osi::OSI;

use std::convert::TryInto;

pub struct PandaTarget;

#[cfg(feature = "x86_64")]
use gdbstub_arch::x86::{X86_64_SSE as X86_64, reg::{X86_64CoreRegs, X86SegmentRegs, F80}};

#[cfg(feature = "i386")]
use gdbstub_arch::x86::{X86_SSE as X86, reg::{X86CoreRegs, F80, X86SegmentRegs}};

#[cfg(feature = "arm")]
use gdbstub_arch::arm::{Armv4t, reg::ArmCoreRegs};

//#[cfg(feature = "ppc")]
//use gdbstub_arch::ppc::{PowerPcAltivec32 as PowerPc, reg::{PowerPcCommonRegs as PowerPcCoreRegs}};

#[cfg(any(feature = "mips", feature = "mipsel"))]
use gdbstub_arch::mips::{Mips, reg::MipsCoreRegs};

#[cfg(not(any(feature = "aarch64", feature = "ppc")))]
impl Target for PandaTarget {
    #[cfg(feature = "x86_64")]
    type Arch = X86_64;
    
    #[cfg(feature = "i386")]
    type Arch = X86;
    
    #[cfg(feature = "arm")]
    type Arch = Armv4t;
    
    #[cfg(feature = "ppc")]
    type Arch = PowerPc;

    #[cfg(any(feature = "mips", feature = "mipsel"))]
    type Arch = Mips;

    type Error = ();

    fn base_ops(&mut self) -> ext::base::BaseOps<Self::Arch, Self::Error> {
        ext::base::BaseOps::SingleThread(
            self as _
        )
    }

    fn breakpoints(&mut self) -> Option<ext::breakpoints::BreakpointsOps<Self>> {
        Some(self as _)
    }

    fn monitor_cmd(&mut self) -> Option<ext::monitor_cmd::MonitorCmdOps<Self>> {
        Some(self as _)
    }

    fn section_offsets(&mut self) -> Option<ext::section_offsets::SectionOffsetsOps<Self>> {
        Some(self)
    }
}

// Implement the standard operations as a fake-single-thread target
impl SingleThreadOps for PandaTarget {
    fn resume(
        &mut self,
        action: ResumeAction,
        _check_gdb_interrupt: ext::base::GdbInterrupt<'_>,
    ) -> Result<StopReason<<Self::Arch as Arch>::Usize>, Self::Error> {
        match action {
            ResumeAction::Step => {
                STATE.start_single_stepping();
                STATE.cont.signal(());
                Ok(
                    match STATE.brk.wait_for() {
                        BreakStatus::Break => StopReason::DoneStep,
                        BreakStatus::Exit => StopReason::Exited(0),
                    }
                )
            }
            ResumeAction::Continue => {
                STATE.cont.signal(());
                Ok(
                    match STATE.brk.wait_for() {
                        BreakStatus::Break => StopReason::SwBreak,
                        BreakStatus::Exit => StopReason::Exited(0),
                    }
                )
            }
            _ => panic!("signals not supported")
        }
    }

    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {

        let cpu = STATE.wait_for_cpu();

        #[cfg(feature = "x86_64")] {
            let env = unsafe { &*(cpu.env_ptr as *const panda::sys::CPUX86State) };

            let segments: [u32; 6] = (&env.segs.iter().map(|seg| seg.base as u32)
                .collect::<Vec<_>>()[..6])
                .try_into()
                .unwrap();

            let segments = X86SegmentRegs {
                cs: segments[0],
                ss: segments[1],
                ds: segments[2],
                es: segments[3],
                fs: segments[4],
                gs: segments[5],
            };

            *regs = X86_64CoreRegs {
                eflags: env.eflags as _,
                regs: (*env).regs.clone(),
                rip: STATE.get_pc(),
                segments,
                st: (&env.fpregs.iter().map(fpreg_to_bytes).collect::<Vec<_>>()[..8]).try_into().unwrap(),
                xmm: (&env.xmm_regs.iter().map(zmm_to_xmm).collect::<Vec<_>>()[..16]).try_into().unwrap(),
                mxcsr: env.mxcsr,
                ..Default::default()
            };
        }
        
        #[cfg(feature = "i386")] {
            let env = unsafe { &*(cpu.env_ptr as *const panda::sys::CPUX86State) };

            use panda::sys::{R_EAX, R_EBX, R_ECX, R_EDX, R_ESP, R_EBP, R_ESI, R_EDI};

            let segments: [u32; 6] = (&env.segs.iter().map(|seg| seg.base as u32)
                .collect::<Vec<_>>()[..6])
                .try_into()
                .unwrap();

            let segments = X86SegmentRegs {
                cs: segments[0],
                ss: segments[1],
                ds: segments[2],
                es: segments[3],
                fs: segments[4],
                gs: segments[5],
            };

            *regs = X86CoreRegs {
                eflags: env.eflags,
                eax: env.regs[R_EAX as usize],
                ebx: env.regs[R_EBX as usize],
                ecx: env.regs[R_ECX as usize],
                edx: env.regs[R_EDX as usize],
                esp: env.regs[R_ESP as usize],
                ebp: env.regs[R_EBP as usize],
                esi: env.regs[R_ESI as usize],
                edi: env.regs[R_EDI as usize],
                eip: STATE.get_pc(),
                segments,
                st: (&(*env).fpregs.iter().map(fpreg_to_bytes).collect::<Vec<_>>()[..8]).try_into().unwrap(),
                xmm: (&(*env).xmm_regs.iter().map(zmm_to_xmm).collect::<Vec<_>>()[..8]).try_into().unwrap(),
                mxcsr: (*env).mxcsr,
                ..Default::default()
            };
        }
        
        #[cfg(feature = "arm")] {
            let env = unsafe { &*(cpu.env_ptr as *const panda::sys::CPUARMState) };

            *regs = ArmCoreRegs {
                r: env.regs[0..13].try_into().unwrap(),
                sp: env.regs[13],
                lr: env.regs[14],
                pc: STATE.get_pc(),
                cpsr: env.uncached_cpsr,
                ..Default::default()
            };
        }

        #[cfg(feature = "ppc")] {

        }
        
        #[cfg(any(feature = "mips", feature = "mipsel"))] {
            let env = unsafe { &*(cpu.env_ptr as *const panda::sys::CPUMIPSState) };

            regs.r = env.active_tc.gpr;
            regs.lo = env.active_tc.LO[0];
            regs.hi = env.active_tc.HI[0];
            regs.pc = STATE.get_pc();
            regs.cp0.status = env.CP0_Status as _;
            regs.cp0.badvaddr = env.CP0_BadVAddr as _;
            regs.cp0.cause = env.CP0_Cause as _;
            // TODO: fpu
        }

        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        let cpu = STATE.wait_for_cpu();

        #[cfg(feature = "x86_64")] {
            let env = cpu.env_ptr as *mut panda::sys::CPUX86State;

            unsafe {
                (*env).regs = regs.regs.clone();
                (*env).eip = regs.rip;
                (*env).mxcsr = regs.mxcsr;
            }
        }
        #[cfg(feature = "arm")] {
            let env = unsafe { &mut *(cpu.env_ptr as *mut panda::sys::CPUARMState) };
            
            for i in 0..13 {
                env.regs[i] = regs.r[i];
            }
            env.regs[13] = regs.sp;
            env.regs[14] = regs.lr;
            env.regs[15] = regs.pc;
            env.uncached_cpsr = regs.cpsr;
        }
        #[cfg(feature = "i386")] {
            let env = unsafe { &mut *(cpu.env_ptr as *mut panda::sys::CPUX86State) };

            use panda::sys::{R_EAX, R_EBX, R_ECX, R_EDX, R_ESP, R_EBP, R_ESI, R_EDI};

            for &(i, val) in &[
                (R_EAX, regs.eax),
                (R_EBX, regs.ebx),
                (R_ECX, regs.ecx),
                (R_EDX, regs.edx),
                (R_ESP, regs.esp),
                (R_EBP, regs.ebp),
                (R_ESI, regs.esi),
                (R_EDI, regs.edi),
            ] {
                env.regs[i as usize] = val;
            }

            env.eflags = regs.eflags;
            STATE.set_pc(regs.eip);
        }

        Ok(())
    }

    fn read_addrs(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        out: &mut [u8]
    ) -> TargetResult<(), Self> {
        let cpu = STATE.wait_for_cpu();

        if let Some(mem) = cpu.try_mem_read(addr, out.len()) {
            out.clone_from_slice(&mem);
            Ok(())
        } else {
            Err(TargetError::NonFatal)
        }
    }

    fn write_addrs(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
         let cpu = STATE.wait_for_cpu();

         cpu.mem_write(addr, data);

         Ok(())
    }
}

// Breakpoints: just say we implement software breakpoints
impl ext::breakpoints::Breakpoints for PandaTarget {
    fn sw_breakpoint(&mut self) -> Option<ext::breakpoints::SwBreakpointOps<'_, Self>> {
        Some(self as _)
    }
}

// Software breakpoints
impl ext::breakpoints::SwBreakpoint for PandaTarget {
    fn add_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind
    ) -> TargetResult<bool, Self> {
        Ok(STATE.add_breakpoint(addr))
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind
    ) -> TargetResult<bool, Self> {
        Ok(STATE.remove_breakpoint(addr))
    }
}

impl ext::monitor_cmd::MonitorCmd for PandaTarget {
    fn handle_monitor_cmd(
        &mut self,
        cmd: &[u8],
        mut out: ext::monitor_cmd::ConsoleOutput<'_>
    ) -> Result<(), Self::Error> {
        if let Ok(cmd) = std::str::from_utf8(cmd) {
            let cpu = STATE.wait_for_cpu();
            monitor_commands::handle_command(cmd, cpu, out);
        } else {
            outputln!(out, "Command must be valid UTF-8");
        }

        Ok(())
    }
}

impl ext::section_offsets::SectionOffsets for PandaTarget {
    fn get_section_offsets(&mut self) -> Result<ext::section_offsets::Offsets<<Self::Arch as Arch>::Usize>, Self::Error> {
        let cpu = STATE.wait_for_cpu();
        let mut process = OSI.get_current_process(cpu);
        let mappings = OSI.get_mappings(cpu, &mut *process);
        if mappings.len() >= 3 {
            let text = &mappings[0];
            let data = &mappings[1];
            let bss = &mappings[2];
            Ok(ext::section_offsets::Offsets::Sections {
                text: text.base,
                data: data.base,
                bss: Some(bss.base),
            })
        } else {
            Err(())
        }
    }
}

#[cfg(any(feature = "x86_64", feature = "i386"))]
fn fpreg_to_bytes(x: &panda::sys::FPReg) -> F80 {
    unsafe {
        std::mem::transmute_copy(x)
    }
}

#[cfg(any(feature = "x86_64", feature = "i386"))]
fn zmm_to_xmm(x: &panda::sys::ZMMReg) -> u128 {
    unsafe {
        std::mem::transmute_copy(x)
    }
}
