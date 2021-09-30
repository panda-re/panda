use panda::{
    prelude::*,
    regs::{get_reg, set_reg, Reg},
};

// =================== Register Order ===================
#[cfg(feature = "i386")]
pub const REG_ORDER: [Reg; 4] = [Reg::EAX, Reg::EBX, Reg::ECX, Reg::EDX];

// XXX: is this right?
#[cfg(feature = "x86_64")]
pub const REG_ORDER: [Reg; 4] = [Reg::RAX, Reg::RBX, Reg::RCX, Reg::RDX];

// =================== Return Value ===================
#[cfg(feature = "i386")]
pub const RET_REG: Reg = Reg::EAX;

#[cfg(feature = "x86_64")]
pub const RET_REG: Reg = Reg::RAX;

pub fn get_hyp_reg(cpu: &mut CPUState, num: usize) -> usize {
    let reg_to_read = REG_ORDER[num];
    get_reg(cpu, reg_to_read) as usize
}

pub fn set_hyp_reg(cpu: &mut CPUState, num: usize, value: usize) {
    let reg_to_write = REG_ORDER[num];
    set_reg(cpu, reg_to_write, value as target_ulong)
}
