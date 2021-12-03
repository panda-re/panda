use panda::{
    prelude::*,
    regs::{
        get_reg, set_reg,
        Reg::{self, *},
    },
};

// =================== Register Order ===================
#[cfg(feature = "i386")]
pub const REG_ORDER: [Reg; 5] = [EAX, EBX, ECX, EDX, EDI];

#[cfg(feature = "x86_64")]
pub const REG_ORDER: [Reg; 5] = [RAX, RBX, RCX, RDX, RDI];

#[cfg(feature = "arm")]
pub const REG_ORDER: [Reg; 5] = [R0, R1, R2, R3, R4];

// =================== Return Value ===================
#[cfg(feature = "i386")]
pub const RET_REG: Reg = EAX;

#[cfg(feature = "x86_64")]
pub const RET_REG: Reg = RAX;

#[cfg(feature = "arm")]
pub const RET_REG: Reg = R0;

pub fn get_hyp_reg(cpu: &mut CPUState, num: usize) -> usize {
    let reg_to_read = REG_ORDER[num];
    get_reg(cpu, reg_to_read) as usize
}

pub fn set_hyp_ret_reg(cpu: &mut CPUState, value: usize) {
    set_reg(cpu, RET_REG, value as target_ulong)
}
