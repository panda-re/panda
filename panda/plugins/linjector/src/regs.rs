use panda::regs::Reg;

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
