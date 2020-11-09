#!/usr/bin/env python3

from pandare import Panda, ffi
import capstone
import keystone
import os

ADDRESS = 0x1000
BFC_ADDRESS = 0x1fc00000 # 0xbfc00000 -> page masked
SYSCALL_ADDRESS = BFC_ADDRESS+ 0x380


BFC_THING = f"""
#mfc0 $k0, $14

#addiu $k0, 4
eret
#jr $k0
#j {SYSCALL_ADDRESS}
""".encode()

SYSCALL_HANDLER = f"""
mfc0 $k0, $14
eret
jr $k0

#Loop: lw $t1, 0x1000
#    j {BFC_ADDRESS}
""".encode()

CODE = f"""
#lw $t1, {SYSCALL_ADDRESS}
#mtc0 $t1, $8
addiu $t0, 1  # $t0++
j .mid
nop

.mid:
li  $t1, 2    # t1 = 2
j .end
nop

.end:
addiu $t1, 1  # t1++
#j {SYSCALL_ADDRESS}
syscall
""".encode()

ks = keystone.Ks(keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32)
#ks = keystone.Ks(keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

encoding, count = ks.asm(CODE, ADDRESS)
syscall_encoding, syscall_count = ks.asm(SYSCALL_HANDLER, SYSCALL_ADDRESS)
bfc_encoding, bfc_count = ks.asm(BFC_THING, BFC_ADDRESS)

stop_addr = ADDRESS + len(encoding)

panda = Panda("mipsel",
        extra_args=["-M", "configurable", "-nographic", "-d", "cpu_reset,mmu"])# "-s", "-S"])
        #raw_monitor=True) # Allows for a user to ctrl-a + c then type quit if things go wrong

ffi.cdef("""
enum mips_excn {
    EXCP_NONE          = -1,
    EXCP_RESET         = 0,
    EXCP_SRESET,
    EXCP_DSS,
    EXCP_DINT,
    EXCP_DDBL,
    EXCP_DDBS,
    EXCP_NMI,
    EXCP_MCHECK,
    EXCP_EXT_INTERRUPT, /* 8 */
    EXCP_DFWATCH,
    EXCP_DIB,
    EXCP_IWATCH,
    EXCP_AdEL,
    EXCP_AdES,
    EXCP_TLBF,
    EXCP_IBE,
    EXCP_DBp, /* 16 */
    EXCP_SYSCALL,
    EXCP_BREAK,
    EXCP_CpU,
    EXCP_RI,
    EXCP_OVERFLOW,
    EXCP_TRAP,
    EXCP_FPE,
    EXCP_DWATCH, /* 24 */
    EXCP_LTLBL,
    EXCP_TLBL,
    EXCP_TLBS,
    EXCP_DBE,
    EXCP_THREAD,
    EXCP_MDMX,
    EXCP_C2E,
    EXCP_CACHE, /* 32 */
    EXCP_DSPDIS,
    EXCP_MSADIS,
    EXCP_MSAFPE,
    EXCP_TLBXI,
    EXCP_TLBRI,

    EXCP_LAST = EXCP_TLBRI,
};
        """)

@panda.cb_before_handle_exception
def before_handle_exception(cpu, exn_index):
    exn = ffi.string(ffi.cast("enum mips_excn", exn_index))
    print(f"got before handle exception {panda.current_pc(cpu):x} {exn}")
    print(f"K0 {cpu.env_ptr.active_tc.gpr[panda.arch.registers['K0']]:x}")
    print(f"error epc: {cpu.env_ptr.CP0_EPC:x}")
    from time import sleep
    sleep(3)
    return 0

@panda.cb_after_machine_init
def setup(cpu):
    '''
    After our CPU has been created, allocate memory and set starting state
    '''
    # map 2MB memory for this emulation
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)

    # Write code into memory
    panda.physical_memory_write(ADDRESS, bytes(encoding))
    
    # map 2MB memory for this emulation
    #cpu.env_ptr.exception_base = 0x20000
    panda.map_memory("syscall", 2* 1024 * 1024, BFC_ADDRESS )
    assert panda.physical_memory_write(BFC_ADDRESS, bytes(bfc_encoding)) == 0

    # Write code into memory
    assert panda.physical_memory_write(SYSCALL_ADDRESS, bytes(syscall_encoding)) == 0

    # Set up registers
    cpu.env_ptr.active_tc.gpr[panda.arch.registers['T0']] = 0x10

    # Set starting_pc
    cpu.env_ptr.active_tc.PC = ADDRESS
    MIPS_HFLAG_M16 = 0x00400
    cpu.env_ptr.hflags &= MIPS_HFLAG_M16
    cpu.env_ptr.CP0_Status =  0xfffd
    import ipdb
    ipdb.set_trace()


@panda.cb_before_block_exec
def bbe(cpu, tb):
    print(hex(panda.current_pc(cpu)))

# Always run insn_exec
panda.cb_insn_translate(lambda x,y: True)

md = capstone.Cs(capstone.CS_ARCH_MIPS, 4) # misp32
count = 0
@panda.cb_insn_exec
def on_insn(cpu, pc):
    '''
    At each instruction, print capstone disassembly.
    '''
    global count
    count += 1
    #if pc >= stop_addr:
    if count > 100:
        print("Finished execution")
        #dump_regs(panda, cpu)
        print("Register t0 contains:", hex(cpu.env_ptr.active_tc.gpr[panda.arch.registers['T0']]))
        print("Register t1 contains:", hex(cpu.env_ptr.active_tc.gpr[panda.arch.registers['T1']]))
        #raise Exception()
        #panda.end_analysis()
        os._exit(0) # TODO: we need a better way to stop here

    code = panda.virtual_memory_read(cpu, pc, 12)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

# Start PANDA running. Callback functions will be called as necessary
panda.run()
