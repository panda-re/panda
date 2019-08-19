
#ifndef __PRI_DWARF_UTIL_H
#define __PRI_DWARF_UTIL_H

#include <libdwarf/libdwarf.h>
#include "panda/plugin.h"
#include <libdwarf/dwarf.h>
#include "pri/pri_types.h"


/*
uint32_t guest_strncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr) {
    buf[0] = 0;
    unsigned i;
    for (i=0; i<maxlen; i++) {
        uint8_t c;
        panda_virtual_memory_rw(cpu, guest_addr+i, &c, 1, 0);
        buf[i] = c;
        if (c==0) {
            break;
        }
    }
    buf[maxlen-1] = 0;
    return i;
}
*/

// util functions to read DW_OP char array
const unsigned char *
read_uleb128 (const unsigned char *p, target_ulong *val)
{
    unsigned int shift = 0;
    unsigned char byte;
    target_ulong result;

    result = 0;
    do
    {
        byte = *p++;
        result |= (byte & 0x7f) << shift;
        shift += 7;
    }
    while (byte & 0x80);

    *val = result;
    return p;
}

/* Similar, but read a signed leb128 value.  */

    const unsigned char *
read_sleb128 (const unsigned char *p, target_long *val)
{
    unsigned int shift = 0;
    unsigned char byte;
    target_ulong result;

    result = 0;
    do
    {
        byte = *p++;
        result |= (byte & 0x7f) << shift;
        shift += 7;
    }
    while (byte & 0x80);

    /* Sign-extend a negative value.  */
    if (shift < 8 * sizeof(result) && (byte & 0x40) != 0)
        result |= -(1L << shift);

    *val = (target_long) result;
    return p;
}



/* util functions for execute_stack_op that basically facilitate reading from memory */
union unaligned
{
    void *p;
    unsigned u2 __attribute__ ((mode (HI)));
    unsigned u4 __attribute__ ((mode (SI)));
    unsigned u8 __attribute__ ((mode (DI)));
    signed s2 __attribute__ ((mode (HI)));
    signed s4 __attribute__ ((mode (SI)));
    signed s8 __attribute__ ((mode (DI)));
} __attribute__ ((packed));

target_ulong
read_guest_pointer (CPUState *cpu, target_ulong guest_addr) { 
    target_ulong out;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *)&out, sizeof(target_ulong), 0); 
    return out; 
}

static inline int
read_1u (CPUState *cpu, target_ulong guest_addr) { 
    unsigned char c;
    panda_virtual_memory_rw(cpu, guest_addr, &c, 1, 0); 
    return c;
}

static inline int
read_1s (CPUState *cpu, target_ulong guest_addr) { 
    unsigned char c;
    panda_virtual_memory_rw(cpu, guest_addr, &c, 1, 0); 
    return c;
}

static inline int
read_2u (CPUState *cpu, target_ulong guest_addr) { 
    union unaligned up;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *) &up, sizeof(up), 0); 
    return up.u2;
}

static inline int
read_2s (CPUState *cpu, target_ulong guest_addr) { 
    union unaligned up;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *) &up, sizeof(up), 0); 
    return up.s2;
}

static inline unsigned int
read_4u (CPUState *cpu, target_ulong guest_addr) { 
    union unaligned up;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *) &up, sizeof(up), 0); 
    return up.u4;
}

static inline int
read_4s (CPUState *cpu, target_ulong guest_addr) { 
    union unaligned up;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *) &up, sizeof(up), 0); 
    return up.s4;
}

static inline unsigned long
read_8u (CPUState *cpu, target_ulong guest_addr) { 
    union unaligned up;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *) &up, sizeof(up), 0); 
    return up.u8;
}

static inline unsigned long
read_8s (CPUState *cpu, target_ulong guest_addr) { 
    union unaligned up;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *) &up, sizeof(up), 0); 
    return up.s8;
}

/* Get the value of register REG as saved in CONTEXT.  */

    inline target_ulong
getReg (CPUState *cpu, int index)
{
    /* This will segfault if the register hasn't been saved.  */
    /* not sure if we dereference register or simply get value  */
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
#if defined(TARGET_I386) || defined(TARGET_ARM)
    return env->regs[index];
#elif defined(TARGET_PPC)
    return env->gpr[index];
#endif
}


void process_dwarf_locs(Dwarf_Loc *locs, Dwarf_Signed loccnt){
    Dwarf_Loc *loc;
    int i;
    for (i = 0; (Dwarf_Half) i < loccnt; i++){
        loc = &locs[i];
        switch (loc->lr_atom){
            case DW_OP_addr:
                printf("%s", "DW_OP_addr");
                break;
            case DW_OP_deref:
                printf("%s", "DW_OP_deref");
                break;
            case DW_OP_const1u:
                printf("%s", "DW_OP_const1u");
                break;
            case DW_OP_const1s:
                printf("%s", "DW_OP_const1s");
                break;
            case DW_OP_const2u:
                printf("%s", "DW_OP_const2u");
                break;
            case DW_OP_const2s:
                printf("%s", "DW_OP_const2s");
                break;
            case DW_OP_const4u:
                printf("%s", "DW_OP_const4u");
                break;
            case DW_OP_const4s:
                printf("%s", "DW_OP_const4s");
                break;
            case DW_OP_const8u:
                printf("%s", "DW_OP_const8u");
                break;
            case DW_OP_const8s:
                printf("%s", "DW_OP_const8s");
                break;
            case DW_OP_constu:
                printf("%s", "DW_OP_constu");
                break;
            case DW_OP_consts:
                printf("%s", "DW_OP_consts");
                break;
            case DW_OP_dup:
                printf("%s", "DW_OP_dup");
                break;
            case DW_OP_drop:
                printf("%s", "DW_OP_drop");
                break;
            case DW_OP_over:
                printf("%s", "DW_OP_over");
                break;
            case DW_OP_pick:
                printf("%s", "DW_OP_pick");
                break;
            case DW_OP_swap:
                printf("%s", "DW_OP_swap");
                break;
            case DW_OP_rot:
                printf("%s", "DW_OP_rot");
                break;
            case DW_OP_xderef:
                printf("%s", "DW_OP_xderef");
                break;
            case DW_OP_abs:
                printf("%s", "DW_OP_abs");
                break;
            case DW_OP_and:
                printf("%s", "DW_OP_and");
                break;
            case DW_OP_div:
                printf("%s", "DW_OP_div");
                break;
            case DW_OP_minus:
                printf("%s", "DW_OP_minus");
                break;
            case DW_OP_mod:
                printf("%s", "DW_OP_mod");
                break;
            case DW_OP_mul:
                printf("%s", "DW_OP_mul");
                break;
            case DW_OP_neg:
                printf("%s", "DW_OP_neg");
                break;
            case DW_OP_not:
                printf("%s", "DW_OP_not");
                break;
            case DW_OP_or:
                printf("%s", "DW_OP_or");
                break;
            case DW_OP_plus:
                printf("%s", "DW_OP_plus");
                break;
            case DW_OP_plus_uconst:
                printf("%s", "DW_OP_plus_uconst");
                break;
            case DW_OP_shl:
                printf("%s", "DW_OP_shl");
                break;
            case DW_OP_shr:
                printf("%s", "DW_OP_shr");
                break;
            case DW_OP_shra:
                printf("%s", "DW_OP_shra");
                break;
            case DW_OP_xor:
                printf("%s", "DW_OP_xor");
                break;
            case DW_OP_bra:
                printf("%s", "DW_OP_bra");
                break;
            case DW_OP_eq:
                printf("%s", "DW_OP_eq");
                break;
            case DW_OP_ge:
                printf("%s", "DW_OP_ge");
                break;
            case DW_OP_gt:
                printf("%s", "DW_OP_gt");
                break;
            case DW_OP_le:
                printf("%s", "DW_OP_le");
                break;
            case DW_OP_lt:
                printf("%s", "DW_OP_lt");
                break;
            case DW_OP_ne:
                printf("%s", "DW_OP_ne");
                break;
            case DW_OP_skip:
                printf("%s", "DW_OP_skip");
                break;
            case DW_OP_lit0:
                printf("%s", "DW_OP_lit0");
                break;
            case DW_OP_lit1:
                printf("%s", "DW_OP_lit1");
                break;
            case DW_OP_lit2:
                printf("%s", "DW_OP_lit2");
                break;
            case DW_OP_lit3:
                printf("%s", "DW_OP_lit3");
                break;
            case DW_OP_lit4:
                printf("%s", "DW_OP_lit4");
                break;
            case DW_OP_lit5:
                printf("%s", "DW_OP_lit5");
                break;
            case DW_OP_lit6:
                printf("%s", "DW_OP_lit6");
                break;
            case DW_OP_lit7:
                printf("%s", "DW_OP_lit7");
                break;
            case DW_OP_lit8:
                printf("%s", "DW_OP_lit8");
                break;
            case DW_OP_lit9:
                printf("%s", "DW_OP_lit9");
                break;
            case DW_OP_lit10:
                printf("%s", "DW_OP_lit10");
                break;
            case DW_OP_lit11:
                printf("%s", "DW_OP_lit11");
                break;
            case DW_OP_lit12:
                printf("%s", "DW_OP_lit12");
                break;
            case DW_OP_lit13:
                printf("%s", "DW_OP_lit13");
                break;
            case DW_OP_lit14:
                printf("%s", "DW_OP_lit14");
                break;
            case DW_OP_lit15:
                printf("%s", "DW_OP_lit15");
                break;
            case DW_OP_lit16:
                printf("%s", "DW_OP_lit16");
                break;
            case DW_OP_lit17:
                printf("%s", "DW_OP_lit17");
                break;
            case DW_OP_lit18:
                printf("%s", "DW_OP_lit18");
                break;
            case DW_OP_lit19:
                printf("%s", "DW_OP_lit19");
                break;
            case DW_OP_lit20:
                printf("%s", "DW_OP_lit20");
                break;
            case DW_OP_lit21:
                printf("%s", "DW_OP_lit21");
                break;
            case DW_OP_lit22:
                printf("%s", "DW_OP_lit22");
                break;
            case DW_OP_lit23:
                printf("%s", "DW_OP_lit23");
                break;
            case DW_OP_lit24:
                printf("%s", "DW_OP_lit24");
                break;
            case DW_OP_lit25:
                printf("%s", "DW_OP_lit25");
                break;
            case DW_OP_lit26:
                printf("%s", "DW_OP_lit26");
                break;
            case DW_OP_lit27:
                printf("%s", "DW_OP_lit27");
                break;
            case DW_OP_lit28:
                printf("%s", "DW_OP_lit28");
                break;
            case DW_OP_lit29:
                printf("%s", "DW_OP_lit29");
                break;
            case DW_OP_lit30:
                printf("%s", "DW_OP_lit30");
                break;
            case DW_OP_lit31:
                printf("%s", "DW_OP_lit31");
                break;
            case DW_OP_reg0:
                printf("%s", "DW_OP_reg0");
                break;
            case DW_OP_reg1:
                printf("%s", "DW_OP_reg1");
                break;
            case DW_OP_reg2:
                printf("%s", "DW_OP_reg2");
                break;
            case DW_OP_reg3:
                printf("%s", "DW_OP_reg3");
                break;
            case DW_OP_reg4:
                printf("%s", "DW_OP_reg4");
                break;
            case DW_OP_reg5:
                printf("%s", "DW_OP_reg5");
                break;
            case DW_OP_reg6:
                printf("%s", "DW_OP_reg6");
                break;
            case DW_OP_reg7:
                printf("%s", "DW_OP_reg7");
                break;
            case DW_OP_reg8:
                printf("%s", "DW_OP_reg8");
                break;
            case DW_OP_reg9:
                printf("%s", "DW_OP_reg9");
                break;
            case DW_OP_reg10:
                printf("%s", "DW_OP_reg10");
                break;
            case DW_OP_reg11:
                printf("%s", "DW_OP_reg11");
                break;
            case DW_OP_reg12:
                printf("%s", "DW_OP_reg12");
                break;
            case DW_OP_reg13:
                printf("%s", "DW_OP_reg13");
                break;
            case DW_OP_reg14:
                printf("%s", "DW_OP_reg14");
                break;
            case DW_OP_reg15:
                printf("%s", "DW_OP_reg15");
                break;
            case DW_OP_reg16:
                printf("%s", "DW_OP_reg16");
                break;
            case DW_OP_reg17:
                printf("%s", "DW_OP_reg17");
                break;
            case DW_OP_reg18:
                printf("%s", "DW_OP_reg18");
                break;
            case DW_OP_reg19:
                printf("%s", "DW_OP_reg19");
                break;
            case DW_OP_reg20:
                printf("%s", "DW_OP_reg20");
                break;
            case DW_OP_reg21:
                printf("%s", "DW_OP_reg21");
                break;
            case DW_OP_reg22:
                printf("%s", "DW_OP_reg22");
                break;
            case DW_OP_reg23:
                printf("%s", "DW_OP_reg23");
                break;
            case DW_OP_reg24:
                printf("%s", "DW_OP_reg24");
                break;
            case DW_OP_reg25:
                printf("%s", "DW_OP_reg25");
                break;
            case DW_OP_reg26:
                printf("%s", "DW_OP_reg26");
                break;
            case DW_OP_reg27:
                printf("%s", "DW_OP_reg27");
                break;
            case DW_OP_reg28:
                printf("%s", "DW_OP_reg28");
                break;
            case DW_OP_reg29:
                printf("%s", "DW_OP_reg29");
                break;
            case DW_OP_reg30:
                printf("%s", "DW_OP_reg30");
                break;
            case DW_OP_reg31:
                printf("%s", "DW_OP_reg31");
                break;
            case DW_OP_breg0:
                printf("%s", "DW_OP_breg0");
                break;
            case DW_OP_breg1:
                printf("%s", "DW_OP_breg1");
                break;
            case DW_OP_breg2:
                printf("%s", "DW_OP_breg2");
                break;
            case DW_OP_breg3:
                printf("%s", "DW_OP_breg3");
                break;
            case DW_OP_breg4:
                printf("%s", "DW_OP_breg4");
                break;
            case DW_OP_breg5:
                printf("%s", "DW_OP_breg5");
                break;
            case DW_OP_breg6:
                printf("%s", "DW_OP_breg6");
                break;
            case DW_OP_breg7:
                printf("%s", "DW_OP_breg7");
                break;
            case DW_OP_breg8:
                printf("%s", "DW_OP_breg8");
                break;
            case DW_OP_breg9:
                printf("%s", "DW_OP_breg9");
                break;
            case DW_OP_breg10:
                printf("%s", "DW_OP_breg10");
                break;
            case DW_OP_breg11:
                printf("%s", "DW_OP_breg11");
                break;
            case DW_OP_breg12:
                printf("%s", "DW_OP_breg12");
                break;
            case DW_OP_breg13:
                printf("%s", "DW_OP_breg13");
                break;
            case DW_OP_breg14:
                printf("%s", "DW_OP_breg14");
                break;
            case DW_OP_breg15:
                printf("%s", "DW_OP_breg15");
                break;
            case DW_OP_breg16:
                printf("%s", "DW_OP_breg16");
                break;
            case DW_OP_breg17:
                printf("%s", "DW_OP_breg17");
                break;
            case DW_OP_breg18:
                printf("%s", "DW_OP_breg18");
                break;
            case DW_OP_breg19:
                printf("%s", "DW_OP_breg19");
                break;
            case DW_OP_breg20:
                printf("%s", "DW_OP_breg20");
                break;
            case DW_OP_breg21:
                printf("%s", "DW_OP_breg21");
                break;
            case DW_OP_breg22:
                printf("%s", "DW_OP_breg22");
                break;
            case DW_OP_breg23:
                printf("%s", "DW_OP_breg23");
                break;
            case DW_OP_breg24:
                printf("%s", "DW_OP_breg24");
                break;
            case DW_OP_breg25:
                printf("%s", "DW_OP_breg25");
                break;
            case DW_OP_breg26:
                printf("%s", "DW_OP_breg26");
                break;
            case DW_OP_breg27:
                printf("%s", "DW_OP_breg27");
                break;
            case DW_OP_breg28:
                printf("%s", "DW_OP_breg28");
                break;
            case DW_OP_breg29:
                printf("%s", "DW_OP_breg29");
                break;
            case DW_OP_breg30:
                printf("%s", "DW_OP_breg30");
                break;
            case DW_OP_breg31:
                printf("%s", "DW_OP_breg31");
                break;
            case DW_OP_regx:
                printf("%s", "DW_OP_regx");
                break;
            case DW_OP_fbreg:
                printf("%s", "DW_OP_fbreg");
                break;
            case DW_OP_bregx:
                printf("%s", "DW_OP_bregx");
                break;
            case DW_OP_piece:
                printf("%s", "DW_OP_piece");
                break;
            case DW_OP_deref_size:
                printf("%s", "DW_OP_deref_size");
                break;
            case DW_OP_xderef_size:
                printf("%s", "DW_OP_xderef_size");
                break;
            case DW_OP_nop:
                printf("%s", "DW_OP_nop");
                break;
            case DW_OP_push_object_address:
                printf("%s", "DW_OP_push_object_address");
                break;
            case DW_OP_call2:
                printf("%s", "DW_OP_call2");
                break;
            case DW_OP_call4:
                printf("%s", "DW_OP_call4");
                break;
            case DW_OP_call_ref:
                printf("%s", "DW_OP_call_ref");
                break;
            case DW_OP_form_tls_address:
                printf("%s", "DW_OP_form_tls_address");
                break;
            case DW_OP_call_frame_cfa:
                printf("%s", "DW_OP_call_frame_cfa");
                break;
            case DW_OP_bit_piece:
                printf("%s", "DW_OP_bit_piece");
                break;
            case DW_OP_implicit_value:
                printf("%s", "DW_OP_implicit_value");
                break;
            case DW_OP_stack_value:
                printf("%s", "DW_OP_stack_value");
                break;
            case DW_OP_implicit_pointer:
                printf("%s", "DW_OP_implicit_pointer");
                break;
            case DW_OP_addrx:
                printf("%s", "DW_OP_addrx");
                break;
            case DW_OP_constx:
                printf("%s", "DW_OP_constx");
                break;
            case DW_OP_entry_value:
                printf("%s", "DW_OP_entry_value");
                break;
            case DW_OP_const_type:
                printf("%s", "DW_OP_const_type");
                break;
            case DW_OP_regval_type:
                printf("%s", "DW_OP_regval_type");
                break;
            case DW_OP_deref_type:
                printf("%s", "DW_OP_deref_type");
                break;
            case DW_OP_xderef_type:
                printf("%s", "DW_OP_xderef_type");
                break;
            case DW_OP_convert:
                printf("%s", "DW_OP_convert");
                break;
            case DW_OP_reinterpret:
                printf("%s", "DW_OP_reinterpret");
                break;

            /* GNU extensions. */
            case DW_OP_GNU_push_tls_address:
                printf("%s", "DW_OP_GNU_push_tls_address");
                break;
            case DW_OP_GNU_uninit:
                printf("%s", "DW_OP_GNU_uninit");
                break;
            case DW_OP_GNU_encoded_addr:
                printf("%s", "DW_OP_GNU_encoded_addr");
                break;
            case DW_OP_GNU_implicit_pointer:
                printf("%s", "DW_OP_GNU_implicit_pointer");
                break;
            case DW_OP_GNU_entry_value:
                printf("%s", "DW_OP_GNU_entry_value");
                break;
            case DW_OP_GNU_const_type:
                printf("%s", "DW_OP_GNU_const_type");
                break;
            case DW_OP_GNU_regval_type:
                printf("%s", "DW_OP_GNU_regval_type");
                break;
            case DW_OP_GNU_deref_type:
                printf("%s", "DW_OP_GNU_deref_type");
                break;
            case DW_OP_GNU_convert:
                printf("%s", "DW_OP_GNU_convert");
                break;
            case DW_OP_GNU_reinterpret:
                printf("%s", "DW_OP_GNU_reinterpret");
                break;
            case DW_OP_GNU_parameter_ref:
                printf("%s", "DW_OP_GNU_parameter_ref");
                break;
            case DW_OP_GNU_addr_index:
                printf("%s", "DW_OP_GNU_addr_index");
                break;
            case DW_OP_GNU_const_index:
                printf("%s", "DW_OP_GNU_const_index");
                break;
            case DW_OP_hi_user:
                printf("%s", "DW_OP_hi_user");
                break;
            default:
                printf("UNKNOWN DW_OP: 0x%x\n", loc->lr_atom);
                //exit(1);
        }
        printf(" %llx %llx ", loc->lr_number, loc->lr_number2);
        //printf(" %llx %llx offset-%llx ", loc->lr_number, loc->lr_number2, loc->lr_offset);
    }
}

/* Decode a DW_OP stack program.  Place top of stack in ret_loc.  Push INITIAL
   onto the stack to start.  Return the location type: memory address, register,
   or const value representing value of variable*/
LocType execute_stack_op(CPUState *cpu, target_ulong pc, Dwarf_Loc *loc_list,
        Dwarf_Half loc_cnt, target_ulong frame_ptr, target_ulong *ret_loc)
{
    //printf("\n {");
    //process_dwarf_locs(loc_list, loc_cnt);
    //printf("} = \n");
    target_ulong stack[64];	/* ??? Assume this is enough.  */
    int stack_elt, loc_idx, i;
    unsigned int next_offset;
    bool inReg = false;
    Dwarf_Small op;
    //stack[0] = initial;
    stack[0] = 0;
    stack_elt = 1;
    loc_idx = 0;
    Dwarf_Loc *cur_loc;
    while (loc_idx < loc_cnt)
    {
        cur_loc = &loc_list[loc_idx];
        op = cur_loc->lr_atom;
        loc_idx++;
        //enum dwarf_location_atom op = *op_ptr++;
        Dwarf_Unsigned result, reg, utmp;
        Dwarf_Signed offset, stmp;
        //printf(" cur_op %x\n", op);
        switch (op)
        {
            case DW_OP_lit0:
            case DW_OP_lit1:
            case DW_OP_lit2:
            case DW_OP_lit3:
            case DW_OP_lit4:
            case DW_OP_lit5:
            case DW_OP_lit6:
            case DW_OP_lit7:
            case DW_OP_lit8:
            case DW_OP_lit9:
            case DW_OP_lit10:
            case DW_OP_lit11:
            case DW_OP_lit12:
            case DW_OP_lit13:
            case DW_OP_lit14:
            case DW_OP_lit15:
            case DW_OP_lit16:
            case DW_OP_lit17:
            case DW_OP_lit18:
            case DW_OP_lit19:
            case DW_OP_lit20:
            case DW_OP_lit21:
            case DW_OP_lit22:
            case DW_OP_lit23:
            case DW_OP_lit24:
            case DW_OP_lit25:
            case DW_OP_lit26:
            case DW_OP_lit27:
            case DW_OP_lit28:
            case DW_OP_lit29:
            case DW_OP_lit30:
            case DW_OP_lit31:
                result = op - DW_OP_lit0;
                break;

            case DW_OP_addr:
                //printf(" DW_OP_addr: 0x%llx\n", cur_loc->lr_number);
                result = cur_loc->lr_number;
                //op_ptr += sizeof (void *);
                break;

            case DW_OP_const1u:
                result = cur_loc->lr_number;
                //result = read_1u (cur_loc->lr_number);
                //op_ptr += 1;
                break;
            case DW_OP_const1s:
                result = cur_loc->lr_number;
                //result = read_1s (cur_loc->lr_number);
                //op_ptr += 1;
                break;
            case DW_OP_const2u:
                result = cur_loc->lr_number;
                //result = read_2u (cur_loc->lr_number);
                //op_ptr += 2;
                break;
            case DW_OP_const2s:
                result = cur_loc->lr_number;
                //result = read_2s (cur_loc->lr_number);
                //op_ptr += 2;
                break;
            case DW_OP_const4u:
                result = cur_loc->lr_number;
                //result = read_4u (cur_loc->lr_number);
                //op_ptr += 4;
                break;
            case DW_OP_const4s:
                result = cur_loc->lr_number;
                //result = read_4s (cur_loc->lr_number);
                //op_ptr += 4;
                break;
            case DW_OP_const8u:
                result = cur_loc->lr_number;
                //result = read_8u (cur_loc->lr_number);
                //op_ptr += 8;
                break;
            case DW_OP_const8s:
                result = cur_loc->lr_number;
                //result = read_8s (cur_loc->lr_number);
                //op_ptr += 8;
                break;
            case DW_OP_constu:
                result = cur_loc->lr_number;
                //read_uleb128 (cur_loc->lr_number, &result);
                break;
            case DW_OP_consts:
                stmp = cur_loc->lr_number;
                //read_sleb128 (cur_loc->lr_number, &stmp);
                result = stmp;
                break;

            case DW_OP_reg0:
            case DW_OP_reg1:
            case DW_OP_reg2:
            case DW_OP_reg3:
            case DW_OP_reg4:
            case DW_OP_reg5:
            case DW_OP_reg6:
            case DW_OP_reg7:
            case DW_OP_reg8:
            case DW_OP_reg9:
            case DW_OP_reg10:
            case DW_OP_reg11:
            case DW_OP_reg12:
            case DW_OP_reg13:
            case DW_OP_reg14:
            case DW_OP_reg15:
            case DW_OP_reg16:
            case DW_OP_reg17:
            case DW_OP_reg18:
            case DW_OP_reg19:
            case DW_OP_reg20:
            case DW_OP_reg21:
            case DW_OP_reg22:
            case DW_OP_reg23:
            case DW_OP_reg24:
            case DW_OP_reg25:
            case DW_OP_reg26:
            case DW_OP_reg27:
            case DW_OP_reg28:
            case DW_OP_reg29:
            case DW_OP_reg30:
            case DW_OP_reg31:
                //result = getReg (cpu, op - DW_OP_reg0);
                result = op - DW_OP_reg0;
                inReg = true;
                break;
            case DW_OP_regx:
                reg = cur_loc->lr_number;
                //result = getReg (cpu, reg);
                result = reg;
                inReg = true;
                break;

            case DW_OP_breg0:
            case DW_OP_breg1:
            case DW_OP_breg2:
            case DW_OP_breg3:
            case DW_OP_breg4:
            case DW_OP_breg5:
            case DW_OP_breg6:
            case DW_OP_breg7:
            case DW_OP_breg8:
            case DW_OP_breg9:
            case DW_OP_breg10:
            case DW_OP_breg11:
            case DW_OP_breg12:
            case DW_OP_breg13:
            case DW_OP_breg14:
            case DW_OP_breg15:
            case DW_OP_breg16:
            case DW_OP_breg17:
            case DW_OP_breg18:
            case DW_OP_breg19:
            case DW_OP_breg20:
            case DW_OP_breg21:
            case DW_OP_breg22:
            case DW_OP_breg23:
            case DW_OP_breg24:
            case DW_OP_breg25:
            case DW_OP_breg26:
            case DW_OP_breg27:
            case DW_OP_breg28:
            case DW_OP_breg29:
            case DW_OP_breg30:
            case DW_OP_breg31:
                offset = cur_loc->lr_number;
                result = getReg (cpu, op - DW_OP_breg0) + offset;
                break;
            case DW_OP_fbreg:
                offset = cur_loc->lr_number;
                // frame pointer
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
                //printf(" fp [0x%x] + ofst: %lld\n", frame_ptr, offset);
                result = frame_ptr + offset;
#else
                fprintf(stderr, "Do not support frame dereferencing on this architecture.\n");
                exit(1);
#endif
                break;
            case DW_OP_bregx:
                reg = cur_loc->lr_number;
                offset = cur_loc->lr_number2;
                result = getReg (cpu, reg) + offset;
                break;

            case DW_OP_dup:
                if (stack_elt < 1)
                    assert (1==0);
                result = stack[stack_elt - 1];
                break;

            case DW_OP_drop:
                if (--stack_elt < 0)
                    assert (1==0);
                goto no_push;

            case DW_OP_pick:
                offset = cur_loc->lr_number;
                //offset = *op_ptr++;
                if (offset >= stack_elt - 1)
                    assert (1==0);
                result = stack[stack_elt - 1 - offset];
                break;

            case DW_OP_over:
                if (stack_elt < 2)
                    assert (1==0);
                result = stack[stack_elt - 2];
                break;
           
            // variable doesn't have location
            // but dwarf information says it's VALUE
            // at this point in the program
            case DW_OP_stack_value:
                if (stack_elt < 1)
                    assert (1==0);
                *ret_loc = stack[stack_elt - 1];
                return LocConst;
                break;
            case DW_OP_rot:
                {
                    target_ulong t1, t2, t3;

                    if (stack_elt < 3)
                        assert (1==0);
                    t1 = stack[stack_elt - 1];
                    t2 = stack[stack_elt - 2];
                    t3 = stack[stack_elt - 3];
                    stack[stack_elt - 1] = t2;
                    stack[stack_elt - 2] = t3;
                    stack[stack_elt - 3] = t1;
                    goto no_push;
                }
            case DW_OP_GNU_entry_value:
                //printf(" DW_OP_entry_value: Must figure out stack unwinding. Not implemented. Returning LocErr\n");
                return LocErr;
            // takes an argument (which is offset into debugging information for a die entry that is a base type
            // converts arg on top of stack to said base type
            case DW_OP_GNU_convert:
            case DW_OP_convert:
                //printf(" DW_OP_[GNU]_convert: Top of stack must be cast to different type.  Not implemented. Returning LocErr\n");
                return LocErr;
            case DW_OP_piece:
            case DW_OP_bit_piece:
                //printf(" DW_OP_[bit]_piece: Variable is split among multiple locations/registers. Not implemented. Returning LocErr\n");
                return LocErr;
            case DW_OP_deref_type:
            case DW_OP_GNU_deref_type:
            case DW_OP_deref:
            case DW_OP_deref_size:
            case DW_OP_abs:
            case DW_OP_neg:
            case DW_OP_not:
            case DW_OP_plus_uconst:
                /* Unary operations.  */
                if (--stack_elt < 0)
                    assert (1==0);
                result = stack[stack_elt];

                switch (op)
                {
                    case DW_OP_deref:
                        {
                            result = read_guest_pointer (cpu, result);
                        }
                        break;
                    case DW_OP_deref_size:
                        {
                            switch (cur_loc->lr_number)
                            {
                                case 1:
                                    result = read_1u (cpu, result);
                                    break;
                                case 2:
                                    result = read_2u (cpu, result);
                                    break;
                                case 4:
                                    result = read_4u (cpu, result);
                                    break;
                                case 8:
                                    result = read_8u (cpu, result);
                                    break;
                                default:
                                    assert (1==0);
                            }
                        }
                        break;
            
                    case DW_OP_GNU_deref_type:
                    case DW_OP_deref_type:
                        //printf(" DW_OP_[GNU]_deref_type: need to dereference an address with a particular type\n");
                        return LocErr;

                    case DW_OP_abs:
                        if ((target_long) result < 0)
                            result = -result;
                        break;
                    case DW_OP_neg:
                        result = -result;
                        break;
                    case DW_OP_not:
                        result = ~result;
                        break;
                    case DW_OP_plus_uconst:
                        utmp = cur_loc->lr_number;
                        result += utmp;
                        break;

                    default:
                        assert (1==0);
                }
                break;

            case DW_OP_and:
            case DW_OP_div:
            case DW_OP_minus:
            case DW_OP_mod:
            case DW_OP_mul:
            case DW_OP_or:
            case DW_OP_plus:
            case DW_OP_shl:
            case DW_OP_shr:
            case DW_OP_shra:
            case DW_OP_xor:
            case DW_OP_le:
            case DW_OP_ge:
            case DW_OP_eq:
            case DW_OP_lt:
            case DW_OP_gt:
            case DW_OP_ne:
                {
                    /* Binary operations.  */
                    target_ulong first, second;
                    if ((stack_elt -= 2) < 0)
                        assert (1==0);
                    second = stack[stack_elt];
                    first = stack[stack_elt + 1];

                    switch (op)
                    {
                        case DW_OP_and:
                            result = second & first;
                            break;
                        case DW_OP_div:
                            result = (target_long) second / (target_long) first;
                            break;
                        case DW_OP_minus:
                            result = second - first;
                            break;
                        case DW_OP_mod:
                            result = (target_long) second % (target_long) first;
                            break;
                        case DW_OP_mul:
                            result = second * first;
                            break;
                        case DW_OP_or:
                            result = second | first;
                            break;
                        case DW_OP_plus:
                            result = second + first;
                            break;
                        case DW_OP_shl:
                            result = second << first;
                            break;
                        case DW_OP_shr:
                            result = second >> first;
                            break;
                        case DW_OP_shra:
                            result = (target_long) second >> first;
                            break;
                        case DW_OP_xor:
                            result = second ^ first;
                            break;
                        case DW_OP_le:
                            result = (target_long) first <= (target_long) second;
                            break;
                        case DW_OP_ge:
                            result = (target_long) first >= (target_long) second;
                            break;
                        case DW_OP_eq:
                            result = (target_long) first == (target_long) second;
                            break;
                        case DW_OP_lt:
                            result = (target_long) first < (target_long) second;
                            break;
                        case DW_OP_gt:
                            result = (target_long) first > (target_long) second;
                            break;
                        case DW_OP_ne:
                            result = (target_long) first != (target_long) second;
                            break;

                        default:
                            assert (1==0);
                    }
                }
                break;

            case DW_OP_skip:
                offset = cur_loc->lr_offset;
                stmp = cur_loc->lr_number;
                next_offset = offset + 1 + 2 + stmp;
                for (i = 0; i < loc_cnt; i++){
                    if (loc_list[i].lr_offset == next_offset){
                        loc_idx = i;
                        goto no_push;
                    }
                }
                //return LocErr;
                assert (1==0);

            case DW_OP_bra:
                if (--stack_elt < 0)
                    assert (1==0);
                offset = cur_loc->lr_offset;
                stmp = cur_loc->lr_number;
                next_offset = offset + 1 + 2 + stmp;
                if (stack[stack_elt] != 0){
                    for (i = 0; i < loc_cnt; i++){
                        if (loc_list[i].lr_offset == next_offset){
                            loc_idx = i;
                            goto no_push;
                        }
                    }
                    //return LocErr;
                    assert (1==0);
                }
                goto no_push;

            case DW_OP_nop:
                goto no_push;

            default:
                //process_dwarf_locs(loc_list, loc_cnt);
                return LocErr; 
                //assert (1==0);
        }

        /* Most things push a result value.  */
        if ((size_t) stack_elt >= sizeof(stack)/sizeof(*stack))
            assert (1==0);
        stack[stack_elt++] = result;
no_push:;
    }

    /* We were executing this program to get a value.  It should be
       at top of stack.  */
    if (--stack_elt < 0)
        assert (1==0);
    
    *ret_loc = stack[stack_elt];
    if (inReg)
        return LocReg;
    else
        return LocMem;
    //return stack[stack_elt];
}

#endif
