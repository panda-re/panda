#if TARGET_LONG_BITS == 32
#define ELF(r) Elf32_ ## r
#define ELFD(r) ELF32_ ## r
#else
#define ELF(r) Elf64_ ## r
#define ELFD(r) ELF64_ ## r
#endif

#define DT_INIT_ARRAY	   25		  ,  /* Array with addresses of init fct */
#define DT_FINI_ARRAY	   26		  ,  /* Array with addresses of fini fct */
#define DT_INIT_ARRAYSZ	   27		  ,  /* Size in bytes of DT_INIT_ARRAY */
#define DT_FINI_ARRAYSZ	   28		  ,  /* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH	       29		  ,  /* Library search path */
#define DT_FLAGS	      30		  ,  /* Flags for the object being loaded */
#define DT_PREINIT_ARRAY  32		  ,  /* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ 33		  ,  /* size in bytes of DT_PREINIT_ARRAY */
#define DT_NUM		      34		  ,  /* Number used */
#define DT_SUNW_RTLDINF 0x6000000e
#define DT_CONFIG 0x6ffffefa
#define DT_DEPAUDIT 0x6ffffefb
#define DT_AUDIT 0x6ffffefc
#define DT_PLTPAD 0x6ffffefd
#define DT_MOVETAB 0x6ffffefe
#define DT_SYMINFO 0x6ffffeff
#define DT_GNU_HASH 0x6FFFFEF5

//https://elixir.bootlin.com/uclibc-ng/latest/source/include/elf.h#L1940
#define DT_MIPS_LOCAL_GOTNO  0x7000000a	/* Number of local GOT entries */
#define DT_MIPS_GOTSYM	     0x70000013	/* First GOT entry in DYNSYM */


// https://elixir.bootlin.com/uclibc-ng/latest/source/include/elf.h#L1893
/* MIPS relocs.  */


#define R_MIPS_NONE		0	/* No reloc */
#define R_MIPS_16		1	/* Direct 16 bit */
#define R_MIPS_32		2	/* Direct 32 bit */
#define R_MIPS_REL32		3	/* PC relative 32 bit */
#define R_MIPS_26		4	/* Direct 26 bit shifted */
#define R_MIPS_HI16		5	/* High 16 bit */
#define R_MIPS_LO16		6	/* Low 16 bit */
#define R_MIPS_GPREL16		7	/* GP relative 16 bit */
#define R_MIPS_LITERAL		8	/* 16 bit literal entry */
#define R_MIPS_GOT16		9	/* 16 bit GOT entry */
#define R_MIPS_PC16		10	/* PC relative 16 bit */
#define R_MIPS_CALL16		11	/* 16 bit GOT entry for function */
#define R_MIPS_GPREL32		12	/* GP relative 32 bit */

#define R_MIPS_SHIFT5		16
#define R_MIPS_SHIFT6		17
#define R_MIPS_64		18
#define R_MIPS_GOT_DISP		19
#define R_MIPS_GOT_PAGE		20
#define R_MIPS_GOT_OFST		21
#define R_MIPS_GOT_HI16		22
#define R_MIPS_GOT_LO16		23
#define R_MIPS_SUB		24
#define R_MIPS_INSERT_A		25
#define R_MIPS_INSERT_B		26
#define R_MIPS_DELETE		27
#define R_MIPS_HIGHER		28
#define R_MIPS_HIGHEST		29
#define R_MIPS_CALL_HI16	30
#define R_MIPS_CALL_LO16	31
#define R_MIPS_SCN_DISP		32
#define R_MIPS_REL16		33
#define R_MIPS_ADD_IMMEDIATE	34
#define R_MIPS_PJUMP		35
#define R_MIPS_RELGOT		36
#define R_MIPS_JALR		37
#define R_MIPS_TLS_DTPMOD32	38	/* Module number 32 bit */
#define R_MIPS_TLS_DTPREL32	39	/* Module-relative offset 32 bit */
#define R_MIPS_TLS_DTPMOD64	40	/* Module number 64 bit */
#define R_MIPS_TLS_DTPREL64	41	/* Module-relative offset 64 bit */
#define R_MIPS_TLS_GD		42	/* 16 bit GOT offset for GD */
#define R_MIPS_TLS_LDM		43	/* 16 bit GOT offset for LDM */
#define R_MIPS_TLS_DTPREL_HI16	44	/* Module-relative offset, high 16 bits */
#define R_MIPS_TLS_DTPREL_LO16	45	/* Module-relative offset, low 16 bits */
#define R_MIPS_TLS_GOTTPREL	46	/* 16 bit GOT offset for IE */
#define R_MIPS_TLS_TPREL32	47	/* TP-relative offset, 32 bit */
#define R_MIPS_TLS_TPREL64	48	/* TP-relative offset, 64 bit */
#define R_MIPS_TLS_TPREL_HI16	49	/* TP-relative offset, high 16 bits */
#define R_MIPS_TLS_TPREL_LO16	50	/* TP-relative offset, low 16 bits */
#define R_MIPS_GLOB_DAT		51
#define R_MIPS_COPY		126
#define R_MIPS_JUMP_SLOT        127
/* Keep this the last entry.  */
#define R_MIPS_NUM		128



/* ARM relocs.  */

#define R_ARM_NONE		0	/* No reloc */
#define R_ARM_PC24		1	/* PC relative 26 bit branch */
#define R_ARM_ABS32		2	/* Direct 32 bit  */
#define R_ARM_REL32		3	/* PC relative 32 bit */
#define R_ARM_PC13		4
#define R_ARM_ABS16		5	/* Direct 16 bit */
#define R_ARM_ABS12		6	/* Direct 12 bit */
#define R_ARM_THM_ABS5		7
#define R_ARM_ABS8		8	/* Direct 8 bit */
#define R_ARM_SBREL32		9
#define R_ARM_THM_PC22		10
#define R_ARM_THM_PC8		11
#define R_ARM_AMP_VCALL9	12
#define R_ARM_SWI24		13
#define R_ARM_THM_SWI8		14
#define R_ARM_XPC25		15
#define R_ARM_THM_XPC22		16
#define R_ARM_TLS_DTPMOD32	17
#define R_ARM_TLS_DTPOFF32	18
#define R_ARM_TLS_TPOFF32	19
#define R_ARM_COPY		20	/* Copy symbol at runtime */
#define R_ARM_GLOB_DAT		21	/* Create GOT entry */
#define R_ARM_JUMP_SLOT		22	/* Create PLT entry */
#define R_ARM_RELATIVE		23	/* Adjust by program base */
#define R_ARM_GOTOFF		24	/* 32 bit offset to GOT */
#define R_ARM_GOTPC		25	/* 32 bit PC relative offset to GOT */
#define R_ARM_GOT32		26	/* 32 bit GOT entry */
#define R_ARM_PLT32		27	/* 32 bit PLT address */
#define R_ARM_ALU_PCREL_7_0	32
#define R_ARM_ALU_PCREL_15_8	33
#define R_ARM_ALU_PCREL_23_15	34
#define R_ARM_LDR_SBREL_11_0	35
#define R_ARM_ALU_SBREL_19_12	36
#define R_ARM_ALU_SBREL_27_20	37
#define R_ARM_GNU_VTENTRY	100
#define R_ARM_GNU_VTINHERIT	101
#define R_ARM_THM_PC11		102	/* thumb unconditional branch */
#define R_ARM_THM_PC9		103	/* thumb conditional branch */
#define R_ARM_TLS_GD32		104
#define R_ARM_TLS_LDM32		105
#define R_ARM_TLS_LDO32		106
#define R_ARM_TLS_IE32		107
#define R_ARM_TLS_LE32		108
#define R_ARM_TLS_LDO12		109
#define R_ARM_TLS_LE12		110
#define R_ARM_TLS_IE12GP	111
#define R_ARM_FUNCDESC		163
#define R_ARM_FUNCDESC_VALUE	164
#define R_ARM_RXPC25		249
#define R_ARM_RSBREL32		250
#define R_ARM_THM_RPC22		251
#define R_ARM_RREL32		252
#define R_ARM_RABS22		253
#define R_ARM_RPC24		254
#define R_ARM_RBASE		255
/* Keep this the last entry.  */
#define R_ARM_NUM		256

