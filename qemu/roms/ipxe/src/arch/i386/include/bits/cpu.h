#ifndef I386_BITS_CPU_H
#define I386_BITS_CPU_H

/* Intel-defined CPU features, CPUID level 0x00000001, word 0 */
#define X86_FEATURE_FPU		0 /* Onboard FPU */
#define X86_FEATURE_VME		1 /* Virtual Mode Extensions */
#define X86_FEATURE_DE		2 /* Debugging Extensions */
#define X86_FEATURE_PSE 	3 /* Page Size Extensions */
#define X86_FEATURE_TSC		4 /* Time Stamp Counter */
#define X86_FEATURE_MSR		5 /* Model-Specific Registers, RDMSR, WRMSR */
#define X86_FEATURE_PAE		6 /* Physical Address Extensions */
#define X86_FEATURE_MCE		7 /* Machine Check Architecture */
#define X86_FEATURE_CX8		8 /* CMPXCHG8 instruction */
#define X86_FEATURE_APIC	9 /* Onboard APIC */
#define X86_FEATURE_SEP		11 /* SYSENTER/SYSEXIT */
#define X86_FEATURE_MTRR	12 /* Memory Type Range Registers */
#define X86_FEATURE_PGE		13 /* Page Global Enable */
#define X86_FEATURE_MCA		14 /* Machine Check Architecture */
#define X86_FEATURE_CMOV	15 /* CMOV instruction (FCMOVCC and FCOMI too if FPU present) */
#define X86_FEATURE_PAT		16 /* Page Attribute Table */
#define X86_FEATURE_PSE36	17 /* 36-bit PSEs */
#define X86_FEATURE_PN		18 /* Processor serial number */
#define X86_FEATURE_CLFLSH	19 /* Supports the CLFLUSH instruction */
#define X86_FEATURE_DTES	21 /* Debug Trace Store */
#define X86_FEATURE_ACPI	22 /* ACPI via MSR */
#define X86_FEATURE_MMX		23 /* Multimedia Extensions */
#define X86_FEATURE_FXSR	24 /* FXSAVE and FXRSTOR instructions (fast save and restore */
				          /* of FPU context), and CR4.OSFXSR available */
#define X86_FEATURE_XMM		25 /* Streaming SIMD Extensions */
#define X86_FEATURE_XMM2	26 /* Streaming SIMD Extensions-2 */
#define X86_FEATURE_SELFSNOOP	27 /* CPU self snoop */
#define X86_FEATURE_HT		28 /* Hyper-Threading */
#define X86_FEATURE_ACC		29 /* Automatic clock control */
#define X86_FEATURE_IA64	30 /* IA-64 processor */

/* AMD-defined CPU features, CPUID level 0x80000001, word 1 */
/* Don't duplicate feature flags which are redundant with Intel! */
#define X86_FEATURE_SYSCALL	11 /* SYSCALL/SYSRET */
#define X86_FEATURE_MMXEXT	22 /* AMD MMX extensions */
#define X86_FEATURE_LM		29 /* Long Mode (x86-64) */
#define X86_FEATURE_3DNOWEXT	30 /* AMD 3DNow! extensions */
#define X86_FEATURE_3DNOW	31 /* 3DNow! */

/** x86 CPU information */
struct cpuinfo_x86 {
	/** CPU features */
	unsigned int features;
	/** 64-bit CPU features */
	unsigned int amd_features;
};

/*
 * EFLAGS bits
 */
#define X86_EFLAGS_CF	0x00000001 /* Carry Flag */
#define X86_EFLAGS_PF	0x00000004 /* Parity Flag */
#define X86_EFLAGS_AF	0x00000010 /* Auxillary carry Flag */
#define X86_EFLAGS_ZF	0x00000040 /* Zero Flag */
#define X86_EFLAGS_SF	0x00000080 /* Sign Flag */
#define X86_EFLAGS_TF	0x00000100 /* Trap Flag */
#define X86_EFLAGS_IF	0x00000200 /* Interrupt Flag */
#define X86_EFLAGS_DF	0x00000400 /* Direction Flag */
#define X86_EFLAGS_OF	0x00000800 /* Overflow Flag */
#define X86_EFLAGS_IOPL	0x00003000 /* IOPL mask */
#define X86_EFLAGS_NT	0x00004000 /* Nested Task */
#define X86_EFLAGS_RF	0x00010000 /* Resume Flag */
#define X86_EFLAGS_VM	0x00020000 /* Virtual Mode */
#define X86_EFLAGS_AC	0x00040000 /* Alignment Check */
#define X86_EFLAGS_VIF	0x00080000 /* Virtual Interrupt Flag */
#define X86_EFLAGS_VIP	0x00100000 /* Virtual Interrupt Pending */
#define X86_EFLAGS_ID	0x00200000 /* CPUID detection flag */

/*
 * Generic CPUID function
 */
static inline __attribute__ (( always_inline )) void
cpuid ( int op, unsigned int *eax, unsigned int *ebx,
	unsigned int *ecx, unsigned int *edx ) {
	__asm__ ( "cpuid" :
		  "=a" ( *eax ), "=b" ( *ebx ), "=c" ( *ecx ), "=d" ( *edx )
		: "0" ( op ) );
}

extern void get_cpuinfo ( struct cpuinfo_x86 *cpu );

#endif /* I386_BITS_CPU_H */
