#include <stdint.h>
#include <string.h>
#include <cpu.h>

/** @file
 *
 * CPU identification
 *
 */

/**
 * Test to see if CPU flag is changeable
 *
 * @v flag		Flag to test
 * @ret can_change	Flag is changeable
 */
static inline int flag_is_changeable ( unsigned int flag ) {
	uint32_t f1, f2;

	__asm__ ( "pushfl\n\t"
		  "pushfl\n\t"
		  "popl %0\n\t"
		  "movl %0,%1\n\t"
		  "xorl %2,%0\n\t"
		  "pushl %0\n\t"
		  "popfl\n\t"
		  "pushfl\n\t"
		  "popl %0\n\t"
		  "popfl\n\t"
		  : "=&r" ( f1 ), "=&r" ( f2 )
		  : "ir" ( flag ) );

	return ( ( ( f1 ^ f2 ) & flag ) != 0 );
}

/**
 * Get CPU information
 *
 * @v cpu		CPU information structure to fill in
 */
void get_cpuinfo ( struct cpuinfo_x86 *cpu ) {
	unsigned int cpuid_level;
	unsigned int cpuid_extlevel;
	unsigned int discard_1, discard_2, discard_3;

	memset ( cpu, 0, sizeof ( *cpu ) );

	/* Check for CPUID instruction */
	if ( ! flag_is_changeable ( X86_EFLAGS_ID ) ) {
		DBG ( "CPUID not supported\n" );
		return;
	}

	/* Get features, if present */
	cpuid ( 0x00000000, &cpuid_level, &discard_1,
		&discard_2, &discard_3 );
	if ( cpuid_level >= 0x00000001 ) {
		cpuid ( 0x00000001, &discard_1, &discard_2,
			&discard_3, &cpu->features );
	} else {
		DBG ( "CPUID cannot return capabilities\n" );
	}

	/* Get 64-bit features, if present */
	cpuid ( 0x80000000, &cpuid_extlevel, &discard_1,
		&discard_2, &discard_3 );
	if ( ( cpuid_extlevel & 0xffff0000 ) == 0x80000000 ) {
		if ( cpuid_extlevel >= 0x80000001 ) {
			cpuid ( 0x80000001, &discard_1, &discard_2,
				&discard_3, &cpu->amd_features );
		}
	}
}
