// Generate assembler offsets.

#include "gen-defs.h" // OFFSET
#include "bregs.h" // struct bregs
#include "biosvar.h" // struct bios_data_area_s

/* workaround for a warning with -Wmissing-prototypes */
void foo(void) VISIBLE16;

void foo(void)
{
    COMMENT("BREGS");
    OFFSET(BREGS_es, bregs, es);
    OFFSET(BREGS_ds, bregs, ds);
    OFFSET(BREGS_eax, bregs, eax);
    OFFSET(BREGS_ebx, bregs, ebx);
    OFFSET(BREGS_ecx, bregs, ecx);
    OFFSET(BREGS_edx, bregs, edx);
    OFFSET(BREGS_ebp, bregs, ebp);
    OFFSET(BREGS_esi, bregs, esi);
    OFFSET(BREGS_edi, bregs, edi);
    OFFSET(BREGS_flags, bregs, flags);
    OFFSET(BREGS_code, bregs, code);

    COMMENT("BDA");
    OFFSET(BDA_ebda_seg, bios_data_area_s, ebda_seg);

    COMMENT("EBDA");
    DEFINE(EBDA_OFFSET_TOP_STACK, EBDA_OFFSET_TOP_STACK);
    DEFINE(EBDA_SEGMENT_START, EBDA_SEGMENT_START);
}
