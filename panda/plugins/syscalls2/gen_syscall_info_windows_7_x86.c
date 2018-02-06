#include <stdint.h>
#include "syscalls2_info.h"
#define MAX_SYSCALL_NO 400
#define MAX_SYSCALL_GENERIC_NO 400
#define MAX_SYSCALL_ARGS 17

#if __GNUC__ < 5
#if 0
	The system call arguments array has variable size.
	This prevents initializing the whole syscall_info statically.
	To solve this, we declare static variables for the arguments
	array of all system calls and assign those instead.
	***This solution may be gcc-specific!***

	See: https://stackoverflow.com/a/24640918
#endif
#warning This file may require gcc-5 or later to be compiled.
#endif

static syscall_argtype_t argt_0[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_0[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_1[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_1[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_2[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_2[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_3[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_3[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_4[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_5[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_5[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_6[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_6[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_7[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_7[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_8[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_8[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_9[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_9[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_10[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_10[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_11[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_11[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_12[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_12[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_13[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_13[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_14[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_14[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_15[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_15[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_16[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_16[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_17[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_17[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_18[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_18[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_19[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_19[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_20[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_20[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_21[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_21[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_22[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_22[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_23[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_23[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_24[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_24[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_25[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_25[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_26[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_26[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_27[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_27[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_28[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_28[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_29[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_29[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_30[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_30[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_31[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_31[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_32[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_32[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_33[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_33[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_34[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_34[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_35[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_35[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_36[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_36[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_37[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_37[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_38[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_38[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_39[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_39[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_40[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_40[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_41[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_41[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_42[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_42[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_43[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_43[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_44[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_44[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_45[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_45[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_46[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_46[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_47[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_47[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_48[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_48[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_49[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_49[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_50[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_50[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_51[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_51[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_52[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_52[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_53[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_53[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_54[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_54[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_55[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_55[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_56[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_56[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_57[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_57[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_58[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_58[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_59[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_59[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_60[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_60[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_61[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_61[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_62[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_62[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_63[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_63[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_64[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_64[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_65[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_65[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_66[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_66[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_67[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_67[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_68[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_68[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_69[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_69[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_70[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_70[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_71[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_71[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_72[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_72[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_73[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_73[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_74[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_74[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_75[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_75[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_76[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_76[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_77[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_77[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_78[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_78[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_79[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_79[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_80[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_80[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_81[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_81[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_82[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_82[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_83[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_83[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_84[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_84[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_85[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_85[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_86[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_86[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_87[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_87[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_88[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_88[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_89[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_89[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_90[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_90[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_91[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_91[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_92[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_92[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_93[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_93[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_94[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_94[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_95[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_95[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_96[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_96[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_97[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_97[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_98[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_98[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_99[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_99[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_100[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_100[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_101[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_101[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_102[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_102[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_103[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_103[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_104[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_104[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_105[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_105[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_106[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_106[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_107[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_107[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_108[] = {};
static uint8_t argsz_108[] = {};
static syscall_argtype_t argt_109[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_109[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_110[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_110[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_111[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_111[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_112[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_112[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_113[] = {};
static uint8_t argsz_113[] = {};
static syscall_argtype_t argt_114[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_114[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_115[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_115[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_116[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_116[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_117[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_117[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_118[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_118[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_119[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_119[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_120[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_120[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_121[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_121[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_122[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_122[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_123[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_123[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_124[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_124[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_125[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_125[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_126[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_126[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_127[] = {};
static uint8_t argsz_127[] = {};
static syscall_argtype_t argt_128[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_128[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_129[] = {};
static uint8_t argsz_129[] = {};
static syscall_argtype_t argt_130[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_130[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_131[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_131[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_132[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_132[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_133[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_133[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_134[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_134[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_135[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_135[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_136[] = {};
static uint8_t argsz_136[] = {};
static syscall_argtype_t argt_137[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_137[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_138[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_138[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_139[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_139[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_140[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_140[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_141[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_141[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_142[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_142[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_143[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_143[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_144[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_144[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_145[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_145[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_146[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_146[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_147[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_147[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_148[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_148[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_149[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_149[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_150[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_150[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_151[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_151[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_152[] = {};
static uint8_t argsz_152[] = {};
static syscall_argtype_t argt_153[] = {};
static uint8_t argsz_153[] = {};
static syscall_argtype_t argt_154[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_154[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_155[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_155[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_156[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_156[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_157[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_157[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_158[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_158[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_159[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_159[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_160[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_160[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_161[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_161[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_162[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_162[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_163[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_163[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_164[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_164[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_165[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_165[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_166[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_166[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_167[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_167[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_168[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_168[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_169[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_169[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_170[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_170[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_171[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_171[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_172[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_172[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_173[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_173[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_174[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_174[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_175[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_175[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_176[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_176[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_177[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_177[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_178[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_178[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_179[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_179[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_180[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_180[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_181[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_181[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_182[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_182[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_183[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_183[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_184[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_184[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_185[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_185[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_186[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_186[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_187[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_187[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_188[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_188[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_189[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_189[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_190[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_190[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_191[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_191[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_192[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_192[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_193[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_193[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_194[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_194[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_195[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_195[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_196[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_196[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_197[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_197[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_198[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_198[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_199[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_199[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_200[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_200[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_201[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_201[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_202[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_202[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_203[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_203[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_204[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_204[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_205[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_205[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_206[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_206[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_207[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_207[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_208[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_208[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_209[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_209[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_210[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_210[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_211[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_211[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_212[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_212[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_213[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_213[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_214[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_214[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_215[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_215[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_216[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_216[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_217[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_217[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_218[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_218[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_219[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_219[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_220[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_220[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_221[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_221[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_222[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_222[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_223[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_223[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_224[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_224[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_225[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_225[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_226[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_226[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_227[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_227[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_228[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_228[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_229[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_229[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_230[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_230[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_231[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_231[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_232[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_232[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_233[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_233[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_234[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_234[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_235[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_235[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_236[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_236[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_237[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_237[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_238[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_238[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_239[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_239[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_240[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_240[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_241[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_241[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_242[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_242[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_243[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_243[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_244[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_244[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_245[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_245[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_246[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_246[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_247[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_247[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_248[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_248[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_249[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_249[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_250[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_250[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_251[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_251[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_252[] = {};
static uint8_t argsz_252[] = {};
static syscall_argtype_t argt_253[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_253[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_254[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_254[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_255[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_255[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_256[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_256[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_257[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_257[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_258[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_258[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_259[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_259[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_260[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_260[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_261[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_261[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_262[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_262[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_263[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_263[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_264[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_264[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_265[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_265[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_266[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_266[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_267[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_267[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_268[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_268[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_269[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_269[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_270[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_270[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_271[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_271[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_272[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_272[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_273[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_273[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_274[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_274[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_275[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_275[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_276[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_276[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_277[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_277[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_278[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_278[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_279[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_279[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_280[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_280[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_281[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_281[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_282[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_282[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_283[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_283[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_284[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_284[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_285[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE};
static uint8_t argsz_285[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_286[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_286[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_287[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_287[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_288[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_288[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_289[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_289[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_290[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_290[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_291[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_291[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_292[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_292[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_293[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_293[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_294[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_294[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_295[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_295[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_296[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_296[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_297[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_297[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_298[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_298[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_299[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_299[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_300[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_300[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_301[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_301[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_302[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_302[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_303[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_303[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_304[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_304[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_305[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_305[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_306[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_306[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_307[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_307[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_308[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_308[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_309[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_309[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_310[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_310[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_311[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_311[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_312[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_312[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_313[] = {};
static uint8_t argsz_313[] = {};
static syscall_argtype_t argt_314[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_314[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_315[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_315[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_316[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_316[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_317[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_317[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_318[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_318[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_319[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_319[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_320[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_320[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_321[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_321[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_322[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_322[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_323[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_323[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_324[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_324[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_325[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_325[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_326[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_326[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_327[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_327[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_328[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_328[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_329[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_329[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_330[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_330[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_331[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_331[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_332[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_332[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_333[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_333[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_334[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_334[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_335[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_335[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_336[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_336[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_337[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_337[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_338[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_338[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_339[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_339[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_340[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_340[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_341[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_341[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_342[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_342[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_343[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_343[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_344[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_344[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_345[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_345[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_346[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_346[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_347[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_347[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_348[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_348[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_349[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_349[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_350[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_350[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_351[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_351[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_352[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_352[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_353[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_353[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_354[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE};
static uint8_t argsz_354[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_355[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_355[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_356[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_356[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_357[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_357[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_358[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_358[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_359[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_359[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_360[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_360[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_361[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_361[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_362[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_362[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_363[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_363[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_364[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_364[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_365[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_365[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_366[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_366[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_367[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_367[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_368[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_368[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_369[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_369[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_370[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_370[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_371[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_371[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_372[] = {};
static uint8_t argsz_372[] = {};
static syscall_argtype_t argt_373[] = {};
static uint8_t argsz_373[] = {};
static syscall_argtype_t argt_374[] = {};
static uint8_t argsz_374[] = {};
static syscall_argtype_t argt_375[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_375[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_376[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_376[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_377[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_377[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_378[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_378[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_379[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_379[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_380[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_380[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_381[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_381[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_382[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_382[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_383[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_383[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_384[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_384[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_385[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_385[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_386[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_386[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_387[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_387[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_388[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_388[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_389[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_389[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_390[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_390[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_391[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_391[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_392[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_392[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_393[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_393[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_394[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_394[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_395[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_395[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_396[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_396[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_397[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_397[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_398[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_398[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_399[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_399[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_400[] = {};
static uint8_t argsz_400[] = {};


syscall_info_t __syscall_info_a[] = {
	/* note that uninitialized values will be zeroed-out */
	[0] = {
		.no = 0,
		.name = "NtAcceptConnectPort",
		.nargs = 6,
		.argt = argt_0,
		.argsz = argsz_0
	},
	[1] = {
		.no = 1,
		.name = "NtAccessCheck",
		.nargs = 8,
		.argt = argt_1,
		.argsz = argsz_1
	},
	[2] = {
		.no = 2,
		.name = "NtAccessCheckAndAuditAlarm",
		.nargs = 11,
		.argt = argt_2,
		.argsz = argsz_2
	},
	[3] = {
		.no = 3,
		.name = "NtAccessCheckByType",
		.nargs = 11,
		.argt = argt_3,
		.argsz = argsz_3
	},
	[4] = {
		.no = 4,
		.name = "NtAccessCheckByTypeAndAuditAlarm",
		.nargs = 16,
		.argt = argt_4,
		.argsz = argsz_4
	},
	[5] = {
		.no = 5,
		.name = "NtAccessCheckByTypeResultList",
		.nargs = 11,
		.argt = argt_5,
		.argsz = argsz_5
	},
	[6] = {
		.no = 6,
		.name = "NtAccessCheckByTypeResultListAndAuditAlarm",
		.nargs = 16,
		.argt = argt_6,
		.argsz = argsz_6
	},
	[7] = {
		.no = 7,
		.name = "NtAccessCheckByTypeResultListAndAuditAlarmByHandle",
		.nargs = 17,
		.argt = argt_7,
		.argsz = argsz_7
	},
	[8] = {
		.no = 8,
		.name = "NtAddAtom",
		.nargs = 3,
		.argt = argt_8,
		.argsz = argsz_8
	},
	[9] = {
		.no = 9,
		.name = "NtAddBootEntry",
		.nargs = 2,
		.argt = argt_9,
		.argsz = argsz_9
	},
	[10] = {
		.no = 10,
		.name = "NtAddDriverEntry",
		.nargs = 2,
		.argt = argt_10,
		.argsz = argsz_10
	},
	[11] = {
		.no = 11,
		.name = "NtAdjustGroupsToken",
		.nargs = 6,
		.argt = argt_11,
		.argsz = argsz_11
	},
	[12] = {
		.no = 12,
		.name = "NtAdjustPrivilegesToken",
		.nargs = 6,
		.argt = argt_12,
		.argsz = argsz_12
	},
	[13] = {
		.no = 13,
		.name = "NtAlertResumeThread",
		.nargs = 2,
		.argt = argt_13,
		.argsz = argsz_13
	},
	[14] = {
		.no = 14,
		.name = "NtAlertThread",
		.nargs = 1,
		.argt = argt_14,
		.argsz = argsz_14
	},
	[15] = {
		.no = 15,
		.name = "NtAllocateLocallyUniqueId",
		.nargs = 1,
		.argt = argt_15,
		.argsz = argsz_15
	},
	[16] = {
		.no = 16,
		.name = "NtAllocateReserveObject",
		.nargs = 3,
		.argt = argt_16,
		.argsz = argsz_16
	},
	[17] = {
		.no = 17,
		.name = "NtAllocateUserPhysicalPages",
		.nargs = 3,
		.argt = argt_17,
		.argsz = argsz_17
	},
	[18] = {
		.no = 18,
		.name = "NtAllocateUuids",
		.nargs = 4,
		.argt = argt_18,
		.argsz = argsz_18
	},
	[19] = {
		.no = 19,
		.name = "NtAllocateVirtualMemory",
		.nargs = 6,
		.argt = argt_19,
		.argsz = argsz_19
	},
	[20] = {
		.no = 20,
		.name = "NtAlpcAcceptConnectPort",
		.nargs = 9,
		.argt = argt_20,
		.argsz = argsz_20
	},
	[21] = {
		.no = 21,
		.name = "NtAlpcCancelMessage",
		.nargs = 3,
		.argt = argt_21,
		.argsz = argsz_21
	},
	[22] = {
		.no = 22,
		.name = "NtAlpcConnectPort",
		.nargs = 11,
		.argt = argt_22,
		.argsz = argsz_22
	},
	[23] = {
		.no = 23,
		.name = "NtAlpcCreatePort",
		.nargs = 3,
		.argt = argt_23,
		.argsz = argsz_23
	},
	[24] = {
		.no = 24,
		.name = "NtAlpcCreatePortSection",
		.nargs = 6,
		.argt = argt_24,
		.argsz = argsz_24
	},
	[25] = {
		.no = 25,
		.name = "NtAlpcCreateResourceReserve",
		.nargs = 4,
		.argt = argt_25,
		.argsz = argsz_25
	},
	[26] = {
		.no = 26,
		.name = "NtAlpcCreateSectionView",
		.nargs = 3,
		.argt = argt_26,
		.argsz = argsz_26
	},
	[27] = {
		.no = 27,
		.name = "NtAlpcCreateSecurityContext",
		.nargs = 3,
		.argt = argt_27,
		.argsz = argsz_27
	},
	[28] = {
		.no = 28,
		.name = "NtAlpcDeletePortSection",
		.nargs = 3,
		.argt = argt_28,
		.argsz = argsz_28
	},
	[29] = {
		.no = 29,
		.name = "NtAlpcDeleteResourceReserve",
		.nargs = 3,
		.argt = argt_29,
		.argsz = argsz_29
	},
	[30] = {
		.no = 30,
		.name = "NtAlpcDeleteSectionView",
		.nargs = 3,
		.argt = argt_30,
		.argsz = argsz_30
	},
	[31] = {
		.no = 31,
		.name = "NtAlpcDeleteSecurityContext",
		.nargs = 3,
		.argt = argt_31,
		.argsz = argsz_31
	},
	[32] = {
		.no = 32,
		.name = "NtAlpcDisconnectPort",
		.nargs = 2,
		.argt = argt_32,
		.argsz = argsz_32
	},
	[33] = {
		.no = 33,
		.name = "NtAlpcImpersonateClientOfPort",
		.nargs = 3,
		.argt = argt_33,
		.argsz = argsz_33
	},
	[34] = {
		.no = 34,
		.name = "NtAlpcOpenSenderProcess",
		.nargs = 6,
		.argt = argt_34,
		.argsz = argsz_34
	},
	[35] = {
		.no = 35,
		.name = "NtAlpcOpenSenderThread",
		.nargs = 6,
		.argt = argt_35,
		.argsz = argsz_35
	},
	[36] = {
		.no = 36,
		.name = "NtAlpcQueryInformation",
		.nargs = 5,
		.argt = argt_36,
		.argsz = argsz_36
	},
	[37] = {
		.no = 37,
		.name = "NtAlpcQueryInformationMessage",
		.nargs = 6,
		.argt = argt_37,
		.argsz = argsz_37
	},
	[38] = {
		.no = 38,
		.name = "NtAlpcRevokeSecurityContext",
		.nargs = 3,
		.argt = argt_38,
		.argsz = argsz_38
	},
	[39] = {
		.no = 39,
		.name = "NtAlpcSendWaitReceivePort",
		.nargs = 8,
		.argt = argt_39,
		.argsz = argsz_39
	},
	[40] = {
		.no = 40,
		.name = "NtAlpcSetInformation",
		.nargs = 4,
		.argt = argt_40,
		.argsz = argsz_40
	},
	[41] = {
		.no = 41,
		.name = "NtApphelpCacheControl",
		.nargs = 2,
		.argt = argt_41,
		.argsz = argsz_41
	},
	[42] = {
		.no = 42,
		.name = "NtAreMappedFilesTheSame",
		.nargs = 2,
		.argt = argt_42,
		.argsz = argsz_42
	},
	[43] = {
		.no = 43,
		.name = "NtAssignProcessToJobObject",
		.nargs = 2,
		.argt = argt_43,
		.argsz = argsz_43
	},
	[44] = {
		.no = 44,
		.name = "NtCallbackReturn",
		.nargs = 3,
		.argt = argt_44,
		.argsz = argsz_44
	},
	[45] = {
		.no = 45,
		.name = "NtCancelIoFile",
		.nargs = 2,
		.argt = argt_45,
		.argsz = argsz_45
	},
	[46] = {
		.no = 46,
		.name = "NtCancelIoFileEx",
		.nargs = 3,
		.argt = argt_46,
		.argsz = argsz_46
	},
	[47] = {
		.no = 47,
		.name = "NtCancelSynchronousIoFile",
		.nargs = 3,
		.argt = argt_47,
		.argsz = argsz_47
	},
	[48] = {
		.no = 48,
		.name = "NtCancelTimer",
		.nargs = 2,
		.argt = argt_48,
		.argsz = argsz_48
	},
	[49] = {
		.no = 49,
		.name = "NtClearEvent",
		.nargs = 1,
		.argt = argt_49,
		.argsz = argsz_49
	},
	[50] = {
		.no = 50,
		.name = "NtClose",
		.nargs = 1,
		.argt = argt_50,
		.argsz = argsz_50
	},
	[51] = {
		.no = 51,
		.name = "NtCloseObjectAuditAlarm",
		.nargs = 3,
		.argt = argt_51,
		.argsz = argsz_51
	},
	[52] = {
		.no = 52,
		.name = "NtCommitComplete",
		.nargs = 2,
		.argt = argt_52,
		.argsz = argsz_52
	},
	[53] = {
		.no = 53,
		.name = "NtCommitEnlistment",
		.nargs = 2,
		.argt = argt_53,
		.argsz = argsz_53
	},
	[54] = {
		.no = 54,
		.name = "NtCommitTransaction",
		.nargs = 2,
		.argt = argt_54,
		.argsz = argsz_54
	},
	[55] = {
		.no = 55,
		.name = "NtCompactKeys",
		.nargs = 2,
		.argt = argt_55,
		.argsz = argsz_55
	},
	[56] = {
		.no = 56,
		.name = "NtCompareTokens",
		.nargs = 3,
		.argt = argt_56,
		.argsz = argsz_56
	},
	[57] = {
		.no = 57,
		.name = "NtCompleteConnectPort",
		.nargs = 1,
		.argt = argt_57,
		.argsz = argsz_57
	},
	[58] = {
		.no = 58,
		.name = "NtCompressKey",
		.nargs = 1,
		.argt = argt_58,
		.argsz = argsz_58
	},
	[59] = {
		.no = 59,
		.name = "NtConnectPort",
		.nargs = 8,
		.argt = argt_59,
		.argsz = argsz_59
	},
	[60] = {
		.no = 60,
		.name = "NtContinue",
		.nargs = 2,
		.argt = argt_60,
		.argsz = argsz_60
	},
	[61] = {
		.no = 61,
		.name = "NtCreateDebugObject",
		.nargs = 4,
		.argt = argt_61,
		.argsz = argsz_61
	},
	[62] = {
		.no = 62,
		.name = "NtCreateDirectoryObject",
		.nargs = 3,
		.argt = argt_62,
		.argsz = argsz_62
	},
	[63] = {
		.no = 63,
		.name = "NtCreateEnlistment",
		.nargs = 8,
		.argt = argt_63,
		.argsz = argsz_63
	},
	[64] = {
		.no = 64,
		.name = "NtCreateEvent",
		.nargs = 5,
		.argt = argt_64,
		.argsz = argsz_64
	},
	[65] = {
		.no = 65,
		.name = "NtCreateEventPair",
		.nargs = 3,
		.argt = argt_65,
		.argsz = argsz_65
	},
	[66] = {
		.no = 66,
		.name = "NtCreateFile",
		.nargs = 11,
		.argt = argt_66,
		.argsz = argsz_66
	},
	[67] = {
		.no = 67,
		.name = "NtCreateIoCompletion",
		.nargs = 4,
		.argt = argt_67,
		.argsz = argsz_67
	},
	[68] = {
		.no = 68,
		.name = "NtCreateJobObject",
		.nargs = 3,
		.argt = argt_68,
		.argsz = argsz_68
	},
	[69] = {
		.no = 69,
		.name = "NtCreateJobSet",
		.nargs = 3,
		.argt = argt_69,
		.argsz = argsz_69
	},
	[70] = {
		.no = 70,
		.name = "NtCreateKey",
		.nargs = 7,
		.argt = argt_70,
		.argsz = argsz_70
	},
	[71] = {
		.no = 71,
		.name = "NtCreateKeyedEvent",
		.nargs = 4,
		.argt = argt_71,
		.argsz = argsz_71
	},
	[72] = {
		.no = 72,
		.name = "NtCreateKeyTransacted",
		.nargs = 8,
		.argt = argt_72,
		.argsz = argsz_72
	},
	[73] = {
		.no = 73,
		.name = "NtCreateMailslotFile",
		.nargs = 8,
		.argt = argt_73,
		.argsz = argsz_73
	},
	[74] = {
		.no = 74,
		.name = "NtCreateMutant",
		.nargs = 4,
		.argt = argt_74,
		.argsz = argsz_74
	},
	[75] = {
		.no = 75,
		.name = "NtCreateNamedPipeFile",
		.nargs = 14,
		.argt = argt_75,
		.argsz = argsz_75
	},
	[76] = {
		.no = 76,
		.name = "NtCreatePagingFile",
		.nargs = 4,
		.argt = argt_76,
		.argsz = argsz_76
	},
	[77] = {
		.no = 77,
		.name = "NtCreatePort",
		.nargs = 5,
		.argt = argt_77,
		.argsz = argsz_77
	},
	[78] = {
		.no = 78,
		.name = "NtCreatePrivateNamespace",
		.nargs = 4,
		.argt = argt_78,
		.argsz = argsz_78
	},
	[79] = {
		.no = 79,
		.name = "NtCreateProcess",
		.nargs = 8,
		.argt = argt_79,
		.argsz = argsz_79
	},
	[80] = {
		.no = 80,
		.name = "NtCreateProcessEx",
		.nargs = 9,
		.argt = argt_80,
		.argsz = argsz_80
	},
	[81] = {
		.no = 81,
		.name = "NtCreateProfile",
		.nargs = 9,
		.argt = argt_81,
		.argsz = argsz_81
	},
	[82] = {
		.no = 82,
		.name = "NtCreateProfileEx",
		.nargs = 10,
		.argt = argt_82,
		.argsz = argsz_82
	},
	[83] = {
		.no = 83,
		.name = "NtCreateResourceManager",
		.nargs = 7,
		.argt = argt_83,
		.argsz = argsz_83
	},
	[84] = {
		.no = 84,
		.name = "NtCreateSection",
		.nargs = 7,
		.argt = argt_84,
		.argsz = argsz_84
	},
	[85] = {
		.no = 85,
		.name = "NtCreateSemaphore",
		.nargs = 5,
		.argt = argt_85,
		.argsz = argsz_85
	},
	[86] = {
		.no = 86,
		.name = "NtCreateSymbolicLinkObject",
		.nargs = 4,
		.argt = argt_86,
		.argsz = argsz_86
	},
	[87] = {
		.no = 87,
		.name = "NtCreateThread",
		.nargs = 8,
		.argt = argt_87,
		.argsz = argsz_87
	},
	[88] = {
		.no = 88,
		.name = "NtCreateThreadEx",
		.nargs = 11,
		.argt = argt_88,
		.argsz = argsz_88
	},
	[89] = {
		.no = 89,
		.name = "NtCreateTimer",
		.nargs = 4,
		.argt = argt_89,
		.argsz = argsz_89
	},
	[90] = {
		.no = 90,
		.name = "NtCreateToken",
		.nargs = 13,
		.argt = argt_90,
		.argsz = argsz_90
	},
	[91] = {
		.no = 91,
		.name = "NtCreateTransaction",
		.nargs = 10,
		.argt = argt_91,
		.argsz = argsz_91
	},
	[92] = {
		.no = 92,
		.name = "NtCreateTransactionManager",
		.nargs = 6,
		.argt = argt_92,
		.argsz = argsz_92
	},
	[93] = {
		.no = 93,
		.name = "NtCreateUserProcess",
		.nargs = 11,
		.argt = argt_93,
		.argsz = argsz_93
	},
	[94] = {
		.no = 94,
		.name = "NtCreateWaitablePort",
		.nargs = 5,
		.argt = argt_94,
		.argsz = argsz_94
	},
	[95] = {
		.no = 95,
		.name = "NtCreateWorkerFactory",
		.nargs = 10,
		.argt = argt_95,
		.argsz = argsz_95
	},
	[96] = {
		.no = 96,
		.name = "NtDebugActiveProcess",
		.nargs = 2,
		.argt = argt_96,
		.argsz = argsz_96
	},
	[97] = {
		.no = 97,
		.name = "NtDebugContinue",
		.nargs = 3,
		.argt = argt_97,
		.argsz = argsz_97
	},
	[98] = {
		.no = 98,
		.name = "NtDelayExecution",
		.nargs = 2,
		.argt = argt_98,
		.argsz = argsz_98
	},
	[99] = {
		.no = 99,
		.name = "NtDeleteAtom",
		.nargs = 1,
		.argt = argt_99,
		.argsz = argsz_99
	},
	[100] = {
		.no = 100,
		.name = "NtDeleteBootEntry",
		.nargs = 1,
		.argt = argt_100,
		.argsz = argsz_100
	},
	[101] = {
		.no = 101,
		.name = "NtDeleteDriverEntry",
		.nargs = 1,
		.argt = argt_101,
		.argsz = argsz_101
	},
	[102] = {
		.no = 102,
		.name = "NtDeleteFile",
		.nargs = 1,
		.argt = argt_102,
		.argsz = argsz_102
	},
	[103] = {
		.no = 103,
		.name = "NtDeleteKey",
		.nargs = 1,
		.argt = argt_103,
		.argsz = argsz_103
	},
	[104] = {
		.no = 104,
		.name = "NtDeleteObjectAuditAlarm",
		.nargs = 3,
		.argt = argt_104,
		.argsz = argsz_104
	},
	[105] = {
		.no = 105,
		.name = "NtDeletePrivateNamespace",
		.nargs = 1,
		.argt = argt_105,
		.argsz = argsz_105
	},
	[106] = {
		.no = 106,
		.name = "NtDeleteValueKey",
		.nargs = 2,
		.argt = argt_106,
		.argsz = argsz_106
	},
	[107] = {
		.no = 107,
		.name = "NtDeviceIoControlFile",
		.nargs = 10,
		.argt = argt_107,
		.argsz = argsz_107
	},
	[108] = {
		.no = 108,
		.name = "NtDisableLastKnownGood",
		.nargs = 0,
		.argt = argt_108,
		.argsz = argsz_108
	},
	[109] = {
		.no = 109,
		.name = "NtDisplayString",
		.nargs = 1,
		.argt = argt_109,
		.argsz = argsz_109
	},
	[110] = {
		.no = 110,
		.name = "NtDrawText",
		.nargs = 1,
		.argt = argt_110,
		.argsz = argsz_110
	},
	[111] = {
		.no = 111,
		.name = "NtDuplicateObject",
		.nargs = 7,
		.argt = argt_111,
		.argsz = argsz_111
	},
	[112] = {
		.no = 112,
		.name = "NtDuplicateToken",
		.nargs = 6,
		.argt = argt_112,
		.argsz = argsz_112
	},
	[113] = {
		.no = 113,
		.name = "NtEnableLastKnownGood",
		.nargs = 0,
		.argt = argt_113,
		.argsz = argsz_113
	},
	[114] = {
		.no = 114,
		.name = "NtEnumerateBootEntries",
		.nargs = 2,
		.argt = argt_114,
		.argsz = argsz_114
	},
	[115] = {
		.no = 115,
		.name = "NtEnumerateDriverEntries",
		.nargs = 2,
		.argt = argt_115,
		.argsz = argsz_115
	},
	[116] = {
		.no = 116,
		.name = "NtEnumerateKey",
		.nargs = 6,
		.argt = argt_116,
		.argsz = argsz_116
	},
	[117] = {
		.no = 117,
		.name = "NtEnumerateSystemEnvironmentValuesEx",
		.nargs = 3,
		.argt = argt_117,
		.argsz = argsz_117
	},
	[118] = {
		.no = 118,
		.name = "NtEnumerateTransactionObject",
		.nargs = 5,
		.argt = argt_118,
		.argsz = argsz_118
	},
	[119] = {
		.no = 119,
		.name = "NtEnumerateValueKey",
		.nargs = 6,
		.argt = argt_119,
		.argsz = argsz_119
	},
	[120] = {
		.no = 120,
		.name = "NtExtendSection",
		.nargs = 2,
		.argt = argt_120,
		.argsz = argsz_120
	},
	[121] = {
		.no = 121,
		.name = "NtFilterToken",
		.nargs = 6,
		.argt = argt_121,
		.argsz = argsz_121
	},
	[122] = {
		.no = 122,
		.name = "NtFindAtom",
		.nargs = 3,
		.argt = argt_122,
		.argsz = argsz_122
	},
	[123] = {
		.no = 123,
		.name = "NtFlushBuffersFile",
		.nargs = 2,
		.argt = argt_123,
		.argsz = argsz_123
	},
	[124] = {
		.no = 124,
		.name = "NtFlushInstallUILanguage",
		.nargs = 2,
		.argt = argt_124,
		.argsz = argsz_124
	},
	[125] = {
		.no = 125,
		.name = "NtFlushInstructionCache",
		.nargs = 3,
		.argt = argt_125,
		.argsz = argsz_125
	},
	[126] = {
		.no = 126,
		.name = "NtFlushKey",
		.nargs = 1,
		.argt = argt_126,
		.argsz = argsz_126
	},
	[127] = {
		.no = 127,
		.name = "NtFlushProcessWriteBuffers",
		.nargs = 0,
		.argt = argt_127,
		.argsz = argsz_127
	},
	[128] = {
		.no = 128,
		.name = "NtFlushVirtualMemory",
		.nargs = 4,
		.argt = argt_128,
		.argsz = argsz_128
	},
	[129] = {
		.no = 129,
		.name = "NtFlushWriteBuffer",
		.nargs = 0,
		.argt = argt_129,
		.argsz = argsz_129
	},
	[130] = {
		.no = 130,
		.name = "NtFreeUserPhysicalPages",
		.nargs = 3,
		.argt = argt_130,
		.argsz = argsz_130
	},
	[131] = {
		.no = 131,
		.name = "NtFreeVirtualMemory",
		.nargs = 4,
		.argt = argt_131,
		.argsz = argsz_131
	},
	[132] = {
		.no = 132,
		.name = "NtFreezeRegistry",
		.nargs = 1,
		.argt = argt_132,
		.argsz = argsz_132
	},
	[133] = {
		.no = 133,
		.name = "NtFreezeTransactions",
		.nargs = 2,
		.argt = argt_133,
		.argsz = argsz_133
	},
	[134] = {
		.no = 134,
		.name = "NtFsControlFile",
		.nargs = 10,
		.argt = argt_134,
		.argsz = argsz_134
	},
	[135] = {
		.no = 135,
		.name = "NtGetContextThread",
		.nargs = 2,
		.argt = argt_135,
		.argsz = argsz_135
	},
	[136] = {
		.no = 136,
		.name = "NtGetCurrentProcessorNumber",
		.nargs = 0,
		.argt = argt_136,
		.argsz = argsz_136
	},
	[137] = {
		.no = 137,
		.name = "NtGetDevicePowerState",
		.nargs = 2,
		.argt = argt_137,
		.argsz = argsz_137
	},
	[138] = {
		.no = 138,
		.name = "NtGetMUIRegistryInfo",
		.nargs = 3,
		.argt = argt_138,
		.argsz = argsz_138
	},
	[139] = {
		.no = 139,
		.name = "NtGetNextProcess",
		.nargs = 5,
		.argt = argt_139,
		.argsz = argsz_139
	},
	[140] = {
		.no = 140,
		.name = "NtGetNextThread",
		.nargs = 6,
		.argt = argt_140,
		.argsz = argsz_140
	},
	[141] = {
		.no = 141,
		.name = "NtGetNlsSectionPtr",
		.nargs = 5,
		.argt = argt_141,
		.argsz = argsz_141
	},
	[142] = {
		.no = 142,
		.name = "NtGetNotificationResourceManager",
		.nargs = 7,
		.argt = argt_142,
		.argsz = argsz_142
	},
	[143] = {
		.no = 143,
		.name = "NtGetPlugPlayEvent",
		.nargs = 4,
		.argt = argt_143,
		.argsz = argsz_143
	},
	[144] = {
		.no = 144,
		.name = "NtGetWriteWatch",
		.nargs = 7,
		.argt = argt_144,
		.argsz = argsz_144
	},
	[145] = {
		.no = 145,
		.name = "NtImpersonateAnonymousToken",
		.nargs = 1,
		.argt = argt_145,
		.argsz = argsz_145
	},
	[146] = {
		.no = 146,
		.name = "NtImpersonateClientOfPort",
		.nargs = 2,
		.argt = argt_146,
		.argsz = argsz_146
	},
	[147] = {
		.no = 147,
		.name = "NtImpersonateThread",
		.nargs = 3,
		.argt = argt_147,
		.argsz = argsz_147
	},
	[148] = {
		.no = 148,
		.name = "NtInitializeNlsFiles",
		.nargs = 3,
		.argt = argt_148,
		.argsz = argsz_148
	},
	[149] = {
		.no = 149,
		.name = "NtInitializeRegistry",
		.nargs = 1,
		.argt = argt_149,
		.argsz = argsz_149
	},
	[150] = {
		.no = 150,
		.name = "NtInitiatePowerAction",
		.nargs = 4,
		.argt = argt_150,
		.argsz = argsz_150
	},
	[151] = {
		.no = 151,
		.name = "NtIsProcessInJob",
		.nargs = 2,
		.argt = argt_151,
		.argsz = argsz_151
	},
	[152] = {
		.no = 152,
		.name = "NtIsSystemResumeAutomatic",
		.nargs = 0,
		.argt = argt_152,
		.argsz = argsz_152
	},
	[153] = {
		.no = 153,
		.name = "NtIsUILanguageComitted",
		.nargs = 0,
		.argt = argt_153,
		.argsz = argsz_153
	},
	[154] = {
		.no = 154,
		.name = "NtListenPort",
		.nargs = 2,
		.argt = argt_154,
		.argsz = argsz_154
	},
	[155] = {
		.no = 155,
		.name = "NtLoadDriver",
		.nargs = 1,
		.argt = argt_155,
		.argsz = argsz_155
	},
	[156] = {
		.no = 156,
		.name = "NtLoadKey",
		.nargs = 2,
		.argt = argt_156,
		.argsz = argsz_156
	},
	[157] = {
		.no = 157,
		.name = "NtLoadKey2",
		.nargs = 3,
		.argt = argt_157,
		.argsz = argsz_157
	},
	[158] = {
		.no = 158,
		.name = "NtLoadKeyEx",
		.nargs = 4,
		.argt = argt_158,
		.argsz = argsz_158
	},
	[159] = {
		.no = 159,
		.name = "NtLockFile",
		.nargs = 10,
		.argt = argt_159,
		.argsz = argsz_159
	},
	[160] = {
		.no = 160,
		.name = "NtLockProductActivationKeys",
		.nargs = 2,
		.argt = argt_160,
		.argsz = argsz_160
	},
	[161] = {
		.no = 161,
		.name = "NtLockRegistryKey",
		.nargs = 1,
		.argt = argt_161,
		.argsz = argsz_161
	},
	[162] = {
		.no = 162,
		.name = "NtLockVirtualMemory",
		.nargs = 4,
		.argt = argt_162,
		.argsz = argsz_162
	},
	[163] = {
		.no = 163,
		.name = "NtMakePermanentObject",
		.nargs = 1,
		.argt = argt_163,
		.argsz = argsz_163
	},
	[164] = {
		.no = 164,
		.name = "NtMakeTemporaryObject",
		.nargs = 1,
		.argt = argt_164,
		.argsz = argsz_164
	},
	[165] = {
		.no = 165,
		.name = "NtMapCMFModule",
		.nargs = 6,
		.argt = argt_165,
		.argsz = argsz_165
	},
	[166] = {
		.no = 166,
		.name = "NtMapUserPhysicalPages",
		.nargs = 3,
		.argt = argt_166,
		.argsz = argsz_166
	},
	[167] = {
		.no = 167,
		.name = "NtMapUserPhysicalPagesScatter",
		.nargs = 3,
		.argt = argt_167,
		.argsz = argsz_167
	},
	[168] = {
		.no = 168,
		.name = "NtMapViewOfSection",
		.nargs = 10,
		.argt = argt_168,
		.argsz = argsz_168
	},
	[169] = {
		.no = 169,
		.name = "NtModifyBootEntry",
		.nargs = 1,
		.argt = argt_169,
		.argsz = argsz_169
	},
	[170] = {
		.no = 170,
		.name = "NtModifyDriverEntry",
		.nargs = 1,
		.argt = argt_170,
		.argsz = argsz_170
	},
	[171] = {
		.no = 171,
		.name = "NtNotifyChangeDirectoryFile",
		.nargs = 9,
		.argt = argt_171,
		.argsz = argsz_171
	},
	[172] = {
		.no = 172,
		.name = "NtNotifyChangeKey",
		.nargs = 10,
		.argt = argt_172,
		.argsz = argsz_172
	},
	[173] = {
		.no = 173,
		.name = "NtNotifyChangeMultipleKeys",
		.nargs = 12,
		.argt = argt_173,
		.argsz = argsz_173
	},
	[174] = {
		.no = 174,
		.name = "NtNotifyChangeSession",
		.nargs = 8,
		.argt = argt_174,
		.argsz = argsz_174
	},
	[175] = {
		.no = 175,
		.name = "NtOpenDirectoryObject",
		.nargs = 3,
		.argt = argt_175,
		.argsz = argsz_175
	},
	[176] = {
		.no = 176,
		.name = "NtOpenEnlistment",
		.nargs = 5,
		.argt = argt_176,
		.argsz = argsz_176
	},
	[177] = {
		.no = 177,
		.name = "NtOpenEvent",
		.nargs = 3,
		.argt = argt_177,
		.argsz = argsz_177
	},
	[178] = {
		.no = 178,
		.name = "NtOpenEventPair",
		.nargs = 3,
		.argt = argt_178,
		.argsz = argsz_178
	},
	[179] = {
		.no = 179,
		.name = "NtOpenFile",
		.nargs = 6,
		.argt = argt_179,
		.argsz = argsz_179
	},
	[180] = {
		.no = 180,
		.name = "NtOpenIoCompletion",
		.nargs = 3,
		.argt = argt_180,
		.argsz = argsz_180
	},
	[181] = {
		.no = 181,
		.name = "NtOpenJobObject",
		.nargs = 3,
		.argt = argt_181,
		.argsz = argsz_181
	},
	[182] = {
		.no = 182,
		.name = "NtOpenKey",
		.nargs = 3,
		.argt = argt_182,
		.argsz = argsz_182
	},
	[183] = {
		.no = 183,
		.name = "NtOpenKeyEx",
		.nargs = 4,
		.argt = argt_183,
		.argsz = argsz_183
	},
	[184] = {
		.no = 184,
		.name = "NtOpenKeyedEvent",
		.nargs = 3,
		.argt = argt_184,
		.argsz = argsz_184
	},
	[185] = {
		.no = 185,
		.name = "NtOpenKeyTransacted",
		.nargs = 4,
		.argt = argt_185,
		.argsz = argsz_185
	},
	[186] = {
		.no = 186,
		.name = "NtOpenKeyTransactedEx",
		.nargs = 5,
		.argt = argt_186,
		.argsz = argsz_186
	},
	[187] = {
		.no = 187,
		.name = "NtOpenMutant",
		.nargs = 3,
		.argt = argt_187,
		.argsz = argsz_187
	},
	[188] = {
		.no = 188,
		.name = "NtOpenObjectAuditAlarm",
		.nargs = 12,
		.argt = argt_188,
		.argsz = argsz_188
	},
	[189] = {
		.no = 189,
		.name = "NtOpenPrivateNamespace",
		.nargs = 4,
		.argt = argt_189,
		.argsz = argsz_189
	},
	[190] = {
		.no = 190,
		.name = "NtOpenProcess",
		.nargs = 4,
		.argt = argt_190,
		.argsz = argsz_190
	},
	[191] = {
		.no = 191,
		.name = "NtOpenProcessToken",
		.nargs = 3,
		.argt = argt_191,
		.argsz = argsz_191
	},
	[192] = {
		.no = 192,
		.name = "NtOpenProcessTokenEx",
		.nargs = 4,
		.argt = argt_192,
		.argsz = argsz_192
	},
	[193] = {
		.no = 193,
		.name = "NtOpenResourceManager",
		.nargs = 5,
		.argt = argt_193,
		.argsz = argsz_193
	},
	[194] = {
		.no = 194,
		.name = "NtOpenSection",
		.nargs = 3,
		.argt = argt_194,
		.argsz = argsz_194
	},
	[195] = {
		.no = 195,
		.name = "NtOpenSemaphore",
		.nargs = 3,
		.argt = argt_195,
		.argsz = argsz_195
	},
	[196] = {
		.no = 196,
		.name = "NtOpenSession",
		.nargs = 3,
		.argt = argt_196,
		.argsz = argsz_196
	},
	[197] = {
		.no = 197,
		.name = "NtOpenSymbolicLinkObject",
		.nargs = 3,
		.argt = argt_197,
		.argsz = argsz_197
	},
	[198] = {
		.no = 198,
		.name = "NtOpenThread",
		.nargs = 4,
		.argt = argt_198,
		.argsz = argsz_198
	},
	[199] = {
		.no = 199,
		.name = "NtOpenThreadToken",
		.nargs = 4,
		.argt = argt_199,
		.argsz = argsz_199
	},
	[200] = {
		.no = 200,
		.name = "NtOpenThreadTokenEx",
		.nargs = 5,
		.argt = argt_200,
		.argsz = argsz_200
	},
	[201] = {
		.no = 201,
		.name = "NtOpenTimer",
		.nargs = 3,
		.argt = argt_201,
		.argsz = argsz_201
	},
	[202] = {
		.no = 202,
		.name = "NtOpenTransaction",
		.nargs = 5,
		.argt = argt_202,
		.argsz = argsz_202
	},
	[203] = {
		.no = 203,
		.name = "NtOpenTransactionManager",
		.nargs = 6,
		.argt = argt_203,
		.argsz = argsz_203
	},
	[204] = {
		.no = 204,
		.name = "NtPlugPlayControl",
		.nargs = 3,
		.argt = argt_204,
		.argsz = argsz_204
	},
	[205] = {
		.no = 205,
		.name = "NtPowerInformation",
		.nargs = 5,
		.argt = argt_205,
		.argsz = argsz_205
	},
	[206] = {
		.no = 206,
		.name = "NtPrepareComplete",
		.nargs = 2,
		.argt = argt_206,
		.argsz = argsz_206
	},
	[207] = {
		.no = 207,
		.name = "NtPrepareEnlistment",
		.nargs = 2,
		.argt = argt_207,
		.argsz = argsz_207
	},
	[208] = {
		.no = 208,
		.name = "NtPrePrepareComplete",
		.nargs = 2,
		.argt = argt_208,
		.argsz = argsz_208
	},
	[209] = {
		.no = 209,
		.name = "NtPrePrepareEnlistment",
		.nargs = 2,
		.argt = argt_209,
		.argsz = argsz_209
	},
	[210] = {
		.no = 210,
		.name = "NtPrivilegeCheck",
		.nargs = 3,
		.argt = argt_210,
		.argsz = argsz_210
	},
	[211] = {
		.no = 211,
		.name = "NtPrivilegedServiceAuditAlarm",
		.nargs = 5,
		.argt = argt_211,
		.argsz = argsz_211
	},
	[212] = {
		.no = 212,
		.name = "NtPrivilegeObjectAuditAlarm",
		.nargs = 6,
		.argt = argt_212,
		.argsz = argsz_212
	},
	[213] = {
		.no = 213,
		.name = "NtPropagationComplete",
		.nargs = 4,
		.argt = argt_213,
		.argsz = argsz_213
	},
	[214] = {
		.no = 214,
		.name = "NtPropagationFailed",
		.nargs = 3,
		.argt = argt_214,
		.argsz = argsz_214
	},
	[215] = {
		.no = 215,
		.name = "NtProtectVirtualMemory",
		.nargs = 5,
		.argt = argt_215,
		.argsz = argsz_215
	},
	[216] = {
		.no = 216,
		.name = "NtPulseEvent",
		.nargs = 2,
		.argt = argt_216,
		.argsz = argsz_216
	},
	[217] = {
		.no = 217,
		.name = "NtQueryAttributesFile",
		.nargs = 2,
		.argt = argt_217,
		.argsz = argsz_217
	},
	[218] = {
		.no = 218,
		.name = "NtQueryBootEntryOrder",
		.nargs = 2,
		.argt = argt_218,
		.argsz = argsz_218
	},
	[219] = {
		.no = 219,
		.name = "NtQueryBootOptions",
		.nargs = 2,
		.argt = argt_219,
		.argsz = argsz_219
	},
	[220] = {
		.no = 220,
		.name = "NtQueryDebugFilterState",
		.nargs = 2,
		.argt = argt_220,
		.argsz = argsz_220
	},
	[221] = {
		.no = 221,
		.name = "NtQueryDefaultLocale",
		.nargs = 2,
		.argt = argt_221,
		.argsz = argsz_221
	},
	[222] = {
		.no = 222,
		.name = "NtQueryDefaultUILanguage",
		.nargs = 1,
		.argt = argt_222,
		.argsz = argsz_222
	},
	[223] = {
		.no = 223,
		.name = "NtQueryDirectoryFile",
		.nargs = 11,
		.argt = argt_223,
		.argsz = argsz_223
	},
	[224] = {
		.no = 224,
		.name = "NtQueryDirectoryObject",
		.nargs = 7,
		.argt = argt_224,
		.argsz = argsz_224
	},
	[225] = {
		.no = 225,
		.name = "NtQueryDriverEntryOrder",
		.nargs = 2,
		.argt = argt_225,
		.argsz = argsz_225
	},
	[226] = {
		.no = 226,
		.name = "NtQueryEaFile",
		.nargs = 9,
		.argt = argt_226,
		.argsz = argsz_226
	},
	[227] = {
		.no = 227,
		.name = "NtQueryEvent",
		.nargs = 5,
		.argt = argt_227,
		.argsz = argsz_227
	},
	[228] = {
		.no = 228,
		.name = "NtQueryFullAttributesFile",
		.nargs = 2,
		.argt = argt_228,
		.argsz = argsz_228
	},
	[229] = {
		.no = 229,
		.name = "NtQueryInformationAtom",
		.nargs = 5,
		.argt = argt_229,
		.argsz = argsz_229
	},
	[230] = {
		.no = 230,
		.name = "NtQueryInformationEnlistment",
		.nargs = 5,
		.argt = argt_230,
		.argsz = argsz_230
	},
	[231] = {
		.no = 231,
		.name = "NtQueryInformationFile",
		.nargs = 5,
		.argt = argt_231,
		.argsz = argsz_231
	},
	[232] = {
		.no = 232,
		.name = "NtQueryInformationJobObject",
		.nargs = 5,
		.argt = argt_232,
		.argsz = argsz_232
	},
	[233] = {
		.no = 233,
		.name = "NtQueryInformationPort",
		.nargs = 5,
		.argt = argt_233,
		.argsz = argsz_233
	},
	[234] = {
		.no = 234,
		.name = "NtQueryInformationProcess",
		.nargs = 5,
		.argt = argt_234,
		.argsz = argsz_234
	},
	[235] = {
		.no = 235,
		.name = "NtQueryInformationResourceManager",
		.nargs = 5,
		.argt = argt_235,
		.argsz = argsz_235
	},
	[236] = {
		.no = 236,
		.name = "NtQueryInformationThread",
		.nargs = 5,
		.argt = argt_236,
		.argsz = argsz_236
	},
	[237] = {
		.no = 237,
		.name = "NtQueryInformationToken",
		.nargs = 5,
		.argt = argt_237,
		.argsz = argsz_237
	},
	[238] = {
		.no = 238,
		.name = "NtQueryInformationTransaction",
		.nargs = 5,
		.argt = argt_238,
		.argsz = argsz_238
	},
	[239] = {
		.no = 239,
		.name = "NtQueryInformationTransactionManager",
		.nargs = 5,
		.argt = argt_239,
		.argsz = argsz_239
	},
	[240] = {
		.no = 240,
		.name = "NtQueryInformationWorkerFactory",
		.nargs = 5,
		.argt = argt_240,
		.argsz = argsz_240
	},
	[241] = {
		.no = 241,
		.name = "NtQueryInstallUILanguage",
		.nargs = 1,
		.argt = argt_241,
		.argsz = argsz_241
	},
	[242] = {
		.no = 242,
		.name = "NtQueryIntervalProfile",
		.nargs = 2,
		.argt = argt_242,
		.argsz = argsz_242
	},
	[243] = {
		.no = 243,
		.name = "NtQueryIoCompletion",
		.nargs = 5,
		.argt = argt_243,
		.argsz = argsz_243
	},
	[244] = {
		.no = 244,
		.name = "NtQueryKey",
		.nargs = 5,
		.argt = argt_244,
		.argsz = argsz_244
	},
	[245] = {
		.no = 245,
		.name = "NtQueryLicenseValue",
		.nargs = 5,
		.argt = argt_245,
		.argsz = argsz_245
	},
	[246] = {
		.no = 246,
		.name = "NtQueryMultipleValueKey",
		.nargs = 6,
		.argt = argt_246,
		.argsz = argsz_246
	},
	[247] = {
		.no = 247,
		.name = "NtQueryMutant",
		.nargs = 5,
		.argt = argt_247,
		.argsz = argsz_247
	},
	[248] = {
		.no = 248,
		.name = "NtQueryObject",
		.nargs = 5,
		.argt = argt_248,
		.argsz = argsz_248
	},
	[249] = {
		.no = 249,
		.name = "NtQueryOpenSubKeys",
		.nargs = 2,
		.argt = argt_249,
		.argsz = argsz_249
	},
	[250] = {
		.no = 250,
		.name = "NtQueryOpenSubKeysEx",
		.nargs = 4,
		.argt = argt_250,
		.argsz = argsz_250
	},
	[251] = {
		.no = 251,
		.name = "NtQueryPerformanceCounter",
		.nargs = 2,
		.argt = argt_251,
		.argsz = argsz_251
	},
	[252] = {
		.no = 252,
		.name = "NtQueryPortInformationProcess",
		.nargs = 0,
		.argt = argt_252,
		.argsz = argsz_252
	},
	[253] = {
		.no = 253,
		.name = "NtQueryQuotaInformationFile",
		.nargs = 9,
		.argt = argt_253,
		.argsz = argsz_253
	},
	[254] = {
		.no = 254,
		.name = "NtQuerySection",
		.nargs = 5,
		.argt = argt_254,
		.argsz = argsz_254
	},
	[255] = {
		.no = 255,
		.name = "NtQuerySecurityAttributesToken",
		.nargs = 6,
		.argt = argt_255,
		.argsz = argsz_255
	},
	[256] = {
		.no = 256,
		.name = "NtQuerySecurityObject",
		.nargs = 5,
		.argt = argt_256,
		.argsz = argsz_256
	},
	[257] = {
		.no = 257,
		.name = "NtQuerySemaphore",
		.nargs = 5,
		.argt = argt_257,
		.argsz = argsz_257
	},
	[258] = {
		.no = 258,
		.name = "NtQuerySymbolicLinkObject",
		.nargs = 3,
		.argt = argt_258,
		.argsz = argsz_258
	},
	[259] = {
		.no = 259,
		.name = "NtQuerySystemEnvironmentValue",
		.nargs = 4,
		.argt = argt_259,
		.argsz = argsz_259
	},
	[260] = {
		.no = 260,
		.name = "NtQuerySystemEnvironmentValueEx",
		.nargs = 5,
		.argt = argt_260,
		.argsz = argsz_260
	},
	[261] = {
		.no = 261,
		.name = "NtQuerySystemInformation",
		.nargs = 4,
		.argt = argt_261,
		.argsz = argsz_261
	},
	[262] = {
		.no = 262,
		.name = "NtQuerySystemInformationEx",
		.nargs = 6,
		.argt = argt_262,
		.argsz = argsz_262
	},
	[263] = {
		.no = 263,
		.name = "NtQuerySystemTime",
		.nargs = 1,
		.argt = argt_263,
		.argsz = argsz_263
	},
	[264] = {
		.no = 264,
		.name = "NtQueryTimer",
		.nargs = 5,
		.argt = argt_264,
		.argsz = argsz_264
	},
	[265] = {
		.no = 265,
		.name = "NtQueryTimerResolution",
		.nargs = 3,
		.argt = argt_265,
		.argsz = argsz_265
	},
	[266] = {
		.no = 266,
		.name = "NtQueryValueKey",
		.nargs = 6,
		.argt = argt_266,
		.argsz = argsz_266
	},
	[267] = {
		.no = 267,
		.name = "NtQueryVirtualMemory",
		.nargs = 6,
		.argt = argt_267,
		.argsz = argsz_267
	},
	[268] = {
		.no = 268,
		.name = "NtQueryVolumeInformationFile",
		.nargs = 5,
		.argt = argt_268,
		.argsz = argsz_268
	},
	[269] = {
		.no = 269,
		.name = "NtQueueApcThread",
		.nargs = 5,
		.argt = argt_269,
		.argsz = argsz_269
	},
	[270] = {
		.no = 270,
		.name = "NtQueueApcThreadEx",
		.nargs = 6,
		.argt = argt_270,
		.argsz = argsz_270
	},
	[271] = {
		.no = 271,
		.name = "NtRaiseException",
		.nargs = 3,
		.argt = argt_271,
		.argsz = argsz_271
	},
	[272] = {
		.no = 272,
		.name = "NtRaiseHardError",
		.nargs = 6,
		.argt = argt_272,
		.argsz = argsz_272
	},
	[273] = {
		.no = 273,
		.name = "NtReadFile",
		.nargs = 9,
		.argt = argt_273,
		.argsz = argsz_273
	},
	[274] = {
		.no = 274,
		.name = "NtReadFileScatter",
		.nargs = 9,
		.argt = argt_274,
		.argsz = argsz_274
	},
	[275] = {
		.no = 275,
		.name = "NtReadOnlyEnlistment",
		.nargs = 2,
		.argt = argt_275,
		.argsz = argsz_275
	},
	[276] = {
		.no = 276,
		.name = "NtReadRequestData",
		.nargs = 6,
		.argt = argt_276,
		.argsz = argsz_276
	},
	[277] = {
		.no = 277,
		.name = "NtReadVirtualMemory",
		.nargs = 5,
		.argt = argt_277,
		.argsz = argsz_277
	},
	[278] = {
		.no = 278,
		.name = "NtRecoverEnlistment",
		.nargs = 2,
		.argt = argt_278,
		.argsz = argsz_278
	},
	[279] = {
		.no = 279,
		.name = "NtRecoverResourceManager",
		.nargs = 1,
		.argt = argt_279,
		.argsz = argsz_279
	},
	[280] = {
		.no = 280,
		.name = "NtRecoverTransactionManager",
		.nargs = 1,
		.argt = argt_280,
		.argsz = argsz_280
	},
	[281] = {
		.no = 281,
		.name = "NtRegisterProtocolAddressInformation",
		.nargs = 5,
		.argt = argt_281,
		.argsz = argsz_281
	},
	[282] = {
		.no = 282,
		.name = "NtRegisterThreadTerminatePort",
		.nargs = 1,
		.argt = argt_282,
		.argsz = argsz_282
	},
	[283] = {
		.no = 283,
		.name = "NtReleaseKeyedEvent",
		.nargs = 4,
		.argt = argt_283,
		.argsz = argsz_283
	},
	[284] = {
		.no = 284,
		.name = "NtReleaseMutant",
		.nargs = 2,
		.argt = argt_284,
		.argsz = argsz_284
	},
	[285] = {
		.no = 285,
		.name = "NtReleaseSemaphore",
		.nargs = 3,
		.argt = argt_285,
		.argsz = argsz_285
	},
	[286] = {
		.no = 286,
		.name = "NtReleaseWorkerFactoryWorker",
		.nargs = 1,
		.argt = argt_286,
		.argsz = argsz_286
	},
	[287] = {
		.no = 287,
		.name = "NtRemoveIoCompletion",
		.nargs = 5,
		.argt = argt_287,
		.argsz = argsz_287
	},
	[288] = {
		.no = 288,
		.name = "NtRemoveIoCompletionEx",
		.nargs = 6,
		.argt = argt_288,
		.argsz = argsz_288
	},
	[289] = {
		.no = 289,
		.name = "NtRemoveProcessDebug",
		.nargs = 2,
		.argt = argt_289,
		.argsz = argsz_289
	},
	[290] = {
		.no = 290,
		.name = "NtRenameKey",
		.nargs = 2,
		.argt = argt_290,
		.argsz = argsz_290
	},
	[291] = {
		.no = 291,
		.name = "NtRenameTransactionManager",
		.nargs = 2,
		.argt = argt_291,
		.argsz = argsz_291
	},
	[292] = {
		.no = 292,
		.name = "NtReplaceKey",
		.nargs = 3,
		.argt = argt_292,
		.argsz = argsz_292
	},
	[293] = {
		.no = 293,
		.name = "NtReplacePartitionUnit",
		.nargs = 3,
		.argt = argt_293,
		.argsz = argsz_293
	},
	[294] = {
		.no = 294,
		.name = "NtReplyPort",
		.nargs = 2,
		.argt = argt_294,
		.argsz = argsz_294
	},
	[295] = {
		.no = 295,
		.name = "NtReplyWaitReceivePort",
		.nargs = 4,
		.argt = argt_295,
		.argsz = argsz_295
	},
	[296] = {
		.no = 296,
		.name = "NtReplyWaitReceivePortEx",
		.nargs = 5,
		.argt = argt_296,
		.argsz = argsz_296
	},
	[297] = {
		.no = 297,
		.name = "NtReplyWaitReplyPort",
		.nargs = 2,
		.argt = argt_297,
		.argsz = argsz_297
	},
	[298] = {
		.no = 298,
		.name = "NtRequestPort",
		.nargs = 2,
		.argt = argt_298,
		.argsz = argsz_298
	},
	[299] = {
		.no = 299,
		.name = "NtRequestWaitReplyPort",
		.nargs = 3,
		.argt = argt_299,
		.argsz = argsz_299
	},
	[300] = {
		.no = 300,
		.name = "NtResetEvent",
		.nargs = 2,
		.argt = argt_300,
		.argsz = argsz_300
	},
	[301] = {
		.no = 301,
		.name = "NtResetWriteWatch",
		.nargs = 3,
		.argt = argt_301,
		.argsz = argsz_301
	},
	[302] = {
		.no = 302,
		.name = "NtRestoreKey",
		.nargs = 3,
		.argt = argt_302,
		.argsz = argsz_302
	},
	[303] = {
		.no = 303,
		.name = "NtResumeProcess",
		.nargs = 1,
		.argt = argt_303,
		.argsz = argsz_303
	},
	[304] = {
		.no = 304,
		.name = "NtResumeThread",
		.nargs = 2,
		.argt = argt_304,
		.argsz = argsz_304
	},
	[305] = {
		.no = 305,
		.name = "NtRollbackComplete",
		.nargs = 2,
		.argt = argt_305,
		.argsz = argsz_305
	},
	[306] = {
		.no = 306,
		.name = "NtRollbackEnlistment",
		.nargs = 2,
		.argt = argt_306,
		.argsz = argsz_306
	},
	[307] = {
		.no = 307,
		.name = "NtRollbackTransaction",
		.nargs = 2,
		.argt = argt_307,
		.argsz = argsz_307
	},
	[308] = {
		.no = 308,
		.name = "NtRollforwardTransactionManager",
		.nargs = 2,
		.argt = argt_308,
		.argsz = argsz_308
	},
	[309] = {
		.no = 309,
		.name = "NtSaveKey",
		.nargs = 2,
		.argt = argt_309,
		.argsz = argsz_309
	},
	[310] = {
		.no = 310,
		.name = "NtSaveKeyEx",
		.nargs = 3,
		.argt = argt_310,
		.argsz = argsz_310
	},
	[311] = {
		.no = 311,
		.name = "NtSaveMergedKeys",
		.nargs = 3,
		.argt = argt_311,
		.argsz = argsz_311
	},
	[312] = {
		.no = 312,
		.name = "NtSecureConnectPort",
		.nargs = 9,
		.argt = argt_312,
		.argsz = argsz_312
	},
	[313] = {
		.no = 313,
		.name = "NtSerializeBoot",
		.nargs = 0,
		.argt = argt_313,
		.argsz = argsz_313
	},
	[314] = {
		.no = 314,
		.name = "NtSetBootEntryOrder",
		.nargs = 2,
		.argt = argt_314,
		.argsz = argsz_314
	},
	[315] = {
		.no = 315,
		.name = "NtSetBootOptions",
		.nargs = 2,
		.argt = argt_315,
		.argsz = argsz_315
	},
	[316] = {
		.no = 316,
		.name = "NtSetContextThread",
		.nargs = 2,
		.argt = argt_316,
		.argsz = argsz_316
	},
	[317] = {
		.no = 317,
		.name = "NtSetDebugFilterState",
		.nargs = 3,
		.argt = argt_317,
		.argsz = argsz_317
	},
	[318] = {
		.no = 318,
		.name = "NtSetDefaultHardErrorPort",
		.nargs = 1,
		.argt = argt_318,
		.argsz = argsz_318
	},
	[319] = {
		.no = 319,
		.name = "NtSetDefaultLocale",
		.nargs = 2,
		.argt = argt_319,
		.argsz = argsz_319
	},
	[320] = {
		.no = 320,
		.name = "NtSetDefaultUILanguage",
		.nargs = 1,
		.argt = argt_320,
		.argsz = argsz_320
	},
	[321] = {
		.no = 321,
		.name = "NtSetDriverEntryOrder",
		.nargs = 2,
		.argt = argt_321,
		.argsz = argsz_321
	},
	[322] = {
		.no = 322,
		.name = "NtSetEaFile",
		.nargs = 4,
		.argt = argt_322,
		.argsz = argsz_322
	},
	[323] = {
		.no = 323,
		.name = "NtSetEvent",
		.nargs = 2,
		.argt = argt_323,
		.argsz = argsz_323
	},
	[324] = {
		.no = 324,
		.name = "NtSetEventBoostPriority",
		.nargs = 1,
		.argt = argt_324,
		.argsz = argsz_324
	},
	[325] = {
		.no = 325,
		.name = "NtSetHighEventPair",
		.nargs = 1,
		.argt = argt_325,
		.argsz = argsz_325
	},
	[326] = {
		.no = 326,
		.name = "NtSetHighWaitLowEventPair",
		.nargs = 1,
		.argt = argt_326,
		.argsz = argsz_326
	},
	[327] = {
		.no = 327,
		.name = "NtSetInformationDebugObject",
		.nargs = 5,
		.argt = argt_327,
		.argsz = argsz_327
	},
	[328] = {
		.no = 328,
		.name = "NtSetInformationEnlistment",
		.nargs = 4,
		.argt = argt_328,
		.argsz = argsz_328
	},
	[329] = {
		.no = 329,
		.name = "NtSetInformationFile",
		.nargs = 5,
		.argt = argt_329,
		.argsz = argsz_329
	},
	[330] = {
		.no = 330,
		.name = "NtSetInformationJobObject",
		.nargs = 4,
		.argt = argt_330,
		.argsz = argsz_330
	},
	[331] = {
		.no = 331,
		.name = "NtSetInformationKey",
		.nargs = 4,
		.argt = argt_331,
		.argsz = argsz_331
	},
	[332] = {
		.no = 332,
		.name = "NtSetInformationObject",
		.nargs = 4,
		.argt = argt_332,
		.argsz = argsz_332
	},
	[333] = {
		.no = 333,
		.name = "NtSetInformationProcess",
		.nargs = 4,
		.argt = argt_333,
		.argsz = argsz_333
	},
	[334] = {
		.no = 334,
		.name = "NtSetInformationResourceManager",
		.nargs = 4,
		.argt = argt_334,
		.argsz = argsz_334
	},
	[335] = {
		.no = 335,
		.name = "NtSetInformationThread",
		.nargs = 4,
		.argt = argt_335,
		.argsz = argsz_335
	},
	[336] = {
		.no = 336,
		.name = "NtSetInformationToken",
		.nargs = 4,
		.argt = argt_336,
		.argsz = argsz_336
	},
	[337] = {
		.no = 337,
		.name = "NtSetInformationTransaction",
		.nargs = 4,
		.argt = argt_337,
		.argsz = argsz_337
	},
	[338] = {
		.no = 338,
		.name = "NtSetInformationTransactionManager",
		.nargs = 4,
		.argt = argt_338,
		.argsz = argsz_338
	},
	[339] = {
		.no = 339,
		.name = "NtSetInformationWorkerFactory",
		.nargs = 4,
		.argt = argt_339,
		.argsz = argsz_339
	},
	[340] = {
		.no = 340,
		.name = "NtSetIntervalProfile",
		.nargs = 2,
		.argt = argt_340,
		.argsz = argsz_340
	},
	[341] = {
		.no = 341,
		.name = "NtSetIoCompletion",
		.nargs = 5,
		.argt = argt_341,
		.argsz = argsz_341
	},
	[342] = {
		.no = 342,
		.name = "NtSetIoCompletionEx",
		.nargs = 6,
		.argt = argt_342,
		.argsz = argsz_342
	},
	[343] = {
		.no = 343,
		.name = "NtSetLdtEntries",
		.nargs = 6,
		.argt = argt_343,
		.argsz = argsz_343
	},
	[344] = {
		.no = 344,
		.name = "NtSetLowEventPair",
		.nargs = 1,
		.argt = argt_344,
		.argsz = argsz_344
	},
	[345] = {
		.no = 345,
		.name = "NtSetLowWaitHighEventPair",
		.nargs = 1,
		.argt = argt_345,
		.argsz = argsz_345
	},
	[346] = {
		.no = 346,
		.name = "NtSetQuotaInformationFile",
		.nargs = 4,
		.argt = argt_346,
		.argsz = argsz_346
	},
	[347] = {
		.no = 347,
		.name = "NtSetSecurityObject",
		.nargs = 3,
		.argt = argt_347,
		.argsz = argsz_347
	},
	[348] = {
		.no = 348,
		.name = "NtSetSystemEnvironmentValue",
		.nargs = 2,
		.argt = argt_348,
		.argsz = argsz_348
	},
	[349] = {
		.no = 349,
		.name = "NtSetSystemEnvironmentValueEx",
		.nargs = 5,
		.argt = argt_349,
		.argsz = argsz_349
	},
	[350] = {
		.no = 350,
		.name = "NtSetSystemInformation",
		.nargs = 3,
		.argt = argt_350,
		.argsz = argsz_350
	},
	[351] = {
		.no = 351,
		.name = "NtSetSystemPowerState",
		.nargs = 3,
		.argt = argt_351,
		.argsz = argsz_351
	},
	[352] = {
		.no = 352,
		.name = "NtSetSystemTime",
		.nargs = 2,
		.argt = argt_352,
		.argsz = argsz_352
	},
	[353] = {
		.no = 353,
		.name = "NtSetThreadExecutionState",
		.nargs = 2,
		.argt = argt_353,
		.argsz = argsz_353
	},
	[354] = {
		.no = 354,
		.name = "NtSetTimer",
		.nargs = 7,
		.argt = argt_354,
		.argsz = argsz_354
	},
	[355] = {
		.no = 355,
		.name = "NtSetTimerEx",
		.nargs = 4,
		.argt = argt_355,
		.argsz = argsz_355
	},
	[356] = {
		.no = 356,
		.name = "NtSetTimerResolution",
		.nargs = 3,
		.argt = argt_356,
		.argsz = argsz_356
	},
	[357] = {
		.no = 357,
		.name = "NtSetUuidSeed",
		.nargs = 1,
		.argt = argt_357,
		.argsz = argsz_357
	},
	[358] = {
		.no = 358,
		.name = "NtSetValueKey",
		.nargs = 6,
		.argt = argt_358,
		.argsz = argsz_358
	},
	[359] = {
		.no = 359,
		.name = "NtSetVolumeInformationFile",
		.nargs = 5,
		.argt = argt_359,
		.argsz = argsz_359
	},
	[360] = {
		.no = 360,
		.name = "NtShutdownSystem",
		.nargs = 1,
		.argt = argt_360,
		.argsz = argsz_360
	},
	[361] = {
		.no = 361,
		.name = "NtShutdownWorkerFactory",
		.nargs = 2,
		.argt = argt_361,
		.argsz = argsz_361
	},
	[362] = {
		.no = 362,
		.name = "NtSignalAndWaitForSingleObject",
		.nargs = 4,
		.argt = argt_362,
		.argsz = argsz_362
	},
	[363] = {
		.no = 363,
		.name = "NtSinglePhaseReject",
		.nargs = 2,
		.argt = argt_363,
		.argsz = argsz_363
	},
	[364] = {
		.no = 364,
		.name = "NtStartProfile",
		.nargs = 1,
		.argt = argt_364,
		.argsz = argsz_364
	},
	[365] = {
		.no = 365,
		.name = "NtStopProfile",
		.nargs = 1,
		.argt = argt_365,
		.argsz = argsz_365
	},
	[366] = {
		.no = 366,
		.name = "NtSuspendProcess",
		.nargs = 1,
		.argt = argt_366,
		.argsz = argsz_366
	},
	[367] = {
		.no = 367,
		.name = "NtSuspendThread",
		.nargs = 2,
		.argt = argt_367,
		.argsz = argsz_367
	},
	[368] = {
		.no = 368,
		.name = "NtSystemDebugControl",
		.nargs = 6,
		.argt = argt_368,
		.argsz = argsz_368
	},
	[369] = {
		.no = 369,
		.name = "NtTerminateJobObject",
		.nargs = 2,
		.argt = argt_369,
		.argsz = argsz_369
	},
	[370] = {
		.no = 370,
		.name = "NtTerminateProcess",
		.nargs = 2,
		.argt = argt_370,
		.argsz = argsz_370
	},
	[371] = {
		.no = 371,
		.name = "NtTerminateThread",
		.nargs = 2,
		.argt = argt_371,
		.argsz = argsz_371
	},
	[372] = {
		.no = 372,
		.name = "NtTestAlert",
		.nargs = 0,
		.argt = argt_372,
		.argsz = argsz_372
	},
	[373] = {
		.no = 373,
		.name = "NtThawRegistry",
		.nargs = 0,
		.argt = argt_373,
		.argsz = argsz_373
	},
	[374] = {
		.no = 374,
		.name = "NtThawTransactions",
		.nargs = 0,
		.argt = argt_374,
		.argsz = argsz_374
	},
	[375] = {
		.no = 375,
		.name = "NtTraceControl",
		.nargs = 6,
		.argt = argt_375,
		.argsz = argsz_375
	},
	[376] = {
		.no = 376,
		.name = "NtTraceEvent",
		.nargs = 4,
		.argt = argt_376,
		.argsz = argsz_376
	},
	[377] = {
		.no = 377,
		.name = "NtTranslateFilePath",
		.nargs = 4,
		.argt = argt_377,
		.argsz = argsz_377
	},
	[378] = {
		.no = 378,
		.name = "NtUmsThreadYield",
		.nargs = 1,
		.argt = argt_378,
		.argsz = argsz_378
	},
	[379] = {
		.no = 379,
		.name = "NtUnloadDriver",
		.nargs = 1,
		.argt = argt_379,
		.argsz = argsz_379
	},
	[380] = {
		.no = 380,
		.name = "NtUnloadKey",
		.nargs = 1,
		.argt = argt_380,
		.argsz = argsz_380
	},
	[381] = {
		.no = 381,
		.name = "NtUnloadKey2",
		.nargs = 2,
		.argt = argt_381,
		.argsz = argsz_381
	},
	[382] = {
		.no = 382,
		.name = "NtUnloadKeyEx",
		.nargs = 2,
		.argt = argt_382,
		.argsz = argsz_382
	},
	[383] = {
		.no = 383,
		.name = "NtUnlockFile",
		.nargs = 5,
		.argt = argt_383,
		.argsz = argsz_383
	},
	[384] = {
		.no = 384,
		.name = "NtUnlockVirtualMemory",
		.nargs = 4,
		.argt = argt_384,
		.argsz = argsz_384
	},
	[385] = {
		.no = 385,
		.name = "NtUnmapViewOfSection",
		.nargs = 2,
		.argt = argt_385,
		.argsz = argsz_385
	},
	[386] = {
		.no = 386,
		.name = "NtVdmControl",
		.nargs = 2,
		.argt = argt_386,
		.argsz = argsz_386
	},
	[387] = {
		.no = 387,
		.name = "NtWaitForDebugEvent",
		.nargs = 4,
		.argt = argt_387,
		.argsz = argsz_387
	},
	[388] = {
		.no = 388,
		.name = "NtWaitForKeyedEvent",
		.nargs = 4,
		.argt = argt_388,
		.argsz = argsz_388
	},
	[389] = {
		.no = 389,
		.name = "NtWaitForMultipleObjects",
		.nargs = 5,
		.argt = argt_389,
		.argsz = argsz_389
	},
	[390] = {
		.no = 390,
		.name = "NtWaitForMultipleObjects32",
		.nargs = 5,
		.argt = argt_390,
		.argsz = argsz_390
	},
	[391] = {
		.no = 391,
		.name = "NtWaitForSingleObject",
		.nargs = 3,
		.argt = argt_391,
		.argsz = argsz_391
	},
	[392] = {
		.no = 392,
		.name = "NtWaitForWorkViaWorkerFactory",
		.nargs = 2,
		.argt = argt_392,
		.argsz = argsz_392
	},
	[393] = {
		.no = 393,
		.name = "NtWaitHighEventPair",
		.nargs = 1,
		.argt = argt_393,
		.argsz = argsz_393
	},
	[394] = {
		.no = 394,
		.name = "NtWaitLowEventPair",
		.nargs = 1,
		.argt = argt_394,
		.argsz = argsz_394
	},
	[395] = {
		.no = 395,
		.name = "NtWorkerFactoryWorkerReady",
		.nargs = 1,
		.argt = argt_395,
		.argsz = argsz_395
	},
	[396] = {
		.no = 396,
		.name = "NtWriteFile",
		.nargs = 9,
		.argt = argt_396,
		.argsz = argsz_396
	},
	[397] = {
		.no = 397,
		.name = "NtWriteFileGather",
		.nargs = 9,
		.argt = argt_397,
		.argsz = argsz_397
	},
	[398] = {
		.no = 398,
		.name = "NtWriteRequestData",
		.nargs = 6,
		.argt = argt_398,
		.argsz = argsz_398
	},
	[399] = {
		.no = 399,
		.name = "NtWriteVirtualMemory",
		.nargs = 5,
		.argt = argt_399,
		.argsz = argsz_399
	},
	[400] = {
		.no = 400,
		.name = "NtYieldExecution",
		.nargs = 0,
		.argt = argt_400,
		.argsz = argsz_400
	},
	
};

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=c: */