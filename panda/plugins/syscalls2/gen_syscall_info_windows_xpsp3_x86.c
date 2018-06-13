#include <stdint.h>
#include "syscalls2_info.h"
#define MAX_SYSCALL_NO 275
#define MAX_SYSCALL_GENERIC_NO 275
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
static syscall_argtype_t argt_10[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_10[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_11[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_11[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_12[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_12[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_13[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_13[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_14[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_14[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_15[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_15[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_16[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_16[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_17[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_17[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_18[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_18[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_19[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_19[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_20[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_20[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_21[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_21[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_22[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_22[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_23[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_23[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_24[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_24[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_25[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_25[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_26[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_26[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_27[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_27[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_28[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_28[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_29[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_29[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_30[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_30[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_31[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_31[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_32[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_32[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_33[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_33[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_34[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_34[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_35[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_35[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_36[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_36[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_37[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_37[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_38[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_38[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_39[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_39[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_40[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_40[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_41[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_41[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_42[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_42[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_43[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_43[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_44[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_44[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_45[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_45[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_46[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_46[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_47[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_47[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_48[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_48[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_49[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_49[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_50[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_50[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_51[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_51[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_52[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_52[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_53[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_53[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_54[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_54[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_55[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_55[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_56[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_56[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_57[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_57[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_58[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_58[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_59[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_59[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_60[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_60[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_61[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_61[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_62[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_62[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_63[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_63[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_64[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_64[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_65[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_65[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_66[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_66[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_67[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_67[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_68[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_68[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_69[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_69[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_70[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_70[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_71[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_71[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_72[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_72[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_73[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_73[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_74[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_74[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_75[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_75[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_76[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_76[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_77[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_77[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_78[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_78[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_79[] = {};
static uint8_t argsz_79[] = {};
static syscall_argtype_t argt_80[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_80[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_81[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_81[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_82[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_82[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_83[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_83[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_84[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_84[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_85[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_85[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_86[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_86[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_87[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_87[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_88[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_88[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_89[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_89[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_90[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_90[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_91[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_91[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_92[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_92[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_93[] = {};
static uint8_t argsz_93[] = {};
static syscall_argtype_t argt_94[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_94[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_95[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_95[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_96[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_96[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_97[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_97[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_98[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_98[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_99[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_99[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_100[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_100[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_101[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_101[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_102[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_102[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_103[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_103[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_104[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_104[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_105[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_105[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_106[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_106[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_107[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_107[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_108[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_108[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_109[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_109[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_110[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_110[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_111[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_111[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_112[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_112[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_113[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_113[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_114[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_114[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_115[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_115[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_116[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_116[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_117[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_117[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_118[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_118[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_119[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_119[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_120[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_120[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_121[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_121[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_122[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_122[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_123[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_123[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_124[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_124[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_125[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_125[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_126[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_126[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_127[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_127[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_128[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_128[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_129[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_129[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_130[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_130[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_131[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_131[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_132[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_132[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_133[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_133[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_134[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_134[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_135[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_135[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_136[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_136[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_137[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_137[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_138[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_138[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_139[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_139[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_140[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_140[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_141[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_141[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_142[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_142[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_143[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_143[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_144[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_144[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_145[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_145[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_146[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_146[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_147[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_147[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_148[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_148[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_149[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_149[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_150[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_150[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_151[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_151[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_152[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_152[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_153[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_153[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_154[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_154[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_155[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_155[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_156[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_156[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_157[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_157[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_158[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_158[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_159[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_159[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_160[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_160[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_161[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_161[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_162[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_162[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_163[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_163[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_164[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_164[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_165[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_165[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_166[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_166[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_167[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_167[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_168[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_168[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_169[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_169[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_170[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_170[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_171[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_171[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_172[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_172[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_173[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_173[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_174[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_174[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_175[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_175[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_176[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_176[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_177[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_177[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_178[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_178[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_179[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_179[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_180[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_180[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_181[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_181[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_182[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_182[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_183[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_183[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_184[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE};
static uint8_t argsz_184[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_185[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_185[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_186[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_186[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_187[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_187[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_188[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_188[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_189[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_189[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_190[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_190[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_191[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_191[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_192[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_192[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_194[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_194[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_195[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_195[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_197[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_197[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_198[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_198[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_199[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_199[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_200[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_200[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_201[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_201[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_202[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_202[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_203[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_203[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_204[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_204[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_205[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_205[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_206[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_206[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_207[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_207[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_208[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_208[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_209[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_209[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_210[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_210[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_211[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_211[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_212[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_212[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_213[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_213[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_214[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_214[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_215[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_215[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_216[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_216[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_217[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_217[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_218[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_218[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_219[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_219[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_220[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_220[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_221[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_221[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_222[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_222[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_223[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_223[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_224[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_224[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_225[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_225[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_226[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_226[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_227[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_227[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_228[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_228[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_229[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_229[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_230[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_230[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_231[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_231[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_232[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_232[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_233[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_233[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_234[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_234[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_235[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_235[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_236[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE};
static uint8_t argsz_236[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_237[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_237[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_238[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_238[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_239[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_239[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_240[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_240[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_241[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_241[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_242[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_242[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_243[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_243[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_244[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_244[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_245[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_245[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_246[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_246[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_247[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_247[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_248[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_248[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_249[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_249[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_250[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_250[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_251[] = {};
static uint8_t argsz_251[] = {};
static syscall_argtype_t argt_252[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_252[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_253[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_253[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_254[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_254[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_255[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_255[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_256[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_256[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_257[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_257[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_258[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_258[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_259[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_259[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_260[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_260[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_261[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_261[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_262[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_262[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_263[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_263[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_264[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_264[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_265[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_265[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_266[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_266[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_267[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_267[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_268[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_268[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_269[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_269[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_270[] = {};
static uint8_t argsz_270[] = {};
static syscall_argtype_t argt_271[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_271[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_272[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_272[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_273[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_273[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_274[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_274[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_275[] = {};
static uint8_t argsz_275[] = {};


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
		.name = "NtEnumerateBootEntries",
		.nargs = 2,
		.argt = argt_9,
		.argsz = argsz_9
	},
	[10] = {
		.no = 10,
		.name = "NtAdjustGroupsToken",
		.nargs = 6,
		.argt = argt_10,
		.argsz = argsz_10
	},
	[11] = {
		.no = 11,
		.name = "NtAdjustPrivilegesToken",
		.nargs = 6,
		.argt = argt_11,
		.argsz = argsz_11
	},
	[12] = {
		.no = 12,
		.name = "NtAlertResumeThread",
		.nargs = 2,
		.argt = argt_12,
		.argsz = argsz_12
	},
	[13] = {
		.no = 13,
		.name = "NtAlertThread",
		.nargs = 1,
		.argt = argt_13,
		.argsz = argsz_13
	},
	[14] = {
		.no = 14,
		.name = "NtAllocateLocallyUniqueId",
		.nargs = 1,
		.argt = argt_14,
		.argsz = argsz_14
	},
	[15] = {
		.no = 15,
		.name = "NtAllocateUserPhysicalPages",
		.nargs = 3,
		.argt = argt_15,
		.argsz = argsz_15
	},
	[16] = {
		.no = 16,
		.name = "NtAllocateUuids",
		.nargs = 4,
		.argt = argt_16,
		.argsz = argsz_16
	},
	[17] = {
		.no = 17,
		.name = "NtAllocateVirtualMemory",
		.nargs = 6,
		.argt = argt_17,
		.argsz = argsz_17
	},
	[18] = {
		.no = 18,
		.name = "NtAreMappedFilesTheSame",
		.nargs = 2,
		.argt = argt_18,
		.argsz = argsz_18
	},
	[19] = {
		.no = 19,
		.name = "NtAssignProcessToJobObject",
		.nargs = 2,
		.argt = argt_19,
		.argsz = argsz_19
	},
	[20] = {
		.no = 20,
		.name = "NtCallbackReturn",
		.nargs = 3,
		.argt = argt_20,
		.argsz = argsz_20
	},
	[21] = {
		.no = 21,
		.name = "NtModifyBootEntry",
		.nargs = 1,
		.argt = argt_21,
		.argsz = argsz_21
	},
	[22] = {
		.no = 22,
		.name = "NtCancelIoFile",
		.nargs = 2,
		.argt = argt_22,
		.argsz = argsz_22
	},
	[23] = {
		.no = 23,
		.name = "NtCancelTimer",
		.nargs = 2,
		.argt = argt_23,
		.argsz = argsz_23
	},
	[24] = {
		.no = 24,
		.name = "NtClearEvent",
		.nargs = 1,
		.argt = argt_24,
		.argsz = argsz_24
	},
	[25] = {
		.no = 25,
		.name = "NtClose",
		.nargs = 1,
		.argt = argt_25,
		.argsz = argsz_25
	},
	[26] = {
		.no = 26,
		.name = "NtCloseObjectAuditAlarm",
		.nargs = 3,
		.argt = argt_26,
		.argsz = argsz_26
	},
	[27] = {
		.no = 27,
		.name = "NtCompactKeys",
		.nargs = 2,
		.argt = argt_27,
		.argsz = argsz_27
	},
	[28] = {
		.no = 28,
		.name = "NtCompareTokens",
		.nargs = 3,
		.argt = argt_28,
		.argsz = argsz_28
	},
	[29] = {
		.no = 29,
		.name = "NtCompleteConnectPort",
		.nargs = 1,
		.argt = argt_29,
		.argsz = argsz_29
	},
	[30] = {
		.no = 30,
		.name = "NtCompressKey",
		.nargs = 1,
		.argt = argt_30,
		.argsz = argsz_30
	},
	[31] = {
		.no = 31,
		.name = "NtConnectPort",
		.nargs = 8,
		.argt = argt_31,
		.argsz = argsz_31
	},
	[32] = {
		.no = 32,
		.name = "NtContinue",
		.nargs = 2,
		.argt = argt_32,
		.argsz = argsz_32
	},
	[33] = {
		.no = 33,
		.name = "NtCreateDebugObject",
		.nargs = 4,
		.argt = argt_33,
		.argsz = argsz_33
	},
	[34] = {
		.no = 34,
		.name = "NtCreateDirectoryObject",
		.nargs = 3,
		.argt = argt_34,
		.argsz = argsz_34
	},
	[35] = {
		.no = 35,
		.name = "NtCreateEvent",
		.nargs = 5,
		.argt = argt_35,
		.argsz = argsz_35
	},
	[36] = {
		.no = 36,
		.name = "NtCreateEventPair",
		.nargs = 3,
		.argt = argt_36,
		.argsz = argsz_36
	},
	[37] = {
		.no = 37,
		.name = "NtCreateFile",
		.nargs = 11,
		.argt = argt_37,
		.argsz = argsz_37
	},
	[38] = {
		.no = 38,
		.name = "NtCreateIoCompletion",
		.nargs = 4,
		.argt = argt_38,
		.argsz = argsz_38
	},
	[39] = {
		.no = 39,
		.name = "NtCreateJobObject",
		.nargs = 3,
		.argt = argt_39,
		.argsz = argsz_39
	},
	[40] = {
		.no = 40,
		.name = "NtCreateJobSet",
		.nargs = 3,
		.argt = argt_40,
		.argsz = argsz_40
	},
	[41] = {
		.no = 41,
		.name = "NtCreateKey",
		.nargs = 7,
		.argt = argt_41,
		.argsz = argsz_41
	},
	[42] = {
		.no = 42,
		.name = "NtCreateMailslotFile",
		.nargs = 8,
		.argt = argt_42,
		.argsz = argsz_42
	},
	[43] = {
		.no = 43,
		.name = "NtCreateMutant",
		.nargs = 4,
		.argt = argt_43,
		.argsz = argsz_43
	},
	[44] = {
		.no = 44,
		.name = "NtCreateNamedPipeFile",
		.nargs = 14,
		.argt = argt_44,
		.argsz = argsz_44
	},
	[45] = {
		.no = 45,
		.name = "NtCreatePagingFile",
		.nargs = 4,
		.argt = argt_45,
		.argsz = argsz_45
	},
	[46] = {
		.no = 46,
		.name = "NtCreatePort",
		.nargs = 5,
		.argt = argt_46,
		.argsz = argsz_46
	},
	[47] = {
		.no = 47,
		.name = "NtCreateProcess",
		.nargs = 8,
		.argt = argt_47,
		.argsz = argsz_47
	},
	[48] = {
		.no = 48,
		.name = "NtCreateProcessEx",
		.nargs = 9,
		.argt = argt_48,
		.argsz = argsz_48
	},
	[49] = {
		.no = 49,
		.name = "NtCreateProfile",
		.nargs = 9,
		.argt = argt_49,
		.argsz = argsz_49
	},
	[50] = {
		.no = 50,
		.name = "NtCreateSection",
		.nargs = 7,
		.argt = argt_50,
		.argsz = argsz_50
	},
	[51] = {
		.no = 51,
		.name = "NtCreateSemaphore",
		.nargs = 5,
		.argt = argt_51,
		.argsz = argsz_51
	},
	[52] = {
		.no = 52,
		.name = "NtCreateSymbolicLinkObject",
		.nargs = 4,
		.argt = argt_52,
		.argsz = argsz_52
	},
	[53] = {
		.no = 53,
		.name = "NtCreateThread",
		.nargs = 8,
		.argt = argt_53,
		.argsz = argsz_53
	},
	[54] = {
		.no = 54,
		.name = "NtCreateTimer",
		.nargs = 4,
		.argt = argt_54,
		.argsz = argsz_54
	},
	[55] = {
		.no = 55,
		.name = "NtCreateToken",
		.nargs = 13,
		.argt = argt_55,
		.argsz = argsz_55
	},
	[56] = {
		.no = 56,
		.name = "NtCreateWaitablePort",
		.nargs = 5,
		.argt = argt_56,
		.argsz = argsz_56
	},
	[57] = {
		.no = 57,
		.name = "NtDebugActiveProcess",
		.nargs = 2,
		.argt = argt_57,
		.argsz = argsz_57
	},
	[58] = {
		.no = 58,
		.name = "NtDebugContinue",
		.nargs = 3,
		.argt = argt_58,
		.argsz = argsz_58
	},
	[59] = {
		.no = 59,
		.name = "NtDelayExecution",
		.nargs = 2,
		.argt = argt_59,
		.argsz = argsz_59
	},
	[60] = {
		.no = 60,
		.name = "NtDeleteAtom",
		.nargs = 1,
		.argt = argt_60,
		.argsz = argsz_60
	},
	[61] = {
		.no = 61,
		.name = "NtDeleteFile",
		.nargs = 1,
		.argt = argt_61,
		.argsz = argsz_61
	},
	[62] = {
		.no = 62,
		.name = "NtDeleteKey",
		.nargs = 1,
		.argt = argt_62,
		.argsz = argsz_62
	},
	[63] = {
		.no = 63,
		.name = "NtDeleteObjectAuditAlarm",
		.nargs = 3,
		.argt = argt_63,
		.argsz = argsz_63
	},
	[64] = {
		.no = 64,
		.name = "NtDeleteValueKey",
		.nargs = 2,
		.argt = argt_64,
		.argsz = argsz_64
	},
	[65] = {
		.no = 65,
		.name = "NtDeviceIoControlFile",
		.nargs = 10,
		.argt = argt_65,
		.argsz = argsz_65
	},
	[66] = {
		.no = 66,
		.name = "NtDisplayString",
		.nargs = 1,
		.argt = argt_66,
		.argsz = argsz_66
	},
	[67] = {
		.no = 67,
		.name = "NtDuplicateObject",
		.nargs = 7,
		.argt = argt_67,
		.argsz = argsz_67
	},
	[68] = {
		.no = 68,
		.name = "NtDuplicateToken",
		.nargs = 6,
		.argt = argt_68,
		.argsz = argsz_68
	},
	[69] = {
		.no = 69,
		.name = "NtEnumerateKey",
		.nargs = 6,
		.argt = argt_69,
		.argsz = argsz_69
	},
	[70] = {
		.no = 70,
		.name = "NtEnumerateSystemEnvironmentValuesEx",
		.nargs = 3,
		.argt = argt_70,
		.argsz = argsz_70
	},
	[71] = {
		.no = 71,
		.name = "NtEnumerateValueKey",
		.nargs = 6,
		.argt = argt_71,
		.argsz = argsz_71
	},
	[72] = {
		.no = 72,
		.name = "NtExtendSection",
		.nargs = 2,
		.argt = argt_72,
		.argsz = argsz_72
	},
	[73] = {
		.no = 73,
		.name = "NtFilterToken",
		.nargs = 6,
		.argt = argt_73,
		.argsz = argsz_73
	},
	[74] = {
		.no = 74,
		.name = "NtFindAtom",
		.nargs = 3,
		.argt = argt_74,
		.argsz = argsz_74
	},
	[75] = {
		.no = 75,
		.name = "NtFlushBuffersFile",
		.nargs = 2,
		.argt = argt_75,
		.argsz = argsz_75
	},
	[76] = {
		.no = 76,
		.name = "NtFlushInstructionCache",
		.nargs = 3,
		.argt = argt_76,
		.argsz = argsz_76
	},
	[77] = {
		.no = 77,
		.name = "NtFlushKey",
		.nargs = 1,
		.argt = argt_77,
		.argsz = argsz_77
	},
	[78] = {
		.no = 78,
		.name = "NtFlushVirtualMemory",
		.nargs = 4,
		.argt = argt_78,
		.argsz = argsz_78
	},
	[79] = {
		.no = 79,
		.name = "NtFlushWriteBuffer",
		.nargs = 0,
		.argt = argt_79,
		.argsz = argsz_79
	},
	[80] = {
		.no = 80,
		.name = "NtFreeUserPhysicalPages",
		.nargs = 3,
		.argt = argt_80,
		.argsz = argsz_80
	},
	[81] = {
		.no = 81,
		.name = "NtFreeVirtualMemory",
		.nargs = 4,
		.argt = argt_81,
		.argsz = argsz_81
	},
	[82] = {
		.no = 82,
		.name = "NtFsControlFile",
		.nargs = 10,
		.argt = argt_82,
		.argsz = argsz_82
	},
	[83] = {
		.no = 83,
		.name = "NtGetContextThread",
		.nargs = 2,
		.argt = argt_83,
		.argsz = argsz_83
	},
	[84] = {
		.no = 84,
		.name = "NtGetDevicePowerState",
		.nargs = 2,
		.argt = argt_84,
		.argsz = argsz_84
	},
	[85] = {
		.no = 85,
		.name = "NtGetPlugPlayEvent",
		.nargs = 4,
		.argt = argt_85,
		.argsz = argsz_85
	},
	[86] = {
		.no = 86,
		.name = "NtGetWriteWatch",
		.nargs = 7,
		.argt = argt_86,
		.argsz = argsz_86
	},
	[87] = {
		.no = 87,
		.name = "NtImpersonateAnonymousToken",
		.nargs = 1,
		.argt = argt_87,
		.argsz = argsz_87
	},
	[88] = {
		.no = 88,
		.name = "NtImpersonateClientOfPort",
		.nargs = 2,
		.argt = argt_88,
		.argsz = argsz_88
	},
	[89] = {
		.no = 89,
		.name = "NtImpersonateThread",
		.nargs = 3,
		.argt = argt_89,
		.argsz = argsz_89
	},
	[90] = {
		.no = 90,
		.name = "NtInitializeRegistry",
		.nargs = 1,
		.argt = argt_90,
		.argsz = argsz_90
	},
	[91] = {
		.no = 91,
		.name = "NtInitiatePowerAction",
		.nargs = 4,
		.argt = argt_91,
		.argsz = argsz_91
	},
	[92] = {
		.no = 92,
		.name = "NtIsProcessInJob",
		.nargs = 2,
		.argt = argt_92,
		.argsz = argsz_92
	},
	[93] = {
		.no = 93,
		.name = "NtIsSystemResumeAutomatic",
		.nargs = 0,
		.argt = argt_93,
		.argsz = argsz_93
	},
	[94] = {
		.no = 94,
		.name = "NtListenPort",
		.nargs = 2,
		.argt = argt_94,
		.argsz = argsz_94
	},
	[95] = {
		.no = 95,
		.name = "NtLoadDriver",
		.nargs = 1,
		.argt = argt_95,
		.argsz = argsz_95
	},
	[96] = {
		.no = 96,
		.name = "NtLoadKey",
		.nargs = 2,
		.argt = argt_96,
		.argsz = argsz_96
	},
	[97] = {
		.no = 97,
		.name = "NtLoadKey2",
		.nargs = 3,
		.argt = argt_97,
		.argsz = argsz_97
	},
	[98] = {
		.no = 98,
		.name = "NtLockFile",
		.nargs = 10,
		.argt = argt_98,
		.argsz = argsz_98
	},
	[99] = {
		.no = 99,
		.name = "NtLockProductActivationKeys",
		.nargs = 2,
		.argt = argt_99,
		.argsz = argsz_99
	},
	[100] = {
		.no = 100,
		.name = "NtLockRegistryKey",
		.nargs = 1,
		.argt = argt_100,
		.argsz = argsz_100
	},
	[101] = {
		.no = 101,
		.name = "NtLockVirtualMemory",
		.nargs = 4,
		.argt = argt_101,
		.argsz = argsz_101
	},
	[102] = {
		.no = 102,
		.name = "NtMakePermanentObject",
		.nargs = 1,
		.argt = argt_102,
		.argsz = argsz_102
	},
	[103] = {
		.no = 103,
		.name = "NtMakeTemporaryObject",
		.nargs = 1,
		.argt = argt_103,
		.argsz = argsz_103
	},
	[104] = {
		.no = 104,
		.name = "NtMapUserPhysicalPages",
		.nargs = 3,
		.argt = argt_104,
		.argsz = argsz_104
	},
	[105] = {
		.no = 105,
		.name = "NtMapUserPhysicalPagesScatter",
		.nargs = 3,
		.argt = argt_105,
		.argsz = argsz_105
	},
	[106] = {
		.no = 106,
		.name = "NtMapViewOfSection",
		.nargs = 10,
		.argt = argt_106,
		.argsz = argsz_106
	},
	[107] = {
		.no = 107,
		.name = "NtNotifyChangeDirectoryFile",
		.nargs = 9,
		.argt = argt_107,
		.argsz = argsz_107
	},
	[108] = {
		.no = 108,
		.name = "NtNotifyChangeKey",
		.nargs = 10,
		.argt = argt_108,
		.argsz = argsz_108
	},
	[109] = {
		.no = 109,
		.name = "NtNotifyChangeMultipleKeys",
		.nargs = 12,
		.argt = argt_109,
		.argsz = argsz_109
	},
	[110] = {
		.no = 110,
		.name = "NtOpenDirectoryObject",
		.nargs = 3,
		.argt = argt_110,
		.argsz = argsz_110
	},
	[111] = {
		.no = 111,
		.name = "NtOpenEvent",
		.nargs = 3,
		.argt = argt_111,
		.argsz = argsz_111
	},
	[112] = {
		.no = 112,
		.name = "NtOpenEventPair",
		.nargs = 3,
		.argt = argt_112,
		.argsz = argsz_112
	},
	[113] = {
		.no = 113,
		.name = "NtOpenFile",
		.nargs = 6,
		.argt = argt_113,
		.argsz = argsz_113
	},
	[114] = {
		.no = 114,
		.name = "NtOpenIoCompletion",
		.nargs = 3,
		.argt = argt_114,
		.argsz = argsz_114
	},
	[115] = {
		.no = 115,
		.name = "NtOpenJobObject",
		.nargs = 3,
		.argt = argt_115,
		.argsz = argsz_115
	},
	[116] = {
		.no = 116,
		.name = "NtOpenKey",
		.nargs = 3,
		.argt = argt_116,
		.argsz = argsz_116
	},
	[117] = {
		.no = 117,
		.name = "NtOpenMutant",
		.nargs = 3,
		.argt = argt_117,
		.argsz = argsz_117
	},
	[118] = {
		.no = 118,
		.name = "NtOpenObjectAuditAlarm",
		.nargs = 12,
		.argt = argt_118,
		.argsz = argsz_118
	},
	[119] = {
		.no = 119,
		.name = "NtOpenProcess",
		.nargs = 4,
		.argt = argt_119,
		.argsz = argsz_119
	},
	[120] = {
		.no = 120,
		.name = "NtOpenProcessToken",
		.nargs = 3,
		.argt = argt_120,
		.argsz = argsz_120
	},
	[121] = {
		.no = 121,
		.name = "NtOpenProcessTokenEx",
		.nargs = 4,
		.argt = argt_121,
		.argsz = argsz_121
	},
	[122] = {
		.no = 122,
		.name = "NtOpenSection",
		.nargs = 3,
		.argt = argt_122,
		.argsz = argsz_122
	},
	[123] = {
		.no = 123,
		.name = "NtOpenSemaphore",
		.nargs = 3,
		.argt = argt_123,
		.argsz = argsz_123
	},
	[124] = {
		.no = 124,
		.name = "NtOpenSymbolicLinkObject",
		.nargs = 3,
		.argt = argt_124,
		.argsz = argsz_124
	},
	[125] = {
		.no = 125,
		.name = "NtOpenThread",
		.nargs = 4,
		.argt = argt_125,
		.argsz = argsz_125
	},
	[126] = {
		.no = 126,
		.name = "NtOpenThreadToken",
		.nargs = 4,
		.argt = argt_126,
		.argsz = argsz_126
	},
	[127] = {
		.no = 127,
		.name = "NtOpenThreadTokenEx",
		.nargs = 5,
		.argt = argt_127,
		.argsz = argsz_127
	},
	[128] = {
		.no = 128,
		.name = "NtOpenTimer",
		.nargs = 3,
		.argt = argt_128,
		.argsz = argsz_128
	},
	[129] = {
		.no = 129,
		.name = "NtPlugPlayControl",
		.nargs = 3,
		.argt = argt_129,
		.argsz = argsz_129
	},
	[130] = {
		.no = 130,
		.name = "NtPowerInformation",
		.nargs = 5,
		.argt = argt_130,
		.argsz = argsz_130
	},
	[131] = {
		.no = 131,
		.name = "NtPrivilegeCheck",
		.nargs = 3,
		.argt = argt_131,
		.argsz = argsz_131
	},
	[132] = {
		.no = 132,
		.name = "NtPrivilegeObjectAuditAlarm",
		.nargs = 6,
		.argt = argt_132,
		.argsz = argsz_132
	},
	[133] = {
		.no = 133,
		.name = "NtPrivilegedServiceAuditAlarm",
		.nargs = 5,
		.argt = argt_133,
		.argsz = argsz_133
	},
	[134] = {
		.no = 134,
		.name = "NtProtectVirtualMemory",
		.nargs = 5,
		.argt = argt_134,
		.argsz = argsz_134
	},
	[135] = {
		.no = 135,
		.name = "NtPulseEvent",
		.nargs = 2,
		.argt = argt_135,
		.argsz = argsz_135
	},
	[136] = {
		.no = 136,
		.name = "NtQueryAttributesFile",
		.nargs = 2,
		.argt = argt_136,
		.argsz = argsz_136
	},
	[137] = {
		.no = 137,
		.name = "NtQueryDebugFilterState",
		.nargs = 2,
		.argt = argt_137,
		.argsz = argsz_137
	},
	[138] = {
		.no = 138,
		.name = "NtQueryDefaultLocale",
		.nargs = 2,
		.argt = argt_138,
		.argsz = argsz_138
	},
	[139] = {
		.no = 139,
		.name = "NtQueryDefaultUILanguage",
		.nargs = 1,
		.argt = argt_139,
		.argsz = argsz_139
	},
	[140] = {
		.no = 140,
		.name = "NtQueryDirectoryFile",
		.nargs = 11,
		.argt = argt_140,
		.argsz = argsz_140
	},
	[141] = {
		.no = 141,
		.name = "NtQueryDirectoryObject",
		.nargs = 7,
		.argt = argt_141,
		.argsz = argsz_141
	},
	[142] = {
		.no = 142,
		.name = "NtQueryEaFile",
		.nargs = 9,
		.argt = argt_142,
		.argsz = argsz_142
	},
	[143] = {
		.no = 143,
		.name = "NtQueryEvent",
		.nargs = 5,
		.argt = argt_143,
		.argsz = argsz_143
	},
	[144] = {
		.no = 144,
		.name = "NtQueryFullAttributesFile",
		.nargs = 2,
		.argt = argt_144,
		.argsz = argsz_144
	},
	[145] = {
		.no = 145,
		.name = "NtQueryInformationAtom",
		.nargs = 5,
		.argt = argt_145,
		.argsz = argsz_145
	},
	[146] = {
		.no = 146,
		.name = "NtQueryInformationFile",
		.nargs = 5,
		.argt = argt_146,
		.argsz = argsz_146
	},
	[147] = {
		.no = 147,
		.name = "NtQueryInformationJobObject",
		.nargs = 5,
		.argt = argt_147,
		.argsz = argsz_147
	},
	[148] = {
		.no = 148,
		.name = "NtQueryInformationPort",
		.nargs = 5,
		.argt = argt_148,
		.argsz = argsz_148
	},
	[149] = {
		.no = 149,
		.name = "NtQueryInformationProcess",
		.nargs = 5,
		.argt = argt_149,
		.argsz = argsz_149
	},
	[150] = {
		.no = 150,
		.name = "NtQueryInformationThread",
		.nargs = 5,
		.argt = argt_150,
		.argsz = argsz_150
	},
	[151] = {
		.no = 151,
		.name = "NtQueryInformationToken",
		.nargs = 5,
		.argt = argt_151,
		.argsz = argsz_151
	},
	[152] = {
		.no = 152,
		.name = "NtQueryInstallUILanguage",
		.nargs = 1,
		.argt = argt_152,
		.argsz = argsz_152
	},
	[153] = {
		.no = 153,
		.name = "NtQueryIntervalProfile",
		.nargs = 2,
		.argt = argt_153,
		.argsz = argsz_153
	},
	[154] = {
		.no = 154,
		.name = "NtQueryIoCompletion",
		.nargs = 5,
		.argt = argt_154,
		.argsz = argsz_154
	},
	[155] = {
		.no = 155,
		.name = "NtQueryKey",
		.nargs = 5,
		.argt = argt_155,
		.argsz = argsz_155
	},
	[156] = {
		.no = 156,
		.name = "NtQueryMultipleValueKey",
		.nargs = 6,
		.argt = argt_156,
		.argsz = argsz_156
	},
	[157] = {
		.no = 157,
		.name = "NtQueryMutant",
		.nargs = 5,
		.argt = argt_157,
		.argsz = argsz_157
	},
	[158] = {
		.no = 158,
		.name = "NtQueryObject",
		.nargs = 5,
		.argt = argt_158,
		.argsz = argsz_158
	},
	[159] = {
		.no = 159,
		.name = "NtQueryOpenSubKeys",
		.nargs = 2,
		.argt = argt_159,
		.argsz = argsz_159
	},
	[160] = {
		.no = 160,
		.name = "NtQueryPerformanceCounter",
		.nargs = 2,
		.argt = argt_160,
		.argsz = argsz_160
	},
	[161] = {
		.no = 161,
		.name = "NtQueryQuotaInformationFile",
		.nargs = 9,
		.argt = argt_161,
		.argsz = argsz_161
	},
	[162] = {
		.no = 162,
		.name = "NtQuerySection",
		.nargs = 5,
		.argt = argt_162,
		.argsz = argsz_162
	},
	[163] = {
		.no = 163,
		.name = "NtQuerySecurityObject",
		.nargs = 5,
		.argt = argt_163,
		.argsz = argsz_163
	},
	[164] = {
		.no = 164,
		.name = "NtQuerySemaphore",
		.nargs = 5,
		.argt = argt_164,
		.argsz = argsz_164
	},
	[165] = {
		.no = 165,
		.name = "NtQuerySymbolicLinkObject",
		.nargs = 3,
		.argt = argt_165,
		.argsz = argsz_165
	},
	[166] = {
		.no = 166,
		.name = "NtQuerySystemEnvironmentValue",
		.nargs = 4,
		.argt = argt_166,
		.argsz = argsz_166
	},
	[167] = {
		.no = 167,
		.name = "NtQuerySystemEnvironmentValueEx",
		.nargs = 5,
		.argt = argt_167,
		.argsz = argsz_167
	},
	[168] = {
		.no = 168,
		.name = "NtQuerySystemInformation",
		.nargs = 4,
		.argt = argt_168,
		.argsz = argsz_168
	},
	[169] = {
		.no = 169,
		.name = "NtQuerySystemTime",
		.nargs = 1,
		.argt = argt_169,
		.argsz = argsz_169
	},
	[170] = {
		.no = 170,
		.name = "NtQueryTimer",
		.nargs = 5,
		.argt = argt_170,
		.argsz = argsz_170
	},
	[171] = {
		.no = 171,
		.name = "NtQueryTimerResolution",
		.nargs = 3,
		.argt = argt_171,
		.argsz = argsz_171
	},
	[172] = {
		.no = 172,
		.name = "NtQueryValueKey",
		.nargs = 6,
		.argt = argt_172,
		.argsz = argsz_172
	},
	[173] = {
		.no = 173,
		.name = "NtQueryVirtualMemory",
		.nargs = 6,
		.argt = argt_173,
		.argsz = argsz_173
	},
	[174] = {
		.no = 174,
		.name = "NtQueryVolumeInformationFile",
		.nargs = 5,
		.argt = argt_174,
		.argsz = argsz_174
	},
	[175] = {
		.no = 175,
		.name = "NtQueueApcThread",
		.nargs = 5,
		.argt = argt_175,
		.argsz = argsz_175
	},
	[176] = {
		.no = 176,
		.name = "NtRaiseException",
		.nargs = 3,
		.argt = argt_176,
		.argsz = argsz_176
	},
	[177] = {
		.no = 177,
		.name = "NtRaiseHardError",
		.nargs = 6,
		.argt = argt_177,
		.argsz = argsz_177
	},
	[178] = {
		.no = 178,
		.name = "NtReadFile",
		.nargs = 9,
		.argt = argt_178,
		.argsz = argsz_178
	},
	[179] = {
		.no = 179,
		.name = "NtReadFileScatter",
		.nargs = 9,
		.argt = argt_179,
		.argsz = argsz_179
	},
	[180] = {
		.no = 180,
		.name = "NtReadRequestData",
		.nargs = 6,
		.argt = argt_180,
		.argsz = argsz_180
	},
	[181] = {
		.no = 181,
		.name = "NtReadVirtualMemory",
		.nargs = 5,
		.argt = argt_181,
		.argsz = argsz_181
	},
	[182] = {
		.no = 182,
		.name = "NtRegisterThreadTerminatePort",
		.nargs = 1,
		.argt = argt_182,
		.argsz = argsz_182
	},
	[183] = {
		.no = 183,
		.name = "NtReleaseMutant",
		.nargs = 2,
		.argt = argt_183,
		.argsz = argsz_183
	},
	[184] = {
		.no = 184,
		.name = "NtReleaseSemaphore",
		.nargs = 3,
		.argt = argt_184,
		.argsz = argsz_184
	},
	[185] = {
		.no = 185,
		.name = "NtRemoveIoCompletion",
		.nargs = 5,
		.argt = argt_185,
		.argsz = argsz_185
	},
	[186] = {
		.no = 186,
		.name = "NtRemoveProcessDebug",
		.nargs = 2,
		.argt = argt_186,
		.argsz = argsz_186
	},
	[187] = {
		.no = 187,
		.name = "NtRenameKey",
		.nargs = 2,
		.argt = argt_187,
		.argsz = argsz_187
	},
	[188] = {
		.no = 188,
		.name = "NtReplaceKey",
		.nargs = 3,
		.argt = argt_188,
		.argsz = argsz_188
	},
	[189] = {
		.no = 189,
		.name = "NtReplyPort",
		.nargs = 2,
		.argt = argt_189,
		.argsz = argsz_189
	},
	[190] = {
		.no = 190,
		.name = "NtReplyWaitReceivePort",
		.nargs = 4,
		.argt = argt_190,
		.argsz = argsz_190
	},
	[191] = {
		.no = 191,
		.name = "NtReplyWaitReceivePortEx",
		.nargs = 5,
		.argt = argt_191,
		.argsz = argsz_191
	},
	[192] = {
		.no = 192,
		.name = "NtReplyWaitReplyPort",
		.nargs = 2,
		.argt = argt_192,
		.argsz = argsz_192
	},
	[194] = {
		.no = 194,
		.name = "NtRequestPort",
		.nargs = 2,
		.argt = argt_194,
		.argsz = argsz_194
	},
	[195] = {
		.no = 195,
		.name = "NtRequestWaitReplyPort",
		.nargs = 3,
		.argt = argt_195,
		.argsz = argsz_195
	},
	[197] = {
		.no = 197,
		.name = "NtResetEvent",
		.nargs = 2,
		.argt = argt_197,
		.argsz = argsz_197
	},
	[198] = {
		.no = 198,
		.name = "NtResetWriteWatch",
		.nargs = 3,
		.argt = argt_198,
		.argsz = argsz_198
	},
	[199] = {
		.no = 199,
		.name = "NtRestoreKey",
		.nargs = 3,
		.argt = argt_199,
		.argsz = argsz_199
	},
	[200] = {
		.no = 200,
		.name = "NtResumeProcess",
		.nargs = 1,
		.argt = argt_200,
		.argsz = argsz_200
	},
	[201] = {
		.no = 201,
		.name = "NtResumeThread",
		.nargs = 2,
		.argt = argt_201,
		.argsz = argsz_201
	},
	[202] = {
		.no = 202,
		.name = "NtSaveKey",
		.nargs = 2,
		.argt = argt_202,
		.argsz = argsz_202
	},
	[203] = {
		.no = 203,
		.name = "NtSaveKeyEx",
		.nargs = 3,
		.argt = argt_203,
		.argsz = argsz_203
	},
	[204] = {
		.no = 204,
		.name = "NtSaveMergedKeys",
		.nargs = 3,
		.argt = argt_204,
		.argsz = argsz_204
	},
	[205] = {
		.no = 205,
		.name = "NtSecureConnectPort",
		.nargs = 9,
		.argt = argt_205,
		.argsz = argsz_205
	},
	[206] = {
		.no = 206,
		.name = "NtSetContextThread",
		.nargs = 2,
		.argt = argt_206,
		.argsz = argsz_206
	},
	[207] = {
		.no = 207,
		.name = "NtSetDebugFilterState",
		.nargs = 3,
		.argt = argt_207,
		.argsz = argsz_207
	},
	[208] = {
		.no = 208,
		.name = "NtSetDefaultHardErrorPort",
		.nargs = 1,
		.argt = argt_208,
		.argsz = argsz_208
	},
	[209] = {
		.no = 209,
		.name = "NtSetDefaultLocale",
		.nargs = 2,
		.argt = argt_209,
		.argsz = argsz_209
	},
	[210] = {
		.no = 210,
		.name = "NtSetDefaultUILanguage",
		.nargs = 1,
		.argt = argt_210,
		.argsz = argsz_210
	},
	[211] = {
		.no = 211,
		.name = "NtSetEaFile",
		.nargs = 4,
		.argt = argt_211,
		.argsz = argsz_211
	},
	[212] = {
		.no = 212,
		.name = "NtSetEvent",
		.nargs = 2,
		.argt = argt_212,
		.argsz = argsz_212
	},
	[213] = {
		.no = 213,
		.name = "NtSetEventBoostPriority",
		.nargs = 1,
		.argt = argt_213,
		.argsz = argsz_213
	},
	[214] = {
		.no = 214,
		.name = "NtSetHighEventPair",
		.nargs = 1,
		.argt = argt_214,
		.argsz = argsz_214
	},
	[215] = {
		.no = 215,
		.name = "NtSetHighWaitLowEventPair",
		.nargs = 1,
		.argt = argt_215,
		.argsz = argsz_215
	},
	[216] = {
		.no = 216,
		.name = "NtSetInformationDebugObject",
		.nargs = 5,
		.argt = argt_216,
		.argsz = argsz_216
	},
	[217] = {
		.no = 217,
		.name = "NtSetInformationFile",
		.nargs = 5,
		.argt = argt_217,
		.argsz = argsz_217
	},
	[218] = {
		.no = 218,
		.name = "NtSetInformationJobObject",
		.nargs = 4,
		.argt = argt_218,
		.argsz = argsz_218
	},
	[219] = {
		.no = 219,
		.name = "NtSetInformationKey",
		.nargs = 4,
		.argt = argt_219,
		.argsz = argsz_219
	},
	[220] = {
		.no = 220,
		.name = "NtSetInformationObject",
		.nargs = 4,
		.argt = argt_220,
		.argsz = argsz_220
	},
	[221] = {
		.no = 221,
		.name = "NtSetInformationProcess",
		.nargs = 4,
		.argt = argt_221,
		.argsz = argsz_221
	},
	[222] = {
		.no = 222,
		.name = "NtSetInformationThread",
		.nargs = 4,
		.argt = argt_222,
		.argsz = argsz_222
	},
	[223] = {
		.no = 223,
		.name = "NtSetInformationToken",
		.nargs = 4,
		.argt = argt_223,
		.argsz = argsz_223
	},
	[224] = {
		.no = 224,
		.name = "NtSetIntervalProfile",
		.nargs = 2,
		.argt = argt_224,
		.argsz = argsz_224
	},
	[225] = {
		.no = 225,
		.name = "NtSetIoCompletion",
		.nargs = 5,
		.argt = argt_225,
		.argsz = argsz_225
	},
	[226] = {
		.no = 226,
		.name = "NtSetLdtEntries",
		.nargs = 6,
		.argt = argt_226,
		.argsz = argsz_226
	},
	[227] = {
		.no = 227,
		.name = "NtSetLowEventPair",
		.nargs = 1,
		.argt = argt_227,
		.argsz = argsz_227
	},
	[228] = {
		.no = 228,
		.name = "NtSetLowWaitHighEventPair",
		.nargs = 1,
		.argt = argt_228,
		.argsz = argsz_228
	},
	[229] = {
		.no = 229,
		.name = "NtSetQuotaInformationFile",
		.nargs = 4,
		.argt = argt_229,
		.argsz = argsz_229
	},
	[230] = {
		.no = 230,
		.name = "NtSetSecurityObject",
		.nargs = 3,
		.argt = argt_230,
		.argsz = argsz_230
	},
	[231] = {
		.no = 231,
		.name = "NtSetSystemEnvironmentValue",
		.nargs = 2,
		.argt = argt_231,
		.argsz = argsz_231
	},
	[232] = {
		.no = 232,
		.name = "NtSetSystemInformation",
		.nargs = 3,
		.argt = argt_232,
		.argsz = argsz_232
	},
	[233] = {
		.no = 233,
		.name = "NtSetSystemPowerState",
		.nargs = 3,
		.argt = argt_233,
		.argsz = argsz_233
	},
	[234] = {
		.no = 234,
		.name = "NtSetSystemTime",
		.nargs = 2,
		.argt = argt_234,
		.argsz = argsz_234
	},
	[235] = {
		.no = 235,
		.name = "NtSetThreadExecutionState",
		.nargs = 2,
		.argt = argt_235,
		.argsz = argsz_235
	},
	[236] = {
		.no = 236,
		.name = "NtSetTimer",
		.nargs = 7,
		.argt = argt_236,
		.argsz = argsz_236
	},
	[237] = {
		.no = 237,
		.name = "NtSetTimerResolution",
		.nargs = 3,
		.argt = argt_237,
		.argsz = argsz_237
	},
	[238] = {
		.no = 238,
		.name = "NtSetUuidSeed",
		.nargs = 1,
		.argt = argt_238,
		.argsz = argsz_238
	},
	[239] = {
		.no = 239,
		.name = "NtSetValueKey",
		.nargs = 6,
		.argt = argt_239,
		.argsz = argsz_239
	},
	[240] = {
		.no = 240,
		.name = "NtSetVolumeInformationFile",
		.nargs = 5,
		.argt = argt_240,
		.argsz = argsz_240
	},
	[241] = {
		.no = 241,
		.name = "NtShutdownSystem",
		.nargs = 1,
		.argt = argt_241,
		.argsz = argsz_241
	},
	[242] = {
		.no = 242,
		.name = "NtSignalAndWaitForSingleObject",
		.nargs = 4,
		.argt = argt_242,
		.argsz = argsz_242
	},
	[243] = {
		.no = 243,
		.name = "NtStartProfile",
		.nargs = 1,
		.argt = argt_243,
		.argsz = argsz_243
	},
	[244] = {
		.no = 244,
		.name = "NtStopProfile",
		.nargs = 1,
		.argt = argt_244,
		.argsz = argsz_244
	},
	[245] = {
		.no = 245,
		.name = "NtSuspendProcess",
		.nargs = 1,
		.argt = argt_245,
		.argsz = argsz_245
	},
	[246] = {
		.no = 246,
		.name = "NtSuspendThread",
		.nargs = 2,
		.argt = argt_246,
		.argsz = argsz_246
	},
	[247] = {
		.no = 247,
		.name = "NtSystemDebugControl",
		.nargs = 6,
		.argt = argt_247,
		.argsz = argsz_247
	},
	[248] = {
		.no = 248,
		.name = "NtTerminateJobObject",
		.nargs = 2,
		.argt = argt_248,
		.argsz = argsz_248
	},
	[249] = {
		.no = 249,
		.name = "NtTerminateProcess",
		.nargs = 2,
		.argt = argt_249,
		.argsz = argsz_249
	},
	[250] = {
		.no = 250,
		.name = "NtTerminateThread",
		.nargs = 2,
		.argt = argt_250,
		.argsz = argsz_250
	},
	[251] = {
		.no = 251,
		.name = "NtTestAlert",
		.nargs = 0,
		.argt = argt_251,
		.argsz = argsz_251
	},
	[252] = {
		.no = 252,
		.name = "NtTraceEvent",
		.nargs = 4,
		.argt = argt_252,
		.argsz = argsz_252
	},
	[253] = {
		.no = 253,
		.name = "NtTranslateFilePath",
		.nargs = 4,
		.argt = argt_253,
		.argsz = argsz_253
	},
	[254] = {
		.no = 254,
		.name = "NtUnloadDriver",
		.nargs = 1,
		.argt = argt_254,
		.argsz = argsz_254
	},
	[255] = {
		.no = 255,
		.name = "NtUnloadKey",
		.nargs = 1,
		.argt = argt_255,
		.argsz = argsz_255
	},
	[256] = {
		.no = 256,
		.name = "NtUnloadKeyEx",
		.nargs = 2,
		.argt = argt_256,
		.argsz = argsz_256
	},
	[257] = {
		.no = 257,
		.name = "NtUnlockFile",
		.nargs = 5,
		.argt = argt_257,
		.argsz = argsz_257
	},
	[258] = {
		.no = 258,
		.name = "NtUnlockVirtualMemory",
		.nargs = 4,
		.argt = argt_258,
		.argsz = argsz_258
	},
	[259] = {
		.no = 259,
		.name = "NtUnmapViewOfSection",
		.nargs = 2,
		.argt = argt_259,
		.argsz = argsz_259
	},
	[260] = {
		.no = 260,
		.name = "NtVdmControl",
		.nargs = 2,
		.argt = argt_260,
		.argsz = argsz_260
	},
	[261] = {
		.no = 261,
		.name = "NtWaitForDebugEvent",
		.nargs = 4,
		.argt = argt_261,
		.argsz = argsz_261
	},
	[262] = {
		.no = 262,
		.name = "NtWaitForMultipleObjects",
		.nargs = 5,
		.argt = argt_262,
		.argsz = argsz_262
	},
	[263] = {
		.no = 263,
		.name = "NtWaitForSingleObject",
		.nargs = 3,
		.argt = argt_263,
		.argsz = argsz_263
	},
	[264] = {
		.no = 264,
		.name = "NtWaitHighEventPair",
		.nargs = 1,
		.argt = argt_264,
		.argsz = argsz_264
	},
	[265] = {
		.no = 265,
		.name = "NtWaitLowEventPair",
		.nargs = 1,
		.argt = argt_265,
		.argsz = argsz_265
	},
	[266] = {
		.no = 266,
		.name = "NtWriteFile",
		.nargs = 9,
		.argt = argt_266,
		.argsz = argsz_266
	},
	[267] = {
		.no = 267,
		.name = "NtWriteFileGather",
		.nargs = 9,
		.argt = argt_267,
		.argsz = argsz_267
	},
	[268] = {
		.no = 268,
		.name = "NtWriteRequestData",
		.nargs = 6,
		.argt = argt_268,
		.argsz = argsz_268
	},
	[269] = {
		.no = 269,
		.name = "NtWriteVirtualMemory",
		.nargs = 5,
		.argt = argt_269,
		.argsz = argsz_269
	},
	[270] = {
		.no = 270,
		.name = "NtYieldExecution",
		.nargs = 0,
		.argt = argt_270,
		.argsz = argsz_270
	},
	[271] = {
		.no = 271,
		.name = "NtCreateKeyedEvent",
		.nargs = 4,
		.argt = argt_271,
		.argsz = argsz_271
	},
	[272] = {
		.no = 272,
		.name = "NtOpenKeyedEvent",
		.nargs = 3,
		.argt = argt_272,
		.argsz = argsz_272
	},
	[273] = {
		.no = 273,
		.name = "NtReleaseKeyedEvent",
		.nargs = 4,
		.argt = argt_273,
		.argsz = argsz_273
	},
	[274] = {
		.no = 274,
		.name = "NtWaitForKeyedEvent",
		.nargs = 4,
		.argt = argt_274,
		.argsz = argsz_274
	},
	[275] = {
		.no = 275,
		.name = "NtQueryPortInformationProcess",
		.nargs = 0,
		.argt = argt_275,
		.argsz = argsz_275
	},
	
};

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=c: */