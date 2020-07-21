#include <stdint.h>
#include <stdbool.h>
#include "../syscalls2_info.h"
#define MAX_SYSCALL_NO 576
#define MAX_SYSCALL_GENERIC_NO 576
#define MAX_SYSCALL_ARGS 7

#if !defined(__clang__) && __GNUC__ < 5
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

static syscall_argtype_t argt_0[] = {};
static uint8_t argsz_0[] = {};
static syscall_argtype_t argt_1[] = {SYSCALL_ARG_S32};
static uint8_t argsz_1[] = {sizeof(int32_t)};
static syscall_argtype_t argt_2[] = {};
static uint8_t argsz_2[] = {};
static syscall_argtype_t argt_3[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_3[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_5[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_5[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_6[] = {SYSCALL_ARG_S32};
static uint8_t argsz_6[] = {sizeof(int32_t)};
static syscall_argtype_t argt_7[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_7[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_8[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_8[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_9[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_9[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_10[] = {SYSCALL_ARG_STR};
static uint8_t argsz_10[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_12[] = {SYSCALL_ARG_STR};
static uint8_t argsz_12[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_13[] = {SYSCALL_ARG_S32};
static uint8_t argsz_13[] = {sizeof(int32_t)};
static syscall_argtype_t argt_14[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_14[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_15[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_15[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_16[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_16[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_18[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S64, SYSCALL_ARG_S32};
static uint8_t argsz_18[] = {sizeof(uint64_t), sizeof(int64_t), sizeof(int32_t)};
static syscall_argtype_t argt_20[] = {};
static uint8_t argsz_20[] = {};
static syscall_argtype_t argt_21[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_21[] = {sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_22[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_22[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_23[] = {SYSCALL_ARG_U32};
static uint8_t argsz_23[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_24[] = {};
static uint8_t argsz_24[] = {};
static syscall_argtype_t argt_25[] = {};
static uint8_t argsz_25[] = {};
static syscall_argtype_t argt_26[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_26[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_27[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_27[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_28[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_28[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_29[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_29[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_30[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_30[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_31[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_31[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_32[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_32[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_33[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_33[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_34[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S64};
static uint8_t argsz_34[] = {sizeof(uint64_t), sizeof(int64_t)};
static syscall_argtype_t argt_35[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S64};
static uint8_t argsz_35[] = {sizeof(int32_t), sizeof(int64_t)};
static syscall_argtype_t argt_36[] = {};
static uint8_t argsz_36[] = {};
static syscall_argtype_t argt_37[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_37[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_38[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_38[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_39[] = {};
static uint8_t argsz_39[] = {};
static syscall_argtype_t argt_40[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_40[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_41[] = {SYSCALL_ARG_U32};
static uint8_t argsz_41[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_42[] = {};
static uint8_t argsz_42[] = {};
static syscall_argtype_t argt_43[] = {};
static uint8_t argsz_43[] = {};
static syscall_argtype_t argt_44[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_44[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_45[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_45[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_46[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_46[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_47[] = {};
static uint8_t argsz_47[] = {};
static syscall_argtype_t argt_49[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_49[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_50[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_50[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_51[] = {SYSCALL_ARG_STR};
static uint8_t argsz_51[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_53[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_53[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_54[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S64, SYSCALL_ARG_STR};
static uint8_t argsz_54[] = {sizeof(int32_t), sizeof(int64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_55[] = {SYSCALL_ARG_S32};
static uint8_t argsz_55[] = {sizeof(int32_t)};
static syscall_argtype_t argt_56[] = {SYSCALL_ARG_STR};
static uint8_t argsz_56[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_57[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_57[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_58[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_58[] = {sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_59[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_59[] = {sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_60[] = {SYSCALL_ARG_U32};
static uint8_t argsz_60[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_61[] = {SYSCALL_ARG_STR};
static uint8_t argsz_61[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_62[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_62[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_63[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_63[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_64[] = {};
static uint8_t argsz_64[] = {};
static syscall_argtype_t argt_65[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_65[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_66[] = {};
static uint8_t argsz_66[] = {};
static syscall_argtype_t argt_69[] = {SYSCALL_ARG_S32};
static uint8_t argsz_69[] = {sizeof(int32_t)};
static syscall_argtype_t argt_70[] = {SYSCALL_ARG_S32};
static uint8_t argsz_70[] = {sizeof(int32_t)};
static syscall_argtype_t argt_72[] = {SYSCALL_ARG_S32};
static uint8_t argsz_72[] = {sizeof(int32_t)};
static syscall_argtype_t argt_73[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_73[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_74[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_74[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_75[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_75[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_78[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_STR};
static uint8_t argsz_78[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_79[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_79[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_80[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_80[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_81[] = {};
static uint8_t argsz_81[] = {};
static syscall_argtype_t argt_82[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_82[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_83[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_83[] = {sizeof(uint32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_84[] = {};
static uint8_t argsz_84[] = {};
static syscall_argtype_t argt_85[] = {SYSCALL_ARG_STR};
static uint8_t argsz_85[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_86[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_86[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_87[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_87[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_88[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_88[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_89[] = {};
static uint8_t argsz_89[] = {};
static syscall_argtype_t argt_90[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_90[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_92[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S64};
static uint8_t argsz_92[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int64_t)};
static syscall_argtype_t argt_93[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_93[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_95[] = {SYSCALL_ARG_S32};
static uint8_t argsz_95[] = {sizeof(int32_t)};
static syscall_argtype_t argt_96[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_96[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_97[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_97[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_98[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_98[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_99[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_99[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_100[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_100[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_101[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_101[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_102[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_102[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_103[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_103[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_104[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_104[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_105[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_105[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_106[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_106[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_108[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_108[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_109[] = {SYSCALL_ARG_S32};
static uint8_t argsz_109[] = {sizeof(int32_t)};
static syscall_argtype_t argt_110[] = {SYSCALL_ARG_S32};
static uint8_t argsz_110[] = {sizeof(int32_t)};
static syscall_argtype_t argt_111[] = {SYSCALL_ARG_U32};
static uint8_t argsz_111[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_112[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_112[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_113[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_113[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_114[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_114[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_116[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_116[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_117[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_117[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_118[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_118[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_120[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_120[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_121[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_121[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_122[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_122[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_123[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_123[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_124[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_124[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_125[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_125[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_126[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_126[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_127[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_127[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_128[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_128[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_131[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_131[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_132[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_132[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_133[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_133[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_134[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_134[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_135[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_135[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_136[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_136[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_137[] = {SYSCALL_ARG_STR};
static uint8_t argsz_137[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_138[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_138[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_140[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_140[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_141[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_141[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_142[] = {};
static uint8_t argsz_142[] = {};
static syscall_argtype_t argt_143[] = {SYSCALL_ARG_S64};
static uint8_t argsz_143[] = {sizeof(int64_t)};
static syscall_argtype_t argt_144[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_144[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_145[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_145[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_146[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_146[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_147[] = {};
static uint8_t argsz_147[] = {};
static syscall_argtype_t argt_148[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_148[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_149[] = {};
static uint8_t argsz_149[] = {};
static syscall_argtype_t argt_150[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_150[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_154[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_154[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_155[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_155[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_156[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_156[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_157[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_157[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_158[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_158[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_160[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_160[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_161[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_161[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_162[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_162[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_163[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_163[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_164[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_164[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_165[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_165[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_166[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_166[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_169[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_169[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_175[] = {SYSCALL_ARG_S32};
static uint8_t argsz_175[] = {sizeof(int32_t)};
static syscall_argtype_t argt_176[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_176[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_181[] = {SYSCALL_ARG_U32};
static uint8_t argsz_181[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_182[] = {SYSCALL_ARG_U32};
static uint8_t argsz_182[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_183[] = {SYSCALL_ARG_U32};
static uint8_t argsz_183[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_188[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_188[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_189[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_189[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_190[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_190[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_191[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_191[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_192[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_192[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_194[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_194[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_195[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_195[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_196[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_196[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_198[] = {};
static uint8_t argsz_198[] = {};
static syscall_argtype_t argt_202[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_202[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_203[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_203[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_204[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_204[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_205[] = {SYSCALL_ARG_STR};
static uint8_t argsz_205[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_206[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_206[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_207[] = {SYSCALL_ARG_S32};
static uint8_t argsz_207[] = {sizeof(int32_t)};
static syscall_argtype_t argt_209[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_209[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_220[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_220[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_221[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_221[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_222[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_222[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_224[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_224[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_225[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_225[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_226[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_226[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_227[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S64, SYSCALL_ARG_S32};
static uint8_t argsz_227[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(int64_t), sizeof(int32_t)};
static syscall_argtype_t argt_229[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_229[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_230[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_230[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_231[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_231[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_232[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_232[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_233[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_233[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_234[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_234[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_235[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_235[] = {sizeof(uint32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_236[] = {SYSCALL_ARG_S32};
static uint8_t argsz_236[] = {sizeof(int32_t)};
static syscall_argtype_t argt_237[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_237[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_238[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_238[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_239[] = {SYSCALL_ARG_S32};
static uint8_t argsz_239[] = {sizeof(int32_t)};
static syscall_argtype_t argt_240[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_240[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_241[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_241[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_242[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_242[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_243[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_243[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_244[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_244[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_247[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_247[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_248[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_248[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_250[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_250[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_251[] = {SYSCALL_ARG_S32};
static uint8_t argsz_251[] = {sizeof(int32_t)};
static syscall_argtype_t argt_253[] = {};
static uint8_t argsz_253[] = {};
static syscall_argtype_t argt_254[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_254[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_255[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_255[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_256[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_256[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_257[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_257[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_272[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_272[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_274[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_274[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_276[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_276[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_278[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_278[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_279[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_279[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_280[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_280[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_289[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U64};
static uint8_t argsz_289[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_290[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U64};
static uint8_t argsz_290[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_297[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_297[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_298[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_298[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_299[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_299[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_300[] = {SYSCALL_ARG_S32};
static uint8_t argsz_300[] = {sizeof(int32_t)};
static syscall_argtype_t argt_301[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_301[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_302[] = {SYSCALL_ARG_S32};
static uint8_t argsz_302[] = {sizeof(int32_t)};
static syscall_argtype_t argt_303[] = {SYSCALL_ARG_STR};
static uint8_t argsz_303[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_304[] = {SYSCALL_ARG_STR};
static uint8_t argsz_304[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_305[] = {SYSCALL_ARG_S32};
static uint8_t argsz_305[] = {sizeof(int32_t)};
static syscall_argtype_t argt_306[] = {SYSCALL_ARG_STR};
static uint8_t argsz_306[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_307[] = {SYSCALL_ARG_S32};
static uint8_t argsz_307[] = {sizeof(int32_t)};
static syscall_argtype_t argt_308[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_308[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_309[] = {SYSCALL_ARG_S32};
static uint8_t argsz_309[] = {sizeof(int32_t)};
static syscall_argtype_t argt_310[] = {SYSCALL_ARG_S32};
static uint8_t argsz_310[] = {sizeof(int32_t)};
static syscall_argtype_t argt_311[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_311[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_312[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_312[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_314[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_314[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_315[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_315[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_316[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_316[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_317[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_317[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_318[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_318[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_319[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_319[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_320[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_320[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_321[] = {};
static uint8_t argsz_321[] = {};
static syscall_argtype_t argt_324[] = {SYSCALL_ARG_S32};
static uint8_t argsz_324[] = {sizeof(int32_t)};
static syscall_argtype_t argt_325[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_325[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_327[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_327[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_328[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_328[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_329[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_329[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_330[] = {SYSCALL_ARG_S32};
static uint8_t argsz_330[] = {sizeof(int32_t)};
static syscall_argtype_t argt_331[] = {};
static uint8_t argsz_331[] = {};
static syscall_argtype_t argt_332[] = {SYSCALL_ARG_S32};
static uint8_t argsz_332[] = {sizeof(int32_t)};
static syscall_argtype_t argt_333[] = {SYSCALL_ARG_S32};
static uint8_t argsz_333[] = {sizeof(int32_t)};
static syscall_argtype_t argt_334[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_334[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_335[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_335[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_336[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U64, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_336[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_337[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_337[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_338[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_338[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_339[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_339[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_340[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_340[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_341[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_341[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_342[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_342[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_343[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_343[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_344[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_344[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_345[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_345[] = {sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_346[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_346[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_347[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_347[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_348[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_348[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_349[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_349[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_350[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_350[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_351[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_351[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_352[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_352[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_353[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_353[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_354[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_354[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_355[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_355[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_356[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_356[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_357[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_357[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_358[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_358[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_359[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_359[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_360[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_360[] = {sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_361[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_361[] = {sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_362[] = {};
static uint8_t argsz_362[] = {};
static syscall_argtype_t argt_363[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_363[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_371[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_371[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_372[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_372[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_373[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_373[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_374[] = {SYSCALL_ARG_S32};
static uint8_t argsz_374[] = {sizeof(int32_t)};
static syscall_argtype_t argt_376[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_376[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_377[] = {SYSCALL_ARG_S64, SYSCALL_ARG_S64, SYSCALL_ARG_S64, SYSCALL_ARG_S64, SYSCALL_ARG_S64, SYSCALL_ARG_S64, SYSCALL_ARG_S64};
static uint8_t argsz_377[] = {sizeof(int64_t), sizeof(int64_t), sizeof(int64_t), sizeof(int64_t), sizeof(int64_t), sizeof(int64_t), sizeof(int64_t)};
static syscall_argtype_t argt_378[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_378[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_384[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_384[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_385[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_385[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_386[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_386[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_387[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_387[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_388[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_388[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_389[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_389[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_390[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_390[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_391[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S64};
static uint8_t argsz_391[] = {sizeof(uint64_t), sizeof(int64_t)};
static syscall_argtype_t argt_392[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_392[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_393[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U64, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_393[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_394[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_394[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_395[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S64, SYSCALL_ARG_S32};
static uint8_t argsz_395[] = {sizeof(uint64_t), sizeof(int64_t), sizeof(int32_t)};
static syscall_argtype_t argt_396[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_396[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_397[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_397[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_398[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_398[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_400[] = {SYSCALL_ARG_U32};
static uint8_t argsz_400[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_401[] = {SYSCALL_ARG_U32};
static uint8_t argsz_401[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_402[] = {SYSCALL_ARG_U32};
static uint8_t argsz_402[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_403[] = {SYSCALL_ARG_U32};
static uint8_t argsz_403[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_404[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_404[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_405[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_405[] = {sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_406[] = {SYSCALL_ARG_STR};
static uint8_t argsz_406[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_407[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_407[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_408[] = {SYSCALL_ARG_U32};
static uint8_t argsz_408[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_409[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_409[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_410[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_410[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_411[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_411[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_412[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_412[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_413[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_413[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_414[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_414[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_415[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_415[] = {sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_416[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_416[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_417[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_417[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_421[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_421[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_422[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_422[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_423[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_423[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_424[] = {SYSCALL_ARG_STR};
static uint8_t argsz_424[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_425[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_425[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_426[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_426[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_427[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_427[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_428[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_428[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_429[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_429[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_430[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_430[] = {sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_431[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_431[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_432[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_432[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_433[] = {SYSCALL_ARG_S64, SYSCALL_ARG_S32};
static uint8_t argsz_433[] = {sizeof(int64_t), sizeof(int32_t)};
static syscall_argtype_t argt_436[] = {SYSCALL_ARG_S32};
static uint8_t argsz_436[] = {sizeof(int32_t)};
static syscall_argtype_t argt_437[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_437[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_438[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_438[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_439[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_439[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_441[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_441[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_442[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_442[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_443[] = {SYSCALL_ARG_S64};
static uint8_t argsz_443[] = {sizeof(int64_t)};
static syscall_argtype_t argt_444[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_444[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_445[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_445[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_446[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_446[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_447[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_447[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_448[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_448[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_449[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_449[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_450[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_450[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_451[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_451[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_452[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_452[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_453[] = {SYSCALL_ARG_STR};
static uint8_t argsz_453[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_454[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_S64, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_454[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(int64_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_455[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_455[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_456[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_456[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_457[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_457[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_458[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_458[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_459[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_459[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_460[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_460[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_461[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_461[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_462[] = {SYSCALL_ARG_STR};
static uint8_t argsz_462[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_463[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_463[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_464[] = {SYSCALL_ARG_S64, SYSCALL_ARG_STR};
static uint8_t argsz_464[] = {sizeof(int64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_465[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_465[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_466[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_466[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_471[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_471[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_472[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_472[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_473[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_473[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_474[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_474[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_475[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U64};
static uint8_t argsz_475[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_476[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U64};
static uint8_t argsz_476[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_478[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U64, SYSCALL_ARG_S32};
static uint8_t argsz_478[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_479[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U64};
static uint8_t argsz_479[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_480[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U64};
static uint8_t argsz_480[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_481[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S64, SYSCALL_ARG_S32};
static uint8_t argsz_481[] = {sizeof(int32_t), sizeof(int64_t), sizeof(int32_t)};
static syscall_argtype_t argt_482[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_482[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_483[] = {SYSCALL_ARG_STR};
static uint8_t argsz_483[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_484[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_484[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_485[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_485[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_486[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_486[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_487[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_487[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_488[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_488[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_489[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_489[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_490[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_490[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_491[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_491[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_492[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_492[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_493[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_493[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_494[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_494[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_495[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_495[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_496[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_496[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_497[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_497[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_498[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_498[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_499[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_499[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_500[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_500[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_501[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_501[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_502[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_502[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_503[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_503[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_504[] = {SYSCALL_ARG_S32};
static uint8_t argsz_504[] = {sizeof(int32_t)};
static syscall_argtype_t argt_505[] = {SYSCALL_ARG_STR};
static uint8_t argsz_505[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_506[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_506[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_507[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_507[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_508[] = {SYSCALL_ARG_S32};
static uint8_t argsz_508[] = {sizeof(int32_t)};
static syscall_argtype_t argt_509[] = {SYSCALL_ARG_S32};
static uint8_t argsz_509[] = {sizeof(int32_t)};
static syscall_argtype_t argt_510[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_510[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_511[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_511[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_512[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_512[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_513[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_513[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_515[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_515[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_516[] = {};
static uint8_t argsz_516[] = {};
static syscall_argtype_t argt_517[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_517[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_518[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_518[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_519[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_519[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_520[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_520[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_522[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_522[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_523[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_523[] = {sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_524[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_524[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_525[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_525[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_526[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_526[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_527[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_527[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_528[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_528[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_529[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_529[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_530[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U64, SYSCALL_ARG_U64};
static uint8_t argsz_530[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_531[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U64, SYSCALL_ARG_U64, SYSCALL_ARG_S32};
static uint8_t argsz_531[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_532[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_532[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_533[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_533[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_534[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_534[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_535[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_535[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_536[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_536[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_537[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_537[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_538[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_538[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_539[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_539[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_540[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S64, SYSCALL_ARG_S32};
static uint8_t argsz_540[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int64_t), sizeof(int32_t)};
static syscall_argtype_t argt_541[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_541[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_542[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_542[] = {sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_543[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_543[] = {sizeof(uint64_t)};
static syscall_argtype_t argt_544[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_544[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_545[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_545[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_546[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_546[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_547[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_547[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_550[] = {SYSCALL_ARG_S32};
static uint8_t argsz_550[] = {sizeof(int32_t)};
static syscall_argtype_t argt_551[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_551[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_552[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_552[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_553[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_553[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_554[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_554[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_555[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_555[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_556[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_556[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_557[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S64, SYSCALL_ARG_S32};
static uint8_t argsz_557[] = {sizeof(uint64_t), sizeof(int64_t), sizeof(int32_t)};
static syscall_argtype_t argt_558[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_558[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_559[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_559[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_560[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_560[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_561[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_561[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_562[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_562[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_563[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_563[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_564[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_564[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_565[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_STR};
static uint8_t argsz_565[] = {sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_566[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_566[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_567[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_567[] = {sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_568[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_568[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_569[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_569[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_570[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_570[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_571[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_571[] = {sizeof(uint64_t), sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_572[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_572[] = {sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_573[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_573[] = {sizeof(int32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_574[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_574[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_575[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_575[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_576[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_576[] = {sizeof(int32_t), sizeof(uint64_t)};


syscall_info_t __syscall_info_a[] = {
	/* note that uninitialized values will be zeroed-out */
	[0] = {
		.no = 0,
		.name = "nosys",
		.nargs = 0,
		.argt = argt_0,
		.argsz = argsz_0,
		.noreturn = false
	},
	[1] = {
		.no = 1,
		.name = "sys_exit",
		.nargs = 1,
		.argt = argt_1,
		.argsz = argsz_1,
		.noreturn = true
	},
	[2] = {
		.no = 2,
		.name = "fork",
		.nargs = 0,
		.argt = argt_2,
		.argsz = argsz_2,
		.noreturn = false
	},
	[3] = {
		.no = 3,
		.name = "read",
		.nargs = 3,
		.argt = argt_3,
		.argsz = argsz_3,
		.noreturn = false
	},
	[4] = {
		.no = 4,
		.name = "write",
		.nargs = 3,
		.argt = argt_4,
		.argsz = argsz_4,
		.noreturn = false
	},
	[5] = {
		.no = 5,
		.name = "open",
		.nargs = 3,
		.argt = argt_5,
		.argsz = argsz_5,
		.noreturn = false
	},
	[6] = {
		.no = 6,
		.name = "close",
		.nargs = 1,
		.argt = argt_6,
		.argsz = argsz_6,
		.noreturn = false
	},
	[7] = {
		.no = 7,
		.name = "wait4",
		.nargs = 4,
		.argt = argt_7,
		.argsz = argsz_7,
		.noreturn = false
	},
	[8] = {
		.no = 8,
		.name = "creat",
		.nargs = 2,
		.argt = argt_8,
		.argsz = argsz_8,
		.noreturn = false
	},
	[9] = {
		.no = 9,
		.name = "link",
		.nargs = 2,
		.argt = argt_9,
		.argsz = argsz_9,
		.noreturn = false
	},
	[10] = {
		.no = 10,
		.name = "unlink",
		.nargs = 1,
		.argt = argt_10,
		.argsz = argsz_10,
		.noreturn = false
	},
	[12] = {
		.no = 12,
		.name = "chdir",
		.nargs = 1,
		.argt = argt_12,
		.argsz = argsz_12,
		.noreturn = false
	},
	[13] = {
		.no = 13,
		.name = "fchdir",
		.nargs = 1,
		.argt = argt_13,
		.argsz = argsz_13,
		.noreturn = false
	},
	[14] = {
		.no = 14,
		.name = "mknod",
		.nargs = 3,
		.argt = argt_14,
		.argsz = argsz_14,
		.noreturn = false
	},
	[15] = {
		.no = 15,
		.name = "chmod",
		.nargs = 2,
		.argt = argt_15,
		.argsz = argsz_15,
		.noreturn = false
	},
	[16] = {
		.no = 16,
		.name = "chown",
		.nargs = 3,
		.argt = argt_16,
		.argsz = argsz_16,
		.noreturn = false
	},
	[18] = {
		.no = 18,
		.name = "getfsstat",
		.nargs = 3,
		.argt = argt_18,
		.argsz = argsz_18,
		.noreturn = false
	},
	[20] = {
		.no = 20,
		.name = "getpid",
		.nargs = 0,
		.argt = argt_20,
		.argsz = argsz_20,
		.noreturn = false
	},
	[21] = {
		.no = 21,
		.name = "mount",
		.nargs = 4,
		.argt = argt_21,
		.argsz = argsz_21,
		.noreturn = false
	},
	[22] = {
		.no = 22,
		.name = "unmount",
		.nargs = 2,
		.argt = argt_22,
		.argsz = argsz_22,
		.noreturn = false
	},
	[23] = {
		.no = 23,
		.name = "setuid",
		.nargs = 1,
		.argt = argt_23,
		.argsz = argsz_23,
		.noreturn = false
	},
	[24] = {
		.no = 24,
		.name = "getuid",
		.nargs = 0,
		.argt = argt_24,
		.argsz = argsz_24,
		.noreturn = false
	},
	[25] = {
		.no = 25,
		.name = "geteuid",
		.nargs = 0,
		.argt = argt_25,
		.argsz = argsz_25,
		.noreturn = false
	},
	[26] = {
		.no = 26,
		.name = "ptrace",
		.nargs = 4,
		.argt = argt_26,
		.argsz = argsz_26,
		.noreturn = false
	},
	[27] = {
		.no = 27,
		.name = "recvmsg",
		.nargs = 3,
		.argt = argt_27,
		.argsz = argsz_27,
		.noreturn = false
	},
	[28] = {
		.no = 28,
		.name = "sendmsg",
		.nargs = 3,
		.argt = argt_28,
		.argsz = argsz_28,
		.noreturn = false
	},
	[29] = {
		.no = 29,
		.name = "recvfrom",
		.nargs = 6,
		.argt = argt_29,
		.argsz = argsz_29,
		.noreturn = false
	},
	[30] = {
		.no = 30,
		.name = "accept",
		.nargs = 3,
		.argt = argt_30,
		.argsz = argsz_30,
		.noreturn = false
	},
	[31] = {
		.no = 31,
		.name = "getpeername",
		.nargs = 3,
		.argt = argt_31,
		.argsz = argsz_31,
		.noreturn = false
	},
	[32] = {
		.no = 32,
		.name = "getsockname",
		.nargs = 3,
		.argt = argt_32,
		.argsz = argsz_32,
		.noreturn = false
	},
	[33] = {
		.no = 33,
		.name = "access",
		.nargs = 2,
		.argt = argt_33,
		.argsz = argsz_33,
		.noreturn = false
	},
	[34] = {
		.no = 34,
		.name = "chflags",
		.nargs = 2,
		.argt = argt_34,
		.argsz = argsz_34,
		.noreturn = false
	},
	[35] = {
		.no = 35,
		.name = "fchflags",
		.nargs = 2,
		.argt = argt_35,
		.argsz = argsz_35,
		.noreturn = false
	},
	[36] = {
		.no = 36,
		.name = "sync",
		.nargs = 0,
		.argt = argt_36,
		.argsz = argsz_36,
		.noreturn = false
	},
	[37] = {
		.no = 37,
		.name = "kill",
		.nargs = 2,
		.argt = argt_37,
		.argsz = argsz_37,
		.noreturn = false
	},
	[38] = {
		.no = 38,
		.name = "stat",
		.nargs = 2,
		.argt = argt_38,
		.argsz = argsz_38,
		.noreturn = false
	},
	[39] = {
		.no = 39,
		.name = "getppid",
		.nargs = 0,
		.argt = argt_39,
		.argsz = argsz_39,
		.noreturn = false
	},
	[40] = {
		.no = 40,
		.name = "lstat",
		.nargs = 2,
		.argt = argt_40,
		.argsz = argsz_40,
		.noreturn = false
	},
	[41] = {
		.no = 41,
		.name = "dup",
		.nargs = 1,
		.argt = argt_41,
		.argsz = argsz_41,
		.noreturn = false
	},
	[42] = {
		.no = 42,
		.name = "pipe",
		.nargs = 0,
		.argt = argt_42,
		.argsz = argsz_42,
		.noreturn = false
	},
	[43] = {
		.no = 43,
		.name = "getegid",
		.nargs = 0,
		.argt = argt_43,
		.argsz = argsz_43,
		.noreturn = false
	},
	[44] = {
		.no = 44,
		.name = "profil",
		.nargs = 4,
		.argt = argt_44,
		.argsz = argsz_44,
		.noreturn = false
	},
	[45] = {
		.no = 45,
		.name = "ktrace",
		.nargs = 4,
		.argt = argt_45,
		.argsz = argsz_45,
		.noreturn = false
	},
	[46] = {
		.no = 46,
		.name = "sigaction",
		.nargs = 3,
		.argt = argt_46,
		.argsz = argsz_46,
		.noreturn = false
	},
	[47] = {
		.no = 47,
		.name = "getgid",
		.nargs = 0,
		.argt = argt_47,
		.argsz = argsz_47,
		.noreturn = false
	},
	[49] = {
		.no = 49,
		.name = "getlogin",
		.nargs = 2,
		.argt = argt_49,
		.argsz = argsz_49,
		.noreturn = false
	},
	[50] = {
		.no = 50,
		.name = "setlogin",
		.nargs = 1,
		.argt = argt_50,
		.argsz = argsz_50,
		.noreturn = false
	},
	[51] = {
		.no = 51,
		.name = "acct",
		.nargs = 1,
		.argt = argt_51,
		.argsz = argsz_51,
		.noreturn = false
	},
	[53] = {
		.no = 53,
		.name = "sigaltstack",
		.nargs = 2,
		.argt = argt_53,
		.argsz = argsz_53,
		.noreturn = false
	},
	[54] = {
		.no = 54,
		.name = "ioctl",
		.nargs = 3,
		.argt = argt_54,
		.argsz = argsz_54,
		.noreturn = false
	},
	[55] = {
		.no = 55,
		.name = "reboot",
		.nargs = 1,
		.argt = argt_55,
		.argsz = argsz_55,
		.noreturn = false
	},
	[56] = {
		.no = 56,
		.name = "revoke",
		.nargs = 1,
		.argt = argt_56,
		.argsz = argsz_56,
		.noreturn = false
	},
	[57] = {
		.no = 57,
		.name = "symlink",
		.nargs = 2,
		.argt = argt_57,
		.argsz = argsz_57,
		.noreturn = false
	},
	[58] = {
		.no = 58,
		.name = "readlink",
		.nargs = 3,
		.argt = argt_58,
		.argsz = argsz_58,
		.noreturn = false
	},
	[59] = {
		.no = 59,
		.name = "execve",
		.nargs = 3,
		.argt = argt_59,
		.argsz = argsz_59,
		.noreturn = true
	},
	[60] = {
		.no = 60,
		.name = "umask",
		.nargs = 1,
		.argt = argt_60,
		.argsz = argsz_60,
		.noreturn = false
	},
	[61] = {
		.no = 61,
		.name = "chroot",
		.nargs = 1,
		.argt = argt_61,
		.argsz = argsz_61,
		.noreturn = false
	},
	[62] = {
		.no = 62,
		.name = "fstat",
		.nargs = 2,
		.argt = argt_62,
		.argsz = argsz_62,
		.noreturn = false
	},
	[63] = {
		.no = 63,
		.name = "getkerninfo",
		.nargs = 4,
		.argt = argt_63,
		.argsz = argsz_63,
		.noreturn = false
	},
	[64] = {
		.no = 64,
		.name = "getpagesize",
		.nargs = 0,
		.argt = argt_64,
		.argsz = argsz_64,
		.noreturn = false
	},
	[65] = {
		.no = 65,
		.name = "msync",
		.nargs = 3,
		.argt = argt_65,
		.argsz = argsz_65,
		.noreturn = false
	},
	[66] = {
		.no = 66,
		.name = "vfork",
		.nargs = 0,
		.argt = argt_66,
		.argsz = argsz_66,
		.noreturn = false
	},
	[69] = {
		.no = 69,
		.name = "sbrk",
		.nargs = 1,
		.argt = argt_69,
		.argsz = argsz_69,
		.noreturn = false
	},
	[70] = {
		.no = 70,
		.name = "sstk",
		.nargs = 1,
		.argt = argt_70,
		.argsz = argsz_70,
		.noreturn = false
	},
	[72] = {
		.no = 72,
		.name = "vadvise",
		.nargs = 1,
		.argt = argt_72,
		.argsz = argsz_72,
		.noreturn = false
	},
	[73] = {
		.no = 73,
		.name = "munmap",
		.nargs = 2,
		.argt = argt_73,
		.argsz = argsz_73,
		.noreturn = false
	},
	[74] = {
		.no = 74,
		.name = "mprotect",
		.nargs = 3,
		.argt = argt_74,
		.argsz = argsz_74,
		.noreturn = false
	},
	[75] = {
		.no = 75,
		.name = "madvise",
		.nargs = 3,
		.argt = argt_75,
		.argsz = argsz_75,
		.noreturn = false
	},
	[78] = {
		.no = 78,
		.name = "mincore",
		.nargs = 3,
		.argt = argt_78,
		.argsz = argsz_78,
		.noreturn = false
	},
	[79] = {
		.no = 79,
		.name = "getgroups",
		.nargs = 2,
		.argt = argt_79,
		.argsz = argsz_79,
		.noreturn = false
	},
	[80] = {
		.no = 80,
		.name = "setgroups",
		.nargs = 2,
		.argt = argt_80,
		.argsz = argsz_80,
		.noreturn = false
	},
	[81] = {
		.no = 81,
		.name = "getpgrp",
		.nargs = 0,
		.argt = argt_81,
		.argsz = argsz_81,
		.noreturn = false
	},
	[82] = {
		.no = 82,
		.name = "setpgid",
		.nargs = 2,
		.argt = argt_82,
		.argsz = argsz_82,
		.noreturn = false
	},
	[83] = {
		.no = 83,
		.name = "setitimer",
		.nargs = 3,
		.argt = argt_83,
		.argsz = argsz_83,
		.noreturn = false
	},
	[84] = {
		.no = 84,
		.name = "wait",
		.nargs = 0,
		.argt = argt_84,
		.argsz = argsz_84,
		.noreturn = false
	},
	[85] = {
		.no = 85,
		.name = "swapon",
		.nargs = 1,
		.argt = argt_85,
		.argsz = argsz_85,
		.noreturn = false
	},
	[86] = {
		.no = 86,
		.name = "getitimer",
		.nargs = 2,
		.argt = argt_86,
		.argsz = argsz_86,
		.noreturn = false
	},
	[87] = {
		.no = 87,
		.name = "gethostname",
		.nargs = 2,
		.argt = argt_87,
		.argsz = argsz_87,
		.noreturn = false
	},
	[88] = {
		.no = 88,
		.name = "sethostname",
		.nargs = 2,
		.argt = argt_88,
		.argsz = argsz_88,
		.noreturn = false
	},
	[89] = {
		.no = 89,
		.name = "getdtablesize",
		.nargs = 0,
		.argt = argt_89,
		.argsz = argsz_89,
		.noreturn = false
	},
	[90] = {
		.no = 90,
		.name = "dup2",
		.nargs = 2,
		.argt = argt_90,
		.argsz = argsz_90,
		.noreturn = false
	},
	[92] = {
		.no = 92,
		.name = "fcntl",
		.nargs = 3,
		.argt = argt_92,
		.argsz = argsz_92,
		.noreturn = false
	},
	[93] = {
		.no = 93,
		.name = "select",
		.nargs = 5,
		.argt = argt_93,
		.argsz = argsz_93,
		.noreturn = false
	},
	[95] = {
		.no = 95,
		.name = "fsync",
		.nargs = 1,
		.argt = argt_95,
		.argsz = argsz_95,
		.noreturn = false
	},
	[96] = {
		.no = 96,
		.name = "setpriority",
		.nargs = 3,
		.argt = argt_96,
		.argsz = argsz_96,
		.noreturn = false
	},
	[97] = {
		.no = 97,
		.name = "socket",
		.nargs = 3,
		.argt = argt_97,
		.argsz = argsz_97,
		.noreturn = false
	},
	[98] = {
		.no = 98,
		.name = "connect",
		.nargs = 3,
		.argt = argt_98,
		.argsz = argsz_98,
		.noreturn = false
	},
	[99] = {
		.no = 99,
		.name = "accept",
		.nargs = 3,
		.argt = argt_99,
		.argsz = argsz_99,
		.noreturn = false
	},
	[100] = {
		.no = 100,
		.name = "getpriority",
		.nargs = 2,
		.argt = argt_100,
		.argsz = argsz_100,
		.noreturn = false
	},
	[101] = {
		.no = 101,
		.name = "send",
		.nargs = 4,
		.argt = argt_101,
		.argsz = argsz_101,
		.noreturn = false
	},
	[102] = {
		.no = 102,
		.name = "recv",
		.nargs = 4,
		.argt = argt_102,
		.argsz = argsz_102,
		.noreturn = false
	},
	[103] = {
		.no = 103,
		.name = "sigreturn",
		.nargs = 1,
		.argt = argt_103,
		.argsz = argsz_103,
		.noreturn = false
	},
	[104] = {
		.no = 104,
		.name = "bind",
		.nargs = 3,
		.argt = argt_104,
		.argsz = argsz_104,
		.noreturn = false
	},
	[105] = {
		.no = 105,
		.name = "setsockopt",
		.nargs = 5,
		.argt = argt_105,
		.argsz = argsz_105,
		.noreturn = false
	},
	[106] = {
		.no = 106,
		.name = "listen",
		.nargs = 2,
		.argt = argt_106,
		.argsz = argsz_106,
		.noreturn = false
	},
	[108] = {
		.no = 108,
		.name = "sigvec",
		.nargs = 3,
		.argt = argt_108,
		.argsz = argsz_108,
		.noreturn = false
	},
	[109] = {
		.no = 109,
		.name = "sigblock",
		.nargs = 1,
		.argt = argt_109,
		.argsz = argsz_109,
		.noreturn = false
	},
	[110] = {
		.no = 110,
		.name = "sigsetmask",
		.nargs = 1,
		.argt = argt_110,
		.argsz = argsz_110,
		.noreturn = false
	},
	[111] = {
		.no = 111,
		.name = "sigsuspend",
		.nargs = 1,
		.argt = argt_111,
		.argsz = argsz_111,
		.noreturn = false
	},
	[112] = {
		.no = 112,
		.name = "sigstack",
		.nargs = 2,
		.argt = argt_112,
		.argsz = argsz_112,
		.noreturn = false
	},
	[113] = {
		.no = 113,
		.name = "recvmsg",
		.nargs = 3,
		.argt = argt_113,
		.argsz = argsz_113,
		.noreturn = false
	},
	[114] = {
		.no = 114,
		.name = "sendmsg",
		.nargs = 3,
		.argt = argt_114,
		.argsz = argsz_114,
		.noreturn = false
	},
	[116] = {
		.no = 116,
		.name = "gettimeofday",
		.nargs = 2,
		.argt = argt_116,
		.argsz = argsz_116,
		.noreturn = false
	},
	[117] = {
		.no = 117,
		.name = "getrusage",
		.nargs = 2,
		.argt = argt_117,
		.argsz = argsz_117,
		.noreturn = false
	},
	[118] = {
		.no = 118,
		.name = "getsockopt",
		.nargs = 5,
		.argt = argt_118,
		.argsz = argsz_118,
		.noreturn = false
	},
	[120] = {
		.no = 120,
		.name = "readv",
		.nargs = 3,
		.argt = argt_120,
		.argsz = argsz_120,
		.noreturn = false
	},
	[121] = {
		.no = 121,
		.name = "writev",
		.nargs = 3,
		.argt = argt_121,
		.argsz = argsz_121,
		.noreturn = false
	},
	[122] = {
		.no = 122,
		.name = "settimeofday",
		.nargs = 2,
		.argt = argt_122,
		.argsz = argsz_122,
		.noreturn = false
	},
	[123] = {
		.no = 123,
		.name = "fchown",
		.nargs = 3,
		.argt = argt_123,
		.argsz = argsz_123,
		.noreturn = false
	},
	[124] = {
		.no = 124,
		.name = "fchmod",
		.nargs = 2,
		.argt = argt_124,
		.argsz = argsz_124,
		.noreturn = false
	},
	[125] = {
		.no = 125,
		.name = "recvfrom",
		.nargs = 6,
		.argt = argt_125,
		.argsz = argsz_125,
		.noreturn = false
	},
	[126] = {
		.no = 126,
		.name = "setreuid",
		.nargs = 2,
		.argt = argt_126,
		.argsz = argsz_126,
		.noreturn = false
	},
	[127] = {
		.no = 127,
		.name = "setregid",
		.nargs = 2,
		.argt = argt_127,
		.argsz = argsz_127,
		.noreturn = false
	},
	[128] = {
		.no = 128,
		.name = "rename",
		.nargs = 2,
		.argt = argt_128,
		.argsz = argsz_128,
		.noreturn = false
	},
	[131] = {
		.no = 131,
		.name = "flock",
		.nargs = 2,
		.argt = argt_131,
		.argsz = argsz_131,
		.noreturn = false
	},
	[132] = {
		.no = 132,
		.name = "mkfifo",
		.nargs = 2,
		.argt = argt_132,
		.argsz = argsz_132,
		.noreturn = false
	},
	[133] = {
		.no = 133,
		.name = "sendto",
		.nargs = 6,
		.argt = argt_133,
		.argsz = argsz_133,
		.noreturn = false
	},
	[134] = {
		.no = 134,
		.name = "shutdown",
		.nargs = 2,
		.argt = argt_134,
		.argsz = argsz_134,
		.noreturn = false
	},
	[135] = {
		.no = 135,
		.name = "socketpair",
		.nargs = 4,
		.argt = argt_135,
		.argsz = argsz_135,
		.noreturn = false
	},
	[136] = {
		.no = 136,
		.name = "mkdir",
		.nargs = 2,
		.argt = argt_136,
		.argsz = argsz_136,
		.noreturn = false
	},
	[137] = {
		.no = 137,
		.name = "rmdir",
		.nargs = 1,
		.argt = argt_137,
		.argsz = argsz_137,
		.noreturn = false
	},
	[138] = {
		.no = 138,
		.name = "utimes",
		.nargs = 2,
		.argt = argt_138,
		.argsz = argsz_138,
		.noreturn = false
	},
	[140] = {
		.no = 140,
		.name = "adjtime",
		.nargs = 2,
		.argt = argt_140,
		.argsz = argsz_140,
		.noreturn = false
	},
	[141] = {
		.no = 141,
		.name = "getpeername",
		.nargs = 3,
		.argt = argt_141,
		.argsz = argsz_141,
		.noreturn = false
	},
	[142] = {
		.no = 142,
		.name = "gethostid",
		.nargs = 0,
		.argt = argt_142,
		.argsz = argsz_142,
		.noreturn = false
	},
	[143] = {
		.no = 143,
		.name = "sethostid",
		.nargs = 1,
		.argt = argt_143,
		.argsz = argsz_143,
		.noreturn = false
	},
	[144] = {
		.no = 144,
		.name = "getrlimit",
		.nargs = 2,
		.argt = argt_144,
		.argsz = argsz_144,
		.noreturn = false
	},
	[145] = {
		.no = 145,
		.name = "setrlimit",
		.nargs = 2,
		.argt = argt_145,
		.argsz = argsz_145,
		.noreturn = false
	},
	[146] = {
		.no = 146,
		.name = "killpg",
		.nargs = 2,
		.argt = argt_146,
		.argsz = argsz_146,
		.noreturn = false
	},
	[147] = {
		.no = 147,
		.name = "setsid",
		.nargs = 0,
		.argt = argt_147,
		.argsz = argsz_147,
		.noreturn = false
	},
	[148] = {
		.no = 148,
		.name = "quotactl",
		.nargs = 4,
		.argt = argt_148,
		.argsz = argsz_148,
		.noreturn = false
	},
	[149] = {
		.no = 149,
		.name = "quota",
		.nargs = 0,
		.argt = argt_149,
		.argsz = argsz_149,
		.noreturn = false
	},
	[150] = {
		.no = 150,
		.name = "getsockname",
		.nargs = 3,
		.argt = argt_150,
		.argsz = argsz_150,
		.noreturn = false
	},
	[154] = {
		.no = 154,
		.name = "nlm_syscall",
		.nargs = 4,
		.argt = argt_154,
		.argsz = argsz_154,
		.noreturn = false
	},
	[155] = {
		.no = 155,
		.name = "nfssvc",
		.nargs = 2,
		.argt = argt_155,
		.argsz = argsz_155,
		.noreturn = false
	},
	[156] = {
		.no = 156,
		.name = "getdirentries",
		.nargs = 4,
		.argt = argt_156,
		.argsz = argsz_156,
		.noreturn = false
	},
	[157] = {
		.no = 157,
		.name = "statfs",
		.nargs = 2,
		.argt = argt_157,
		.argsz = argsz_157,
		.noreturn = false
	},
	[158] = {
		.no = 158,
		.name = "fstatfs",
		.nargs = 2,
		.argt = argt_158,
		.argsz = argsz_158,
		.noreturn = false
	},
	[160] = {
		.no = 160,
		.name = "lgetfh",
		.nargs = 2,
		.argt = argt_160,
		.argsz = argsz_160,
		.noreturn = false
	},
	[161] = {
		.no = 161,
		.name = "getfh",
		.nargs = 2,
		.argt = argt_161,
		.argsz = argsz_161,
		.noreturn = false
	},
	[162] = {
		.no = 162,
		.name = "getdomainname",
		.nargs = 2,
		.argt = argt_162,
		.argsz = argsz_162,
		.noreturn = false
	},
	[163] = {
		.no = 163,
		.name = "setdomainname",
		.nargs = 2,
		.argt = argt_163,
		.argsz = argsz_163,
		.noreturn = false
	},
	[164] = {
		.no = 164,
		.name = "uname",
		.nargs = 1,
		.argt = argt_164,
		.argsz = argsz_164,
		.noreturn = false
	},
	[165] = {
		.no = 165,
		.name = "sysarch",
		.nargs = 2,
		.argt = argt_165,
		.argsz = argsz_165,
		.noreturn = false
	},
	[166] = {
		.no = 166,
		.name = "rtprio",
		.nargs = 3,
		.argt = argt_166,
		.argsz = argsz_166,
		.noreturn = false
	},
	[169] = {
		.no = 169,
		.name = "semsys",
		.nargs = 5,
		.argt = argt_169,
		.argsz = argsz_169,
		.noreturn = false
	},
	[175] = {
		.no = 175,
		.name = "setfib",
		.nargs = 1,
		.argt = argt_175,
		.argsz = argsz_175,
		.noreturn = false
	},
	[176] = {
		.no = 176,
		.name = "ntp_adjtime",
		.nargs = 1,
		.argt = argt_176,
		.argsz = argsz_176,
		.noreturn = false
	},
	[181] = {
		.no = 181,
		.name = "setgid",
		.nargs = 1,
		.argt = argt_181,
		.argsz = argsz_181,
		.noreturn = false
	},
	[182] = {
		.no = 182,
		.name = "setegid",
		.nargs = 1,
		.argt = argt_182,
		.argsz = argsz_182,
		.noreturn = false
	},
	[183] = {
		.no = 183,
		.name = "seteuid",
		.nargs = 1,
		.argt = argt_183,
		.argsz = argsz_183,
		.noreturn = false
	},
	[188] = {
		.no = 188,
		.name = "stat",
		.nargs = 2,
		.argt = argt_188,
		.argsz = argsz_188,
		.noreturn = false
	},
	[189] = {
		.no = 189,
		.name = "fstat",
		.nargs = 2,
		.argt = argt_189,
		.argsz = argsz_189,
		.noreturn = false
	},
	[190] = {
		.no = 190,
		.name = "lstat",
		.nargs = 2,
		.argt = argt_190,
		.argsz = argsz_190,
		.noreturn = false
	},
	[191] = {
		.no = 191,
		.name = "pathconf",
		.nargs = 2,
		.argt = argt_191,
		.argsz = argsz_191,
		.noreturn = false
	},
	[192] = {
		.no = 192,
		.name = "fpathconf",
		.nargs = 2,
		.argt = argt_192,
		.argsz = argsz_192,
		.noreturn = false
	},
	[194] = {
		.no = 194,
		.name = "getrlimit",
		.nargs = 2,
		.argt = argt_194,
		.argsz = argsz_194,
		.noreturn = false
	},
	[195] = {
		.no = 195,
		.name = "setrlimit",
		.nargs = 2,
		.argt = argt_195,
		.argsz = argsz_195,
		.noreturn = false
	},
	[196] = {
		.no = 196,
		.name = "getdirentries",
		.nargs = 4,
		.argt = argt_196,
		.argsz = argsz_196,
		.noreturn = false
	},
	[198] = {
		.no = 198,
		.name = "nosys",
		.nargs = 0,
		.argt = argt_198,
		.argsz = argsz_198,
		.noreturn = false
	},
	[202] = {
		.no = 202,
		.name = "__sysctl",
		.nargs = 6,
		.argt = argt_202,
		.argsz = argsz_202,
		.noreturn = false
	},
	[203] = {
		.no = 203,
		.name = "mlock",
		.nargs = 2,
		.argt = argt_203,
		.argsz = argsz_203,
		.noreturn = false
	},
	[204] = {
		.no = 204,
		.name = "munlock",
		.nargs = 2,
		.argt = argt_204,
		.argsz = argsz_204,
		.noreturn = false
	},
	[205] = {
		.no = 205,
		.name = "undelete",
		.nargs = 1,
		.argt = argt_205,
		.argsz = argsz_205,
		.noreturn = false
	},
	[206] = {
		.no = 206,
		.name = "futimes",
		.nargs = 2,
		.argt = argt_206,
		.argsz = argsz_206,
		.noreturn = false
	},
	[207] = {
		.no = 207,
		.name = "getpgid",
		.nargs = 1,
		.argt = argt_207,
		.argsz = argsz_207,
		.noreturn = false
	},
	[209] = {
		.no = 209,
		.name = "poll",
		.nargs = 3,
		.argt = argt_209,
		.argsz = argsz_209,
		.noreturn = false
	},
	[220] = {
		.no = 220,
		.name = "__semctl",
		.nargs = 4,
		.argt = argt_220,
		.argsz = argsz_220,
		.noreturn = false
	},
	[221] = {
		.no = 221,
		.name = "semget",
		.nargs = 3,
		.argt = argt_221,
		.argsz = argsz_221,
		.noreturn = false
	},
	[222] = {
		.no = 222,
		.name = "semop",
		.nargs = 3,
		.argt = argt_222,
		.argsz = argsz_222,
		.noreturn = false
	},
	[224] = {
		.no = 224,
		.name = "msgctl",
		.nargs = 3,
		.argt = argt_224,
		.argsz = argsz_224,
		.noreturn = false
	},
	[225] = {
		.no = 225,
		.name = "msgget",
		.nargs = 2,
		.argt = argt_225,
		.argsz = argsz_225,
		.noreturn = false
	},
	[226] = {
		.no = 226,
		.name = "msgsnd",
		.nargs = 4,
		.argt = argt_226,
		.argsz = argsz_226,
		.noreturn = false
	},
	[227] = {
		.no = 227,
		.name = "msgrcv",
		.nargs = 5,
		.argt = argt_227,
		.argsz = argsz_227,
		.noreturn = false
	},
	[229] = {
		.no = 229,
		.name = "shmctl",
		.nargs = 3,
		.argt = argt_229,
		.argsz = argsz_229,
		.noreturn = false
	},
	[230] = {
		.no = 230,
		.name = "shmdt",
		.nargs = 1,
		.argt = argt_230,
		.argsz = argsz_230,
		.noreturn = false
	},
	[231] = {
		.no = 231,
		.name = "shmget",
		.nargs = 3,
		.argt = argt_231,
		.argsz = argsz_231,
		.noreturn = false
	},
	[232] = {
		.no = 232,
		.name = "clock_gettime",
		.nargs = 2,
		.argt = argt_232,
		.argsz = argsz_232,
		.noreturn = false
	},
	[233] = {
		.no = 233,
		.name = "clock_settime",
		.nargs = 2,
		.argt = argt_233,
		.argsz = argsz_233,
		.noreturn = false
	},
	[234] = {
		.no = 234,
		.name = "clock_getres",
		.nargs = 2,
		.argt = argt_234,
		.argsz = argsz_234,
		.noreturn = false
	},
	[235] = {
		.no = 235,
		.name = "ktimer_create",
		.nargs = 3,
		.argt = argt_235,
		.argsz = argsz_235,
		.noreturn = false
	},
	[236] = {
		.no = 236,
		.name = "ktimer_delete",
		.nargs = 1,
		.argt = argt_236,
		.argsz = argsz_236,
		.noreturn = false
	},
	[237] = {
		.no = 237,
		.name = "ktimer_settime",
		.nargs = 4,
		.argt = argt_237,
		.argsz = argsz_237,
		.noreturn = false
	},
	[238] = {
		.no = 238,
		.name = "ktimer_gettime",
		.nargs = 2,
		.argt = argt_238,
		.argsz = argsz_238,
		.noreturn = false
	},
	[239] = {
		.no = 239,
		.name = "ktimer_getoverrun",
		.nargs = 1,
		.argt = argt_239,
		.argsz = argsz_239,
		.noreturn = false
	},
	[240] = {
		.no = 240,
		.name = "nanosleep",
		.nargs = 2,
		.argt = argt_240,
		.argsz = argsz_240,
		.noreturn = false
	},
	[241] = {
		.no = 241,
		.name = "ffclock_getcounter",
		.nargs = 1,
		.argt = argt_241,
		.argsz = argsz_241,
		.noreturn = false
	},
	[242] = {
		.no = 242,
		.name = "ffclock_setestimate",
		.nargs = 1,
		.argt = argt_242,
		.argsz = argsz_242,
		.noreturn = false
	},
	[243] = {
		.no = 243,
		.name = "ffclock_getestimate",
		.nargs = 1,
		.argt = argt_243,
		.argsz = argsz_243,
		.noreturn = false
	},
	[244] = {
		.no = 244,
		.name = "clock_nanosleep",
		.nargs = 4,
		.argt = argt_244,
		.argsz = argsz_244,
		.noreturn = false
	},
	[247] = {
		.no = 247,
		.name = "clock_getcpuclockid2",
		.nargs = 3,
		.argt = argt_247,
		.argsz = argsz_247,
		.noreturn = false
	},
	[248] = {
		.no = 248,
		.name = "ntp_gettime",
		.nargs = 1,
		.argt = argt_248,
		.argsz = argsz_248,
		.noreturn = false
	},
	[250] = {
		.no = 250,
		.name = "minherit",
		.nargs = 3,
		.argt = argt_250,
		.argsz = argsz_250,
		.noreturn = false
	},
	[251] = {
		.no = 251,
		.name = "rfork",
		.nargs = 1,
		.argt = argt_251,
		.argsz = argsz_251,
		.noreturn = false
	},
	[253] = {
		.no = 253,
		.name = "issetugid",
		.nargs = 0,
		.argt = argt_253,
		.argsz = argsz_253,
		.noreturn = false
	},
	[254] = {
		.no = 254,
		.name = "lchown",
		.nargs = 3,
		.argt = argt_254,
		.argsz = argsz_254,
		.noreturn = false
	},
	[255] = {
		.no = 255,
		.name = "aio_read",
		.nargs = 1,
		.argt = argt_255,
		.argsz = argsz_255,
		.noreturn = false
	},
	[256] = {
		.no = 256,
		.name = "aio_write",
		.nargs = 1,
		.argt = argt_256,
		.argsz = argsz_256,
		.noreturn = false
	},
	[257] = {
		.no = 257,
		.name = "lio_listio",
		.nargs = 4,
		.argt = argt_257,
		.argsz = argsz_257,
		.noreturn = false
	},
	[272] = {
		.no = 272,
		.name = "getdents",
		.nargs = 3,
		.argt = argt_272,
		.argsz = argsz_272,
		.noreturn = false
	},
	[274] = {
		.no = 274,
		.name = "lchmod",
		.nargs = 2,
		.argt = argt_274,
		.argsz = argsz_274,
		.noreturn = false
	},
	[276] = {
		.no = 276,
		.name = "lutimes",
		.nargs = 2,
		.argt = argt_276,
		.argsz = argsz_276,
		.noreturn = false
	},
	[278] = {
		.no = 278,
		.name = "nstat",
		.nargs = 2,
		.argt = argt_278,
		.argsz = argsz_278,
		.noreturn = false
	},
	[279] = {
		.no = 279,
		.name = "nfstat",
		.nargs = 2,
		.argt = argt_279,
		.argsz = argsz_279,
		.noreturn = false
	},
	[280] = {
		.no = 280,
		.name = "nlstat",
		.nargs = 2,
		.argt = argt_280,
		.argsz = argsz_280,
		.noreturn = false
	},
	[289] = {
		.no = 289,
		.name = "preadv",
		.nargs = 4,
		.argt = argt_289,
		.argsz = argsz_289,
		.noreturn = false
	},
	[290] = {
		.no = 290,
		.name = "pwritev",
		.nargs = 4,
		.argt = argt_290,
		.argsz = argsz_290,
		.noreturn = false
	},
	[297] = {
		.no = 297,
		.name = "fhstatfs",
		.nargs = 2,
		.argt = argt_297,
		.argsz = argsz_297,
		.noreturn = false
	},
	[298] = {
		.no = 298,
		.name = "fhopen",
		.nargs = 2,
		.argt = argt_298,
		.argsz = argsz_298,
		.noreturn = false
	},
	[299] = {
		.no = 299,
		.name = "fhstat",
		.nargs = 2,
		.argt = argt_299,
		.argsz = argsz_299,
		.noreturn = false
	},
	[300] = {
		.no = 300,
		.name = "modnext",
		.nargs = 1,
		.argt = argt_300,
		.argsz = argsz_300,
		.noreturn = false
	},
	[301] = {
		.no = 301,
		.name = "modstat",
		.nargs = 2,
		.argt = argt_301,
		.argsz = argsz_301,
		.noreturn = false
	},
	[302] = {
		.no = 302,
		.name = "modfnext",
		.nargs = 1,
		.argt = argt_302,
		.argsz = argsz_302,
		.noreturn = false
	},
	[303] = {
		.no = 303,
		.name = "modfind",
		.nargs = 1,
		.argt = argt_303,
		.argsz = argsz_303,
		.noreturn = false
	},
	[304] = {
		.no = 304,
		.name = "kldload",
		.nargs = 1,
		.argt = argt_304,
		.argsz = argsz_304,
		.noreturn = false
	},
	[305] = {
		.no = 305,
		.name = "kldunload",
		.nargs = 1,
		.argt = argt_305,
		.argsz = argsz_305,
		.noreturn = false
	},
	[306] = {
		.no = 306,
		.name = "kldfind",
		.nargs = 1,
		.argt = argt_306,
		.argsz = argsz_306,
		.noreturn = false
	},
	[307] = {
		.no = 307,
		.name = "kldnext",
		.nargs = 1,
		.argt = argt_307,
		.argsz = argsz_307,
		.noreturn = false
	},
	[308] = {
		.no = 308,
		.name = "kldstat",
		.nargs = 2,
		.argt = argt_308,
		.argsz = argsz_308,
		.noreturn = false
	},
	[309] = {
		.no = 309,
		.name = "kldfirstmod",
		.nargs = 1,
		.argt = argt_309,
		.argsz = argsz_309,
		.noreturn = false
	},
	[310] = {
		.no = 310,
		.name = "getsid",
		.nargs = 1,
		.argt = argt_310,
		.argsz = argsz_310,
		.noreturn = false
	},
	[311] = {
		.no = 311,
		.name = "setresuid",
		.nargs = 3,
		.argt = argt_311,
		.argsz = argsz_311,
		.noreturn = false
	},
	[312] = {
		.no = 312,
		.name = "setresgid",
		.nargs = 3,
		.argt = argt_312,
		.argsz = argsz_312,
		.noreturn = false
	},
	[314] = {
		.no = 314,
		.name = "aio_return",
		.nargs = 1,
		.argt = argt_314,
		.argsz = argsz_314,
		.noreturn = false
	},
	[315] = {
		.no = 315,
		.name = "aio_suspend",
		.nargs = 3,
		.argt = argt_315,
		.argsz = argsz_315,
		.noreturn = false
	},
	[316] = {
		.no = 316,
		.name = "aio_cancel",
		.nargs = 2,
		.argt = argt_316,
		.argsz = argsz_316,
		.noreturn = false
	},
	[317] = {
		.no = 317,
		.name = "aio_error",
		.nargs = 1,
		.argt = argt_317,
		.argsz = argsz_317,
		.noreturn = false
	},
	[318] = {
		.no = 318,
		.name = "aio_read",
		.nargs = 1,
		.argt = argt_318,
		.argsz = argsz_318,
		.noreturn = false
	},
	[319] = {
		.no = 319,
		.name = "aio_write",
		.nargs = 1,
		.argt = argt_319,
		.argsz = argsz_319,
		.noreturn = false
	},
	[320] = {
		.no = 320,
		.name = "lio_listio",
		.nargs = 4,
		.argt = argt_320,
		.argsz = argsz_320,
		.noreturn = false
	},
	[321] = {
		.no = 321,
		.name = "yield",
		.nargs = 0,
		.argt = argt_321,
		.argsz = argsz_321,
		.noreturn = false
	},
	[324] = {
		.no = 324,
		.name = "mlockall",
		.nargs = 1,
		.argt = argt_324,
		.argsz = argsz_324,
		.noreturn = false
	},
	[325] = {
		.no = 325,
		.name = "__getcwd",
		.nargs = 2,
		.argt = argt_325,
		.argsz = argsz_325,
		.noreturn = false
	},
	[327] = {
		.no = 327,
		.name = "sched_setparam",
		.nargs = 2,
		.argt = argt_327,
		.argsz = argsz_327,
		.noreturn = false
	},
	[328] = {
		.no = 328,
		.name = "sched_getparam",
		.nargs = 2,
		.argt = argt_328,
		.argsz = argsz_328,
		.noreturn = false
	},
	[329] = {
		.no = 329,
		.name = "sched_setscheduler",
		.nargs = 3,
		.argt = argt_329,
		.argsz = argsz_329,
		.noreturn = false
	},
	[330] = {
		.no = 330,
		.name = "sched_getscheduler",
		.nargs = 1,
		.argt = argt_330,
		.argsz = argsz_330,
		.noreturn = false
	},
	[331] = {
		.no = 331,
		.name = "sched_yield",
		.nargs = 0,
		.argt = argt_331,
		.argsz = argsz_331,
		.noreturn = false
	},
	[332] = {
		.no = 332,
		.name = "sched_get_priority_max",
		.nargs = 1,
		.argt = argt_332,
		.argsz = argsz_332,
		.noreturn = false
	},
	[333] = {
		.no = 333,
		.name = "sched_get_priority_min",
		.nargs = 1,
		.argt = argt_333,
		.argsz = argsz_333,
		.noreturn = false
	},
	[334] = {
		.no = 334,
		.name = "sched_rr_get_interval",
		.nargs = 2,
		.argt = argt_334,
		.argsz = argsz_334,
		.noreturn = false
	},
	[335] = {
		.no = 335,
		.name = "utrace",
		.nargs = 2,
		.argt = argt_335,
		.argsz = argsz_335,
		.noreturn = false
	},
	[336] = {
		.no = 336,
		.name = "sendfile",
		.nargs = 7,
		.argt = argt_336,
		.argsz = argsz_336,
		.noreturn = false
	},
	[337] = {
		.no = 337,
		.name = "kldsym",
		.nargs = 3,
		.argt = argt_337,
		.argsz = argsz_337,
		.noreturn = false
	},
	[338] = {
		.no = 338,
		.name = "jail",
		.nargs = 1,
		.argt = argt_338,
		.argsz = argsz_338,
		.noreturn = false
	},
	[339] = {
		.no = 339,
		.name = "nnpfs_syscall",
		.nargs = 5,
		.argt = argt_339,
		.argsz = argsz_339,
		.noreturn = false
	},
	[340] = {
		.no = 340,
		.name = "sigprocmask",
		.nargs = 3,
		.argt = argt_340,
		.argsz = argsz_340,
		.noreturn = false
	},
	[341] = {
		.no = 341,
		.name = "sigsuspend",
		.nargs = 1,
		.argt = argt_341,
		.argsz = argsz_341,
		.noreturn = false
	},
	[342] = {
		.no = 342,
		.name = "sigaction",
		.nargs = 3,
		.argt = argt_342,
		.argsz = argsz_342,
		.noreturn = false
	},
	[343] = {
		.no = 343,
		.name = "sigpending",
		.nargs = 1,
		.argt = argt_343,
		.argsz = argsz_343,
		.noreturn = false
	},
	[344] = {
		.no = 344,
		.name = "sigreturn",
		.nargs = 1,
		.argt = argt_344,
		.argsz = argsz_344,
		.noreturn = false
	},
	[345] = {
		.no = 345,
		.name = "sigtimedwait",
		.nargs = 3,
		.argt = argt_345,
		.argsz = argsz_345,
		.noreturn = false
	},
	[346] = {
		.no = 346,
		.name = "sigwaitinfo",
		.nargs = 2,
		.argt = argt_346,
		.argsz = argsz_346,
		.noreturn = false
	},
	[347] = {
		.no = 347,
		.name = "__acl_get_file",
		.nargs = 3,
		.argt = argt_347,
		.argsz = argsz_347,
		.noreturn = false
	},
	[348] = {
		.no = 348,
		.name = "__acl_set_file",
		.nargs = 3,
		.argt = argt_348,
		.argsz = argsz_348,
		.noreturn = false
	},
	[349] = {
		.no = 349,
		.name = "__acl_get_fd",
		.nargs = 3,
		.argt = argt_349,
		.argsz = argsz_349,
		.noreturn = false
	},
	[350] = {
		.no = 350,
		.name = "__acl_set_fd",
		.nargs = 3,
		.argt = argt_350,
		.argsz = argsz_350,
		.noreturn = false
	},
	[351] = {
		.no = 351,
		.name = "__acl_delete_file",
		.nargs = 2,
		.argt = argt_351,
		.argsz = argsz_351,
		.noreturn = false
	},
	[352] = {
		.no = 352,
		.name = "__acl_delete_fd",
		.nargs = 2,
		.argt = argt_352,
		.argsz = argsz_352,
		.noreturn = false
	},
	[353] = {
		.no = 353,
		.name = "__acl_aclcheck_file",
		.nargs = 3,
		.argt = argt_353,
		.argsz = argsz_353,
		.noreturn = false
	},
	[354] = {
		.no = 354,
		.name = "__acl_aclcheck_fd",
		.nargs = 3,
		.argt = argt_354,
		.argsz = argsz_354,
		.noreturn = false
	},
	[355] = {
		.no = 355,
		.name = "extattrctl",
		.nargs = 5,
		.argt = argt_355,
		.argsz = argsz_355,
		.noreturn = false
	},
	[356] = {
		.no = 356,
		.name = "extattr_set_file",
		.nargs = 5,
		.argt = argt_356,
		.argsz = argsz_356,
		.noreturn = false
	},
	[357] = {
		.no = 357,
		.name = "extattr_get_file",
		.nargs = 5,
		.argt = argt_357,
		.argsz = argsz_357,
		.noreturn = false
	},
	[358] = {
		.no = 358,
		.name = "extattr_delete_file",
		.nargs = 3,
		.argt = argt_358,
		.argsz = argsz_358,
		.noreturn = false
	},
	[359] = {
		.no = 359,
		.name = "aio_waitcomplete",
		.nargs = 2,
		.argt = argt_359,
		.argsz = argsz_359,
		.noreturn = false
	},
	[360] = {
		.no = 360,
		.name = "getresuid",
		.nargs = 3,
		.argt = argt_360,
		.argsz = argsz_360,
		.noreturn = false
	},
	[361] = {
		.no = 361,
		.name = "getresgid",
		.nargs = 3,
		.argt = argt_361,
		.argsz = argsz_361,
		.noreturn = false
	},
	[362] = {
		.no = 362,
		.name = "kqueue",
		.nargs = 0,
		.argt = argt_362,
		.argsz = argsz_362,
		.noreturn = false
	},
	[363] = {
		.no = 363,
		.name = "kevent",
		.nargs = 6,
		.argt = argt_363,
		.argsz = argsz_363,
		.noreturn = false
	},
	[371] = {
		.no = 371,
		.name = "extattr_set_fd",
		.nargs = 5,
		.argt = argt_371,
		.argsz = argsz_371,
		.noreturn = false
	},
	[372] = {
		.no = 372,
		.name = "extattr_get_fd",
		.nargs = 5,
		.argt = argt_372,
		.argsz = argsz_372,
		.noreturn = false
	},
	[373] = {
		.no = 373,
		.name = "extattr_delete_fd",
		.nargs = 3,
		.argt = argt_373,
		.argsz = argsz_373,
		.noreturn = false
	},
	[374] = {
		.no = 374,
		.name = "__setugid",
		.nargs = 1,
		.argt = argt_374,
		.argsz = argsz_374,
		.noreturn = false
	},
	[376] = {
		.no = 376,
		.name = "eaccess",
		.nargs = 2,
		.argt = argt_376,
		.argsz = argsz_376,
		.noreturn = false
	},
	[377] = {
		.no = 377,
		.name = "afs3_syscall",
		.nargs = 7,
		.argt = argt_377,
		.argsz = argsz_377,
		.noreturn = false
	},
	[378] = {
		.no = 378,
		.name = "nmount",
		.nargs = 3,
		.argt = argt_378,
		.argsz = argsz_378,
		.noreturn = false
	},
	[384] = {
		.no = 384,
		.name = "__mac_get_proc",
		.nargs = 1,
		.argt = argt_384,
		.argsz = argsz_384,
		.noreturn = false
	},
	[385] = {
		.no = 385,
		.name = "__mac_set_proc",
		.nargs = 1,
		.argt = argt_385,
		.argsz = argsz_385,
		.noreturn = false
	},
	[386] = {
		.no = 386,
		.name = "__mac_get_fd",
		.nargs = 2,
		.argt = argt_386,
		.argsz = argsz_386,
		.noreturn = false
	},
	[387] = {
		.no = 387,
		.name = "__mac_get_file",
		.nargs = 2,
		.argt = argt_387,
		.argsz = argsz_387,
		.noreturn = false
	},
	[388] = {
		.no = 388,
		.name = "__mac_set_fd",
		.nargs = 2,
		.argt = argt_388,
		.argsz = argsz_388,
		.noreturn = false
	},
	[389] = {
		.no = 389,
		.name = "__mac_set_file",
		.nargs = 2,
		.argt = argt_389,
		.argsz = argsz_389,
		.noreturn = false
	},
	[390] = {
		.no = 390,
		.name = "kenv",
		.nargs = 4,
		.argt = argt_390,
		.argsz = argsz_390,
		.noreturn = false
	},
	[391] = {
		.no = 391,
		.name = "lchflags",
		.nargs = 2,
		.argt = argt_391,
		.argsz = argsz_391,
		.noreturn = false
	},
	[392] = {
		.no = 392,
		.name = "uuidgen",
		.nargs = 2,
		.argt = argt_392,
		.argsz = argsz_392,
		.noreturn = false
	},
	[393] = {
		.no = 393,
		.name = "sendfile",
		.nargs = 7,
		.argt = argt_393,
		.argsz = argsz_393,
		.noreturn = false
	},
	[394] = {
		.no = 394,
		.name = "mac_syscall",
		.nargs = 3,
		.argt = argt_394,
		.argsz = argsz_394,
		.noreturn = false
	},
	[395] = {
		.no = 395,
		.name = "getfsstat",
		.nargs = 3,
		.argt = argt_395,
		.argsz = argsz_395,
		.noreturn = false
	},
	[396] = {
		.no = 396,
		.name = "statfs",
		.nargs = 2,
		.argt = argt_396,
		.argsz = argsz_396,
		.noreturn = false
	},
	[397] = {
		.no = 397,
		.name = "fstatfs",
		.nargs = 2,
		.argt = argt_397,
		.argsz = argsz_397,
		.noreturn = false
	},
	[398] = {
		.no = 398,
		.name = "fhstatfs",
		.nargs = 2,
		.argt = argt_398,
		.argsz = argsz_398,
		.noreturn = false
	},
	[400] = {
		.no = 400,
		.name = "ksem_close",
		.nargs = 1,
		.argt = argt_400,
		.argsz = argsz_400,
		.noreturn = false
	},
	[401] = {
		.no = 401,
		.name = "ksem_post",
		.nargs = 1,
		.argt = argt_401,
		.argsz = argsz_401,
		.noreturn = false
	},
	[402] = {
		.no = 402,
		.name = "ksem_wait",
		.nargs = 1,
		.argt = argt_402,
		.argsz = argsz_402,
		.noreturn = false
	},
	[403] = {
		.no = 403,
		.name = "ksem_trywait",
		.nargs = 1,
		.argt = argt_403,
		.argsz = argsz_403,
		.noreturn = false
	},
	[404] = {
		.no = 404,
		.name = "ksem_init",
		.nargs = 2,
		.argt = argt_404,
		.argsz = argsz_404,
		.noreturn = false
	},
	[405] = {
		.no = 405,
		.name = "ksem_open",
		.nargs = 5,
		.argt = argt_405,
		.argsz = argsz_405,
		.noreturn = false
	},
	[406] = {
		.no = 406,
		.name = "ksem_unlink",
		.nargs = 1,
		.argt = argt_406,
		.argsz = argsz_406,
		.noreturn = false
	},
	[407] = {
		.no = 407,
		.name = "ksem_getvalue",
		.nargs = 2,
		.argt = argt_407,
		.argsz = argsz_407,
		.noreturn = false
	},
	[408] = {
		.no = 408,
		.name = "ksem_destroy",
		.nargs = 1,
		.argt = argt_408,
		.argsz = argsz_408,
		.noreturn = false
	},
	[409] = {
		.no = 409,
		.name = "__mac_get_pid",
		.nargs = 2,
		.argt = argt_409,
		.argsz = argsz_409,
		.noreturn = false
	},
	[410] = {
		.no = 410,
		.name = "__mac_get_link",
		.nargs = 2,
		.argt = argt_410,
		.argsz = argsz_410,
		.noreturn = false
	},
	[411] = {
		.no = 411,
		.name = "__mac_set_link",
		.nargs = 2,
		.argt = argt_411,
		.argsz = argsz_411,
		.noreturn = false
	},
	[412] = {
		.no = 412,
		.name = "extattr_set_link",
		.nargs = 5,
		.argt = argt_412,
		.argsz = argsz_412,
		.noreturn = false
	},
	[413] = {
		.no = 413,
		.name = "extattr_get_link",
		.nargs = 5,
		.argt = argt_413,
		.argsz = argsz_413,
		.noreturn = false
	},
	[414] = {
		.no = 414,
		.name = "extattr_delete_link",
		.nargs = 3,
		.argt = argt_414,
		.argsz = argsz_414,
		.noreturn = false
	},
	[415] = {
		.no = 415,
		.name = "__mac_execve",
		.nargs = 4,
		.argt = argt_415,
		.argsz = argsz_415,
		.noreturn = true
	},
	[416] = {
		.no = 416,
		.name = "sigaction",
		.nargs = 3,
		.argt = argt_416,
		.argsz = argsz_416,
		.noreturn = false
	},
	[417] = {
		.no = 417,
		.name = "sigreturn",
		.nargs = 1,
		.argt = argt_417,
		.argsz = argsz_417,
		.noreturn = false
	},
	[421] = {
		.no = 421,
		.name = "getcontext",
		.nargs = 1,
		.argt = argt_421,
		.argsz = argsz_421,
		.noreturn = false
	},
	[422] = {
		.no = 422,
		.name = "setcontext",
		.nargs = 1,
		.argt = argt_422,
		.argsz = argsz_422,
		.noreturn = false
	},
	[423] = {
		.no = 423,
		.name = "swapcontext",
		.nargs = 2,
		.argt = argt_423,
		.argsz = argsz_423,
		.noreturn = false
	},
	[424] = {
		.no = 424,
		.name = "swapoff",
		.nargs = 1,
		.argt = argt_424,
		.argsz = argsz_424,
		.noreturn = false
	},
	[425] = {
		.no = 425,
		.name = "__acl_get_link",
		.nargs = 3,
		.argt = argt_425,
		.argsz = argsz_425,
		.noreturn = false
	},
	[426] = {
		.no = 426,
		.name = "__acl_set_link",
		.nargs = 3,
		.argt = argt_426,
		.argsz = argsz_426,
		.noreturn = false
	},
	[427] = {
		.no = 427,
		.name = "__acl_delete_link",
		.nargs = 2,
		.argt = argt_427,
		.argsz = argsz_427,
		.noreturn = false
	},
	[428] = {
		.no = 428,
		.name = "__acl_aclcheck_link",
		.nargs = 3,
		.argt = argt_428,
		.argsz = argsz_428,
		.noreturn = false
	},
	[429] = {
		.no = 429,
		.name = "sigwait",
		.nargs = 2,
		.argt = argt_429,
		.argsz = argsz_429,
		.noreturn = false
	},
	[430] = {
		.no = 430,
		.name = "thr_create",
		.nargs = 3,
		.argt = argt_430,
		.argsz = argsz_430,
		.noreturn = false
	},
	[431] = {
		.no = 431,
		.name = "thr_exit",
		.nargs = 1,
		.argt = argt_431,
		.argsz = argsz_431,
		.noreturn = true
	},
	[432] = {
		.no = 432,
		.name = "thr_self",
		.nargs = 1,
		.argt = argt_432,
		.argsz = argsz_432,
		.noreturn = false
	},
	[433] = {
		.no = 433,
		.name = "thr_kill",
		.nargs = 2,
		.argt = argt_433,
		.argsz = argsz_433,
		.noreturn = false
	},
	[436] = {
		.no = 436,
		.name = "jail_attach",
		.nargs = 1,
		.argt = argt_436,
		.argsz = argsz_436,
		.noreturn = false
	},
	[437] = {
		.no = 437,
		.name = "extattr_list_fd",
		.nargs = 4,
		.argt = argt_437,
		.argsz = argsz_437,
		.noreturn = false
	},
	[438] = {
		.no = 438,
		.name = "extattr_list_file",
		.nargs = 4,
		.argt = argt_438,
		.argsz = argsz_438,
		.noreturn = false
	},
	[439] = {
		.no = 439,
		.name = "extattr_list_link",
		.nargs = 4,
		.argt = argt_439,
		.argsz = argsz_439,
		.noreturn = false
	},
	[441] = {
		.no = 441,
		.name = "ksem_timedwait",
		.nargs = 2,
		.argt = argt_441,
		.argsz = argsz_441,
		.noreturn = false
	},
	[442] = {
		.no = 442,
		.name = "thr_suspend",
		.nargs = 1,
		.argt = argt_442,
		.argsz = argsz_442,
		.noreturn = false
	},
	[443] = {
		.no = 443,
		.name = "thr_wake",
		.nargs = 1,
		.argt = argt_443,
		.argsz = argsz_443,
		.noreturn = false
	},
	[444] = {
		.no = 444,
		.name = "kldunloadf",
		.nargs = 2,
		.argt = argt_444,
		.argsz = argsz_444,
		.noreturn = false
	},
	[445] = {
		.no = 445,
		.name = "audit",
		.nargs = 2,
		.argt = argt_445,
		.argsz = argsz_445,
		.noreturn = false
	},
	[446] = {
		.no = 446,
		.name = "auditon",
		.nargs = 3,
		.argt = argt_446,
		.argsz = argsz_446,
		.noreturn = false
	},
	[447] = {
		.no = 447,
		.name = "getauid",
		.nargs = 1,
		.argt = argt_447,
		.argsz = argsz_447,
		.noreturn = false
	},
	[448] = {
		.no = 448,
		.name = "setauid",
		.nargs = 1,
		.argt = argt_448,
		.argsz = argsz_448,
		.noreturn = false
	},
	[449] = {
		.no = 449,
		.name = "getaudit",
		.nargs = 1,
		.argt = argt_449,
		.argsz = argsz_449,
		.noreturn = false
	},
	[450] = {
		.no = 450,
		.name = "setaudit",
		.nargs = 1,
		.argt = argt_450,
		.argsz = argsz_450,
		.noreturn = false
	},
	[451] = {
		.no = 451,
		.name = "getaudit_addr",
		.nargs = 2,
		.argt = argt_451,
		.argsz = argsz_451,
		.noreturn = false
	},
	[452] = {
		.no = 452,
		.name = "setaudit_addr",
		.nargs = 2,
		.argt = argt_452,
		.argsz = argsz_452,
		.noreturn = false
	},
	[453] = {
		.no = 453,
		.name = "auditctl",
		.nargs = 1,
		.argt = argt_453,
		.argsz = argsz_453,
		.noreturn = false
	},
	[454] = {
		.no = 454,
		.name = "_umtx_op",
		.nargs = 5,
		.argt = argt_454,
		.argsz = argsz_454,
		.noreturn = false
	},
	[455] = {
		.no = 455,
		.name = "thr_new",
		.nargs = 2,
		.argt = argt_455,
		.argsz = argsz_455,
		.noreturn = false
	},
	[456] = {
		.no = 456,
		.name = "sigqueue",
		.nargs = 3,
		.argt = argt_456,
		.argsz = argsz_456,
		.noreturn = false
	},
	[457] = {
		.no = 457,
		.name = "kmq_open",
		.nargs = 4,
		.argt = argt_457,
		.argsz = argsz_457,
		.noreturn = false
	},
	[458] = {
		.no = 458,
		.name = "kmq_setattr",
		.nargs = 3,
		.argt = argt_458,
		.argsz = argsz_458,
		.noreturn = false
	},
	[459] = {
		.no = 459,
		.name = "kmq_timedreceive",
		.nargs = 5,
		.argt = argt_459,
		.argsz = argsz_459,
		.noreturn = false
	},
	[460] = {
		.no = 460,
		.name = "kmq_timedsend",
		.nargs = 5,
		.argt = argt_460,
		.argsz = argsz_460,
		.noreturn = false
	},
	[461] = {
		.no = 461,
		.name = "kmq_notify",
		.nargs = 2,
		.argt = argt_461,
		.argsz = argsz_461,
		.noreturn = false
	},
	[462] = {
		.no = 462,
		.name = "kmq_unlink",
		.nargs = 1,
		.argt = argt_462,
		.argsz = argsz_462,
		.noreturn = false
	},
	[463] = {
		.no = 463,
		.name = "abort2",
		.nargs = 3,
		.argt = argt_463,
		.argsz = argsz_463,
		.noreturn = false
	},
	[464] = {
		.no = 464,
		.name = "thr_set_name",
		.nargs = 2,
		.argt = argt_464,
		.argsz = argsz_464,
		.noreturn = false
	},
	[465] = {
		.no = 465,
		.name = "aio_fsync",
		.nargs = 2,
		.argt = argt_465,
		.argsz = argsz_465,
		.noreturn = false
	},
	[466] = {
		.no = 466,
		.name = "rtprio_thread",
		.nargs = 3,
		.argt = argt_466,
		.argsz = argsz_466,
		.noreturn = false
	},
	[471] = {
		.no = 471,
		.name = "sctp_peeloff",
		.nargs = 2,
		.argt = argt_471,
		.argsz = argsz_471,
		.noreturn = false
	},
	[472] = {
		.no = 472,
		.name = "sctp_generic_sendmsg",
		.nargs = 7,
		.argt = argt_472,
		.argsz = argsz_472,
		.noreturn = false
	},
	[473] = {
		.no = 473,
		.name = "sctp_generic_sendmsg_iov",
		.nargs = 7,
		.argt = argt_473,
		.argsz = argsz_473,
		.noreturn = false
	},
	[474] = {
		.no = 474,
		.name = "sctp_generic_recvmsg",
		.nargs = 7,
		.argt = argt_474,
		.argsz = argsz_474,
		.noreturn = false
	},
	[475] = {
		.no = 475,
		.name = "pread",
		.nargs = 4,
		.argt = argt_475,
		.argsz = argsz_475,
		.noreturn = false
	},
	[476] = {
		.no = 476,
		.name = "pwrite",
		.nargs = 4,
		.argt = argt_476,
		.argsz = argsz_476,
		.noreturn = false
	},
	[478] = {
		.no = 478,
		.name = "lseek",
		.nargs = 3,
		.argt = argt_478,
		.argsz = argsz_478,
		.noreturn = false
	},
	[479] = {
		.no = 479,
		.name = "truncate",
		.nargs = 2,
		.argt = argt_479,
		.argsz = argsz_479,
		.noreturn = false
	},
	[480] = {
		.no = 480,
		.name = "ftruncate",
		.nargs = 2,
		.argt = argt_480,
		.argsz = argsz_480,
		.noreturn = false
	},
	[481] = {
		.no = 481,
		.name = "thr_kill2",
		.nargs = 3,
		.argt = argt_481,
		.argsz = argsz_481,
		.noreturn = false
	},
	[482] = {
		.no = 482,
		.name = "shm_open",
		.nargs = 3,
		.argt = argt_482,
		.argsz = argsz_482,
		.noreturn = false
	},
	[483] = {
		.no = 483,
		.name = "shm_unlink",
		.nargs = 1,
		.argt = argt_483,
		.argsz = argsz_483,
		.noreturn = false
	},
	[484] = {
		.no = 484,
		.name = "cpuset",
		.nargs = 1,
		.argt = argt_484,
		.argsz = argsz_484,
		.noreturn = false
	},
	[485] = {
		.no = 485,
		.name = "cpuset_setid",
		.nargs = 3,
		.argt = argt_485,
		.argsz = argsz_485,
		.noreturn = false
	},
	[486] = {
		.no = 486,
		.name = "cpuset_getid",
		.nargs = 4,
		.argt = argt_486,
		.argsz = argsz_486,
		.noreturn = false
	},
	[487] = {
		.no = 487,
		.name = "cpuset_getaffinity",
		.nargs = 5,
		.argt = argt_487,
		.argsz = argsz_487,
		.noreturn = false
	},
	[488] = {
		.no = 488,
		.name = "cpuset_setaffinity",
		.nargs = 5,
		.argt = argt_488,
		.argsz = argsz_488,
		.noreturn = false
	},
	[489] = {
		.no = 489,
		.name = "faccessat",
		.nargs = 4,
		.argt = argt_489,
		.argsz = argsz_489,
		.noreturn = false
	},
	[490] = {
		.no = 490,
		.name = "fchmodat",
		.nargs = 4,
		.argt = argt_490,
		.argsz = argsz_490,
		.noreturn = false
	},
	[491] = {
		.no = 491,
		.name = "fchownat",
		.nargs = 5,
		.argt = argt_491,
		.argsz = argsz_491,
		.noreturn = false
	},
	[492] = {
		.no = 492,
		.name = "fexecve",
		.nargs = 3,
		.argt = argt_492,
		.argsz = argsz_492,
		.noreturn = true
	},
	[493] = {
		.no = 493,
		.name = "fstatat",
		.nargs = 4,
		.argt = argt_493,
		.argsz = argsz_493,
		.noreturn = false
	},
	[494] = {
		.no = 494,
		.name = "futimesat",
		.nargs = 3,
		.argt = argt_494,
		.argsz = argsz_494,
		.noreturn = false
	},
	[495] = {
		.no = 495,
		.name = "linkat",
		.nargs = 5,
		.argt = argt_495,
		.argsz = argsz_495,
		.noreturn = false
	},
	[496] = {
		.no = 496,
		.name = "mkdirat",
		.nargs = 3,
		.argt = argt_496,
		.argsz = argsz_496,
		.noreturn = false
	},
	[497] = {
		.no = 497,
		.name = "mkfifoat",
		.nargs = 3,
		.argt = argt_497,
		.argsz = argsz_497,
		.noreturn = false
	},
	[498] = {
		.no = 498,
		.name = "mknodat",
		.nargs = 4,
		.argt = argt_498,
		.argsz = argsz_498,
		.noreturn = false
	},
	[499] = {
		.no = 499,
		.name = "openat",
		.nargs = 4,
		.argt = argt_499,
		.argsz = argsz_499,
		.noreturn = false
	},
	[500] = {
		.no = 500,
		.name = "readlinkat",
		.nargs = 4,
		.argt = argt_500,
		.argsz = argsz_500,
		.noreturn = false
	},
	[501] = {
		.no = 501,
		.name = "renameat",
		.nargs = 4,
		.argt = argt_501,
		.argsz = argsz_501,
		.noreturn = false
	},
	[502] = {
		.no = 502,
		.name = "symlinkat",
		.nargs = 3,
		.argt = argt_502,
		.argsz = argsz_502,
		.noreturn = false
	},
	[503] = {
		.no = 503,
		.name = "unlinkat",
		.nargs = 3,
		.argt = argt_503,
		.argsz = argsz_503,
		.noreturn = false
	},
	[504] = {
		.no = 504,
		.name = "posix_openpt",
		.nargs = 1,
		.argt = argt_504,
		.argsz = argsz_504,
		.noreturn = false
	},
	[505] = {
		.no = 505,
		.name = "gssd_syscall",
		.nargs = 1,
		.argt = argt_505,
		.argsz = argsz_505,
		.noreturn = false
	},
	[506] = {
		.no = 506,
		.name = "jail_get",
		.nargs = 3,
		.argt = argt_506,
		.argsz = argsz_506,
		.noreturn = false
	},
	[507] = {
		.no = 507,
		.name = "jail_set",
		.nargs = 3,
		.argt = argt_507,
		.argsz = argsz_507,
		.noreturn = false
	},
	[508] = {
		.no = 508,
		.name = "jail_remove",
		.nargs = 1,
		.argt = argt_508,
		.argsz = argsz_508,
		.noreturn = false
	},
	[509] = {
		.no = 509,
		.name = "closefrom",
		.nargs = 1,
		.argt = argt_509,
		.argsz = argsz_509,
		.noreturn = false
	},
	[510] = {
		.no = 510,
		.name = "__semctl",
		.nargs = 4,
		.argt = argt_510,
		.argsz = argsz_510,
		.noreturn = false
	},
	[511] = {
		.no = 511,
		.name = "msgctl",
		.nargs = 3,
		.argt = argt_511,
		.argsz = argsz_511,
		.noreturn = false
	},
	[512] = {
		.no = 512,
		.name = "shmctl",
		.nargs = 3,
		.argt = argt_512,
		.argsz = argsz_512,
		.noreturn = false
	},
	[513] = {
		.no = 513,
		.name = "lpathconf",
		.nargs = 2,
		.argt = argt_513,
		.argsz = argsz_513,
		.noreturn = false
	},
	[515] = {
		.no = 515,
		.name = "__cap_rights_get",
		.nargs = 3,
		.argt = argt_515,
		.argsz = argsz_515,
		.noreturn = false
	},
	[516] = {
		.no = 516,
		.name = "cap_enter",
		.nargs = 0,
		.argt = argt_516,
		.argsz = argsz_516,
		.noreturn = false
	},
	[517] = {
		.no = 517,
		.name = "cap_getmode",
		.nargs = 1,
		.argt = argt_517,
		.argsz = argsz_517,
		.noreturn = false
	},
	[518] = {
		.no = 518,
		.name = "pdfork",
		.nargs = 2,
		.argt = argt_518,
		.argsz = argsz_518,
		.noreturn = false
	},
	[519] = {
		.no = 519,
		.name = "pdkill",
		.nargs = 2,
		.argt = argt_519,
		.argsz = argsz_519,
		.noreturn = false
	},
	[520] = {
		.no = 520,
		.name = "pdgetpid",
		.nargs = 2,
		.argt = argt_520,
		.argsz = argsz_520,
		.noreturn = false
	},
	[522] = {
		.no = 522,
		.name = "pselect",
		.nargs = 6,
		.argt = argt_522,
		.argsz = argsz_522,
		.noreturn = false
	},
	[523] = {
		.no = 523,
		.name = "getloginclass",
		.nargs = 2,
		.argt = argt_523,
		.argsz = argsz_523,
		.noreturn = false
	},
	[524] = {
		.no = 524,
		.name = "setloginclass",
		.nargs = 1,
		.argt = argt_524,
		.argsz = argsz_524,
		.noreturn = false
	},
	[525] = {
		.no = 525,
		.name = "rctl_get_racct",
		.nargs = 4,
		.argt = argt_525,
		.argsz = argsz_525,
		.noreturn = false
	},
	[526] = {
		.no = 526,
		.name = "rctl_get_rules",
		.nargs = 4,
		.argt = argt_526,
		.argsz = argsz_526,
		.noreturn = false
	},
	[527] = {
		.no = 527,
		.name = "rctl_get_limits",
		.nargs = 4,
		.argt = argt_527,
		.argsz = argsz_527,
		.noreturn = false
	},
	[528] = {
		.no = 528,
		.name = "rctl_add_rule",
		.nargs = 4,
		.argt = argt_528,
		.argsz = argsz_528,
		.noreturn = false
	},
	[529] = {
		.no = 529,
		.name = "rctl_remove_rule",
		.nargs = 4,
		.argt = argt_529,
		.argsz = argsz_529,
		.noreturn = false
	},
	[530] = {
		.no = 530,
		.name = "posix_fallocate",
		.nargs = 3,
		.argt = argt_530,
		.argsz = argsz_530,
		.noreturn = false
	},
	[531] = {
		.no = 531,
		.name = "posix_fadvise",
		.nargs = 4,
		.argt = argt_531,
		.argsz = argsz_531,
		.noreturn = false
	},
	[532] = {
		.no = 532,
		.name = "wait6",
		.nargs = 6,
		.argt = argt_532,
		.argsz = argsz_532,
		.noreturn = false
	},
	[533] = {
		.no = 533,
		.name = "cap_rights_limit",
		.nargs = 2,
		.argt = argt_533,
		.argsz = argsz_533,
		.noreturn = false
	},
	[534] = {
		.no = 534,
		.name = "cap_ioctls_limit",
		.nargs = 3,
		.argt = argt_534,
		.argsz = argsz_534,
		.noreturn = false
	},
	[535] = {
		.no = 535,
		.name = "cap_ioctls_get",
		.nargs = 3,
		.argt = argt_535,
		.argsz = argsz_535,
		.noreturn = false
	},
	[536] = {
		.no = 536,
		.name = "cap_fcntls_limit",
		.nargs = 2,
		.argt = argt_536,
		.argsz = argsz_536,
		.noreturn = false
	},
	[537] = {
		.no = 537,
		.name = "cap_fcntls_get",
		.nargs = 2,
		.argt = argt_537,
		.argsz = argsz_537,
		.noreturn = false
	},
	[538] = {
		.no = 538,
		.name = "bindat",
		.nargs = 4,
		.argt = argt_538,
		.argsz = argsz_538,
		.noreturn = false
	},
	[539] = {
		.no = 539,
		.name = "connectat",
		.nargs = 4,
		.argt = argt_539,
		.argsz = argsz_539,
		.noreturn = false
	},
	[540] = {
		.no = 540,
		.name = "chflagsat",
		.nargs = 4,
		.argt = argt_540,
		.argsz = argsz_540,
		.noreturn = false
	},
	[541] = {
		.no = 541,
		.name = "accept4",
		.nargs = 4,
		.argt = argt_541,
		.argsz = argsz_541,
		.noreturn = false
	},
	[542] = {
		.no = 542,
		.name = "pipe2",
		.nargs = 2,
		.argt = argt_542,
		.argsz = argsz_542,
		.noreturn = false
	},
	[543] = {
		.no = 543,
		.name = "aio_mlock",
		.nargs = 1,
		.argt = argt_543,
		.argsz = argsz_543,
		.noreturn = false
	},
	[544] = {
		.no = 544,
		.name = "procctl",
		.nargs = 4,
		.argt = argt_544,
		.argsz = argsz_544,
		.noreturn = false
	},
	[545] = {
		.no = 545,
		.name = "ppoll",
		.nargs = 4,
		.argt = argt_545,
		.argsz = argsz_545,
		.noreturn = false
	},
	[546] = {
		.no = 546,
		.name = "futimens",
		.nargs = 2,
		.argt = argt_546,
		.argsz = argsz_546,
		.noreturn = false
	},
	[547] = {
		.no = 547,
		.name = "utimensat",
		.nargs = 4,
		.argt = argt_547,
		.argsz = argsz_547,
		.noreturn = false
	},
	[550] = {
		.no = 550,
		.name = "fdatasync",
		.nargs = 1,
		.argt = argt_550,
		.argsz = argsz_550,
		.noreturn = false
	},
	[551] = {
		.no = 551,
		.name = "fstat",
		.nargs = 2,
		.argt = argt_551,
		.argsz = argsz_551,
		.noreturn = false
	},
	[552] = {
		.no = 552,
		.name = "fstatat",
		.nargs = 4,
		.argt = argt_552,
		.argsz = argsz_552,
		.noreturn = false
	},
	[553] = {
		.no = 553,
		.name = "fhstat",
		.nargs = 2,
		.argt = argt_553,
		.argsz = argsz_553,
		.noreturn = false
	},
	[554] = {
		.no = 554,
		.name = "getdirentries",
		.nargs = 4,
		.argt = argt_554,
		.argsz = argsz_554,
		.noreturn = false
	},
	[555] = {
		.no = 555,
		.name = "statfs",
		.nargs = 2,
		.argt = argt_555,
		.argsz = argsz_555,
		.noreturn = false
	},
	[556] = {
		.no = 556,
		.name = "fstatfs",
		.nargs = 2,
		.argt = argt_556,
		.argsz = argsz_556,
		.noreturn = false
	},
	[557] = {
		.no = 557,
		.name = "getfsstat",
		.nargs = 3,
		.argt = argt_557,
		.argsz = argsz_557,
		.noreturn = false
	},
	[558] = {
		.no = 558,
		.name = "fhstatfs",
		.nargs = 2,
		.argt = argt_558,
		.argsz = argsz_558,
		.noreturn = false
	},
	[559] = {
		.no = 559,
		.name = "mknodat",
		.nargs = 4,
		.argt = argt_559,
		.argsz = argsz_559,
		.noreturn = false
	},
	[560] = {
		.no = 560,
		.name = "kevent",
		.nargs = 6,
		.argt = argt_560,
		.argsz = argsz_560,
		.noreturn = false
	},
	[561] = {
		.no = 561,
		.name = "cpuset_getdomain",
		.nargs = 6,
		.argt = argt_561,
		.argsz = argsz_561,
		.noreturn = false
	},
	[562] = {
		.no = 562,
		.name = "cpuset_setdomain",
		.nargs = 6,
		.argt = argt_562,
		.argsz = argsz_562,
		.noreturn = false
	},
	[563] = {
		.no = 563,
		.name = "getrandom",
		.nargs = 3,
		.argt = argt_563,
		.argsz = argsz_563,
		.noreturn = false
	},
	[564] = {
		.no = 564,
		.name = "getfhat",
		.nargs = 4,
		.argt = argt_564,
		.argsz = argsz_564,
		.noreturn = false
	},
	[565] = {
		.no = 565,
		.name = "fhlink",
		.nargs = 2,
		.argt = argt_565,
		.argsz = argsz_565,
		.noreturn = false
	},
	[566] = {
		.no = 566,
		.name = "fhlinkat",
		.nargs = 3,
		.argt = argt_566,
		.argsz = argsz_566,
		.noreturn = false
	},
	[567] = {
		.no = 567,
		.name = "fhreadlink",
		.nargs = 3,
		.argt = argt_567,
		.argsz = argsz_567,
		.noreturn = false
	},
	[568] = {
		.no = 568,
		.name = "funlinkat",
		.nargs = 4,
		.argt = argt_568,
		.argsz = argsz_568,
		.noreturn = false
	},
	[569] = {
		.no = 569,
		.name = "copy_file_range",
		.nargs = 6,
		.argt = argt_569,
		.argsz = argsz_569,
		.noreturn = false
	},
	[570] = {
		.no = 570,
		.name = "__sysctlbyname",
		.nargs = 6,
		.argt = argt_570,
		.argsz = argsz_570,
		.noreturn = false
	},
	[571] = {
		.no = 571,
		.name = "shm_open2",
		.nargs = 5,
		.argt = argt_571,
		.argsz = argsz_571,
		.noreturn = false
	},
	[572] = {
		.no = 572,
		.name = "shm_rename",
		.nargs = 3,
		.argt = argt_572,
		.argsz = argsz_572,
		.noreturn = false
	},
	[573] = {
		.no = 573,
		.name = "sigfastblock",
		.nargs = 2,
		.argt = argt_573,
		.argsz = argsz_573,
		.noreturn = false
	},
	[574] = {
		.no = 574,
		.name = "__realpathat",
		.nargs = 5,
		.argt = argt_574,
		.argsz = argsz_574,
		.noreturn = false
	},
	[575] = {
		.no = 575,
		.name = "close_range",
		.nargs = 3,
		.argt = argt_575,
		.argsz = argsz_575,
		.noreturn = false
	},
	[576] = {
		.no = 576,
		.name = "rpctls_syscall",
		.nargs = 2,
		.argt = argt_576,
		.argsz = argsz_576,
		.noreturn = false
	},
	
};

syscall_meta_t __syscall_meta = {
	.max = MAX_SYSCALL_NO,
	.max_generic = MAX_SYSCALL_GENERIC_NO,
	.max_args = MAX_SYSCALL_ARGS
};

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=c: */