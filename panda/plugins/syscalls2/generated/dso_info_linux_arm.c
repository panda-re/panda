#include <stdint.h>
#include <stdbool.h>
#include "../syscalls2_info.h"
#define MAX_SYSCALL_NO 983045
#define MAX_SYSCALL_GENERIC_NO 390
#define MAX_SYSCALL_ARGS 6

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

static syscall_argtype_t argt_0[] = {};
static uint8_t argsz_0[] = {};
static syscall_argtype_t argt_1[] = {SYSCALL_ARG_S32};
static uint8_t argsz_1[] = {sizeof(int32_t)};
static syscall_argtype_t argt_2[] = {};
static uint8_t argsz_2[] = {};
static syscall_argtype_t argt_3[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_3[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_5[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_5[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_6[] = {SYSCALL_ARG_U32};
static uint8_t argsz_6[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_8[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_8[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_9[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_9[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_10[] = {SYSCALL_ARG_STR};
static uint8_t argsz_10[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_11[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_11[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_12[] = {SYSCALL_ARG_STR};
static uint8_t argsz_12[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_13[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_13[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_14[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_14[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_15[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_15[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_16[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_16[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_19[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_19[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_20[] = {};
static uint8_t argsz_20[] = {};
static syscall_argtype_t argt_21[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_21[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_23[] = {SYSCALL_ARG_U32};
static uint8_t argsz_23[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_24[] = {};
static uint8_t argsz_24[] = {};
static syscall_argtype_t argt_25[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_25[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_26[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_26[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_27[] = {SYSCALL_ARG_U32};
static uint8_t argsz_27[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_29[] = {};
static uint8_t argsz_29[] = {};
static syscall_argtype_t argt_30[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_30[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_33[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_33[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_34[] = {SYSCALL_ARG_S32};
static uint8_t argsz_34[] = {sizeof(int32_t)};
static syscall_argtype_t argt_36[] = {};
static uint8_t argsz_36[] = {};
static syscall_argtype_t argt_37[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_37[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_38[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_38[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_39[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_39[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_40[] = {SYSCALL_ARG_STR};
static uint8_t argsz_40[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_41[] = {SYSCALL_ARG_U32};
static uint8_t argsz_41[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_42[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_42[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_43[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_43[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_45[] = {SYSCALL_ARG_U32};
static uint8_t argsz_45[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_46[] = {SYSCALL_ARG_U32};
static uint8_t argsz_46[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_47[] = {};
static uint8_t argsz_47[] = {};
static syscall_argtype_t argt_49[] = {};
static uint8_t argsz_49[] = {};
static syscall_argtype_t argt_50[] = {};
static uint8_t argsz_50[] = {};
static syscall_argtype_t argt_51[] = {SYSCALL_ARG_STR};
static uint8_t argsz_51[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_52[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_52[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_54[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_54[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_55[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_55[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_57[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_57[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_60[] = {SYSCALL_ARG_S32};
static uint8_t argsz_60[] = {sizeof(int32_t)};
static syscall_argtype_t argt_61[] = {SYSCALL_ARG_STR};
static uint8_t argsz_61[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_62[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_62[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_63[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_63[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_64[] = {};
static uint8_t argsz_64[] = {};
static syscall_argtype_t argt_65[] = {};
static uint8_t argsz_65[] = {};
static syscall_argtype_t argt_66[] = {};
static uint8_t argsz_66[] = {};
static syscall_argtype_t argt_67[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_67[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_70[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_70[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_71[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_71[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_72[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_72[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_73[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_73[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_74[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_74[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_75[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_75[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_77[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_77[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_78[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_78[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_79[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_79[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_80[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_80[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_81[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_81[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_83[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_83[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_85[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_85[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_86[] = {SYSCALL_ARG_STR};
static uint8_t argsz_86[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_87[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_87[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_88[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_88[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_91[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_91[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_92[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_92[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_93[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_93[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_94[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_94[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_95[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_95[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_96[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_96[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_97[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_97[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_99[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_99[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_100[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_100[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_102[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_102[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_103[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_103[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_104[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_104[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_105[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_105[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_106[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_106[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_107[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_107[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_108[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_108[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_111[] = {};
static uint8_t argsz_111[] = {};
static syscall_argtype_t argt_114[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_114[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_115[] = {SYSCALL_ARG_STR};
static uint8_t argsz_115[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_116[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_116[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_117[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_117[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_118[] = {SYSCALL_ARG_U32};
static uint8_t argsz_118[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_119[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_119[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_120[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_120[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_121[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_121[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_122[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_122[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_124[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_124[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_125[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_125[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_126[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_126[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_128[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_STR};
static uint8_t argsz_128[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_129[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_129[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_131[] = {SYSCALL_ARG_U32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_131[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_132[] = {SYSCALL_ARG_S32};
static uint8_t argsz_132[] = {sizeof(int32_t)};
static syscall_argtype_t argt_133[] = {SYSCALL_ARG_U32};
static uint8_t argsz_133[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_134[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_134[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_135[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_135[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_136[] = {SYSCALL_ARG_U32};
static uint8_t argsz_136[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_138[] = {SYSCALL_ARG_U32};
static uint8_t argsz_138[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_139[] = {SYSCALL_ARG_U32};
static uint8_t argsz_139[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_140[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_140[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_141[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_141[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_142[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_142[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_143[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_143[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_144[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_144[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_145[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_145[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_146[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_146[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_147[] = {SYSCALL_ARG_S32};
static uint8_t argsz_147[] = {sizeof(int32_t)};
static syscall_argtype_t argt_148[] = {SYSCALL_ARG_U32};
static uint8_t argsz_148[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_149[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_149[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_150[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_150[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_151[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_151[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_152[] = {SYSCALL_ARG_S32};
static uint8_t argsz_152[] = {sizeof(int32_t)};
static syscall_argtype_t argt_153[] = {};
static uint8_t argsz_153[] = {};
static syscall_argtype_t argt_154[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_154[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_155[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_155[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_156[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_156[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_157[] = {SYSCALL_ARG_S32};
static uint8_t argsz_157[] = {sizeof(int32_t)};
static syscall_argtype_t argt_158[] = {};
static uint8_t argsz_158[] = {};
static syscall_argtype_t argt_159[] = {SYSCALL_ARG_S32};
static uint8_t argsz_159[] = {sizeof(int32_t)};
static syscall_argtype_t argt_160[] = {SYSCALL_ARG_S32};
static uint8_t argsz_160[] = {sizeof(int32_t)};
static syscall_argtype_t argt_161[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_161[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_162[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_162[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_163[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_163[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_164[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_164[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_165[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_165[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_168[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_168[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_170[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_170[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_171[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_171[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_172[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_172[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_173[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_173[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_174[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_174[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_175[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_175[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_176[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_176[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_177[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_177[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_178[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_178[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_179[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_179[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_180[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U64};
static uint8_t argsz_180[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_181[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U64};
static uint8_t argsz_181[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_182[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_182[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_183[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_183[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_184[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_184[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_185[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_185[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_186[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_186[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_187[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_187[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_190[] = {};
static uint8_t argsz_190[] = {};
static syscall_argtype_t argt_191[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_191[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_192[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_192[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_193[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U64};
static uint8_t argsz_193[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_194[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U64};
static uint8_t argsz_194[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_195[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_195[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_196[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_196[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_197[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_197[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_198[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_198[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_199[] = {};
static uint8_t argsz_199[] = {};
static syscall_argtype_t argt_200[] = {};
static uint8_t argsz_200[] = {};
static syscall_argtype_t argt_201[] = {};
static uint8_t argsz_201[] = {};
static syscall_argtype_t argt_202[] = {};
static uint8_t argsz_202[] = {};
static syscall_argtype_t argt_203[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_203[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_204[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_204[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_205[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_205[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_206[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_206[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_207[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_207[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_208[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_208[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_209[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_209[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_210[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_210[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_211[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_211[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_212[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_212[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_213[] = {SYSCALL_ARG_U32};
static uint8_t argsz_213[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_214[] = {SYSCALL_ARG_U32};
static uint8_t argsz_214[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_215[] = {SYSCALL_ARG_U32};
static uint8_t argsz_215[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_216[] = {SYSCALL_ARG_U32};
static uint8_t argsz_216[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_217[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_217[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_218[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_218[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_219[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_STR};
static uint8_t argsz_219[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_220[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_220[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_221[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_221[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_224[] = {};
static uint8_t argsz_224[] = {};
static syscall_argtype_t argt_225[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U64, SYSCALL_ARG_U32};
static uint8_t argsz_225[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_226[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_226[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_227[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_227[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_228[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_228[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_229[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_229[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_230[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_230[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_231[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_231[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_232[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_232[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_233[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_233[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_234[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_234[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_235[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_235[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_236[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_236[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_237[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_237[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_238[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_238[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_239[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_239[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_240[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_240[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_241[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_241[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_242[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_242[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_243[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_243[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_244[] = {SYSCALL_ARG_U32};
static uint8_t argsz_244[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_245[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_245[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_246[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_246[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_247[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_247[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_248[] = {SYSCALL_ARG_S32};
static uint8_t argsz_248[] = {sizeof(int32_t)};
static syscall_argtype_t argt_249[] = {SYSCALL_ARG_U64, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_249[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_250[] = {SYSCALL_ARG_S32};
static uint8_t argsz_250[] = {sizeof(int32_t)};
static syscall_argtype_t argt_251[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_251[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_252[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_252[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_253[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_253[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_256[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_256[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_257[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_257[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_258[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_258[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_259[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_259[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_260[] = {SYSCALL_ARG_U32};
static uint8_t argsz_260[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_261[] = {SYSCALL_ARG_U32};
static uint8_t argsz_261[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_262[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_262[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_263[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_263[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_264[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_264[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_265[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_265[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_266[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_266[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_267[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_267[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_268[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_268[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_269[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_269[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_270[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U64, SYSCALL_ARG_U64};
static uint8_t argsz_270[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_271[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_271[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_272[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_272[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_273[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_273[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_274[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_274[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_275[] = {SYSCALL_ARG_STR};
static uint8_t argsz_275[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_276[] = {SYSCALL_ARG_U32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_276[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_277[] = {SYSCALL_ARG_U32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_277[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_278[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_278[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_279[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_279[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_280[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_280[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_281[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_281[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_282[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_282[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_283[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_283[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_284[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_284[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_285[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_285[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_286[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_286[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_287[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_287[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_288[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_288[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_289[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_289[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_290[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_290[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_291[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_291[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_292[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_292[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_293[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_293[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_294[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_294[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_295[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_295[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_296[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_296[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_297[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_297[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_298[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_298[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_299[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_299[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_300[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_300[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_301[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_301[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_302[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_302[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_303[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_303[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_304[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_304[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_305[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_305[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_306[] = {SYSCALL_ARG_STR};
static uint8_t argsz_306[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_307[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_307[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_308[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_308[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_309[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_309[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_310[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_310[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_311[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_311[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_312[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_312[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_314[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_314[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_315[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_315[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_316[] = {};
static uint8_t argsz_316[] = {};
static syscall_argtype_t argt_317[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_317[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_318[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_318[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_319[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_319[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_320[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_320[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_321[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_321[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_322[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_322[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_323[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_323[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_324[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_324[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_325[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_325[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_326[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_326[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_327[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_327[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_328[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_328[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_329[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_329[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_330[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_330[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_331[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_331[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_332[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_332[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_333[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_333[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_334[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_334[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_335[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_335[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_336[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_336[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_337[] = {SYSCALL_ARG_U32};
static uint8_t argsz_337[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_338[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_338[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_339[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_339[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_340[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_340[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_341[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U64, SYSCALL_ARG_U64};
static uint8_t argsz_341[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_342[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_342[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_343[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_343[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_344[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_344[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_345[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_345[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_346[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_346[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_347[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_347[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_348[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_348[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_349[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_349[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_350[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_350[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_351[] = {SYSCALL_ARG_U32};
static uint8_t argsz_351[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_352[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U64, SYSCALL_ARG_U64};
static uint8_t argsz_352[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_353[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_353[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_354[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_354[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_355[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_355[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_356[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_356[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_357[] = {SYSCALL_ARG_S32};
static uint8_t argsz_357[] = {sizeof(int32_t)};
static syscall_argtype_t argt_358[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_358[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_359[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_359[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_360[] = {SYSCALL_ARG_S32};
static uint8_t argsz_360[] = {sizeof(int32_t)};
static syscall_argtype_t argt_361[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_361[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_362[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_362[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_363[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_363[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_364[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_364[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_365[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_365[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_366[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_366[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_367[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_367[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_368[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U64, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_368[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_369[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_369[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_370[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_370[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_371[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_371[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_372[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_372[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_373[] = {SYSCALL_ARG_S32};
static uint8_t argsz_373[] = {sizeof(int32_t)};
static syscall_argtype_t argt_374[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_374[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_375[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_375[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_376[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_376[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_377[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_377[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_378[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_378[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_379[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_379[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_380[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_380[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_381[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_381[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_382[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_382[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_383[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_STR};
static uint8_t argsz_383[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_384[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_384[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_385[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_385[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_386[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_386[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_387[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_387[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_388[] = {SYSCALL_ARG_S32};
static uint8_t argsz_388[] = {sizeof(int32_t)};
static syscall_argtype_t argt_389[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_389[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_390[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_390[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
/* skipping non generic system call 983041 (ARM_breakpoint) */
/* skipping non generic system call 983042 (ARM_cacheflush) */
/* skipping non generic system call 983043 (ARM_user26_mode) */
/* skipping non generic system call 983044 (ARM_usr32_mode) */
/* skipping non generic system call 983045 (ARM_set_tls) */


syscall_info_t __syscall_info_a[] = {
	/* note that uninitialized values will be zeroed-out */
	[0] = {
		.no = 0,
		.name = "sys_restart_syscall",
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
		.noreturn = false
	},
	[2] = {
		.no = 2,
		.name = "sys_fork",
		.nargs = 0,
		.argt = argt_2,
		.argsz = argsz_2,
		.noreturn = false
	},
	[3] = {
		.no = 3,
		.name = "sys_read",
		.nargs = 3,
		.argt = argt_3,
		.argsz = argsz_3,
		.noreturn = false
	},
	[4] = {
		.no = 4,
		.name = "sys_write",
		.nargs = 3,
		.argt = argt_4,
		.argsz = argsz_4,
		.noreturn = false
	},
	[5] = {
		.no = 5,
		.name = "sys_open",
		.nargs = 3,
		.argt = argt_5,
		.argsz = argsz_5,
		.noreturn = false
	},
	[6] = {
		.no = 6,
		.name = "sys_close",
		.nargs = 1,
		.argt = argt_6,
		.argsz = argsz_6,
		.noreturn = false
	},
	[8] = {
		.no = 8,
		.name = "sys_creat",
		.nargs = 2,
		.argt = argt_8,
		.argsz = argsz_8,
		.noreturn = false
	},
	[9] = {
		.no = 9,
		.name = "sys_link",
		.nargs = 2,
		.argt = argt_9,
		.argsz = argsz_9,
		.noreturn = false
	},
	[10] = {
		.no = 10,
		.name = "sys_unlink",
		.nargs = 1,
		.argt = argt_10,
		.argsz = argsz_10,
		.noreturn = false
	},
	[11] = {
		.no = 11,
		.name = "sys_execve",
		.nargs = 3,
		.argt = argt_11,
		.argsz = argsz_11,
		.noreturn = true
	},
	[12] = {
		.no = 12,
		.name = "sys_chdir",
		.nargs = 1,
		.argt = argt_12,
		.argsz = argsz_12,
		.noreturn = false
	},
	[13] = {
		.no = 13,
		.name = "sys_time",
		.nargs = 1,
		.argt = argt_13,
		.argsz = argsz_13,
		.noreturn = false
	},
	[14] = {
		.no = 14,
		.name = "sys_mknod",
		.nargs = 3,
		.argt = argt_14,
		.argsz = argsz_14,
		.noreturn = false
	},
	[15] = {
		.no = 15,
		.name = "sys_chmod",
		.nargs = 2,
		.argt = argt_15,
		.argsz = argsz_15,
		.noreturn = false
	},
	[16] = {
		.no = 16,
		.name = "sys_lchown16",
		.nargs = 3,
		.argt = argt_16,
		.argsz = argsz_16,
		.noreturn = false
	},
	[19] = {
		.no = 19,
		.name = "sys_lseek",
		.nargs = 3,
		.argt = argt_19,
		.argsz = argsz_19,
		.noreturn = false
	},
	[20] = {
		.no = 20,
		.name = "sys_getpid",
		.nargs = 0,
		.argt = argt_20,
		.argsz = argsz_20,
		.noreturn = false
	},
	[21] = {
		.no = 21,
		.name = "sys_mount",
		.nargs = 5,
		.argt = argt_21,
		.argsz = argsz_21,
		.noreturn = false
	},
	[23] = {
		.no = 23,
		.name = "sys_setuid16",
		.nargs = 1,
		.argt = argt_23,
		.argsz = argsz_23,
		.noreturn = false
	},
	[24] = {
		.no = 24,
		.name = "sys_getuid16",
		.nargs = 0,
		.argt = argt_24,
		.argsz = argsz_24,
		.noreturn = false
	},
	[25] = {
		.no = 25,
		.name = "sys_stime",
		.nargs = 1,
		.argt = argt_25,
		.argsz = argsz_25,
		.noreturn = false
	},
	[26] = {
		.no = 26,
		.name = "sys_ptrace",
		.nargs = 4,
		.argt = argt_26,
		.argsz = argsz_26,
		.noreturn = false
	},
	[27] = {
		.no = 27,
		.name = "sys_alarm",
		.nargs = 1,
		.argt = argt_27,
		.argsz = argsz_27,
		.noreturn = false
	},
	[29] = {
		.no = 29,
		.name = "sys_pause",
		.nargs = 0,
		.argt = argt_29,
		.argsz = argsz_29,
		.noreturn = false
	},
	[30] = {
		.no = 30,
		.name = "sys_utime",
		.nargs = 2,
		.argt = argt_30,
		.argsz = argsz_30,
		.noreturn = false
	},
	[33] = {
		.no = 33,
		.name = "sys_access",
		.nargs = 2,
		.argt = argt_33,
		.argsz = argsz_33,
		.noreturn = false
	},
	[34] = {
		.no = 34,
		.name = "sys_nice",
		.nargs = 1,
		.argt = argt_34,
		.argsz = argsz_34,
		.noreturn = false
	},
	[36] = {
		.no = 36,
		.name = "sys_sync",
		.nargs = 0,
		.argt = argt_36,
		.argsz = argsz_36,
		.noreturn = false
	},
	[37] = {
		.no = 37,
		.name = "sys_kill",
		.nargs = 2,
		.argt = argt_37,
		.argsz = argsz_37,
		.noreturn = false
	},
	[38] = {
		.no = 38,
		.name = "sys_rename",
		.nargs = 2,
		.argt = argt_38,
		.argsz = argsz_38,
		.noreturn = false
	},
	[39] = {
		.no = 39,
		.name = "sys_mkdir",
		.nargs = 2,
		.argt = argt_39,
		.argsz = argsz_39,
		.noreturn = false
	},
	[40] = {
		.no = 40,
		.name = "sys_rmdir",
		.nargs = 1,
		.argt = argt_40,
		.argsz = argsz_40,
		.noreturn = false
	},
	[41] = {
		.no = 41,
		.name = "sys_dup",
		.nargs = 1,
		.argt = argt_41,
		.argsz = argsz_41,
		.noreturn = false
	},
	[42] = {
		.no = 42,
		.name = "sys_pipe",
		.nargs = 1,
		.argt = argt_42,
		.argsz = argsz_42,
		.noreturn = false
	},
	[43] = {
		.no = 43,
		.name = "sys_times",
		.nargs = 1,
		.argt = argt_43,
		.argsz = argsz_43,
		.noreturn = false
	},
	[45] = {
		.no = 45,
		.name = "sys_brk",
		.nargs = 1,
		.argt = argt_45,
		.argsz = argsz_45,
		.noreturn = false
	},
	[46] = {
		.no = 46,
		.name = "sys_setgid16",
		.nargs = 1,
		.argt = argt_46,
		.argsz = argsz_46,
		.noreturn = false
	},
	[47] = {
		.no = 47,
		.name = "sys_getgid16",
		.nargs = 0,
		.argt = argt_47,
		.argsz = argsz_47,
		.noreturn = false
	},
	[49] = {
		.no = 49,
		.name = "sys_geteuid16",
		.nargs = 0,
		.argt = argt_49,
		.argsz = argsz_49,
		.noreturn = false
	},
	[50] = {
		.no = 50,
		.name = "sys_getegid16",
		.nargs = 0,
		.argt = argt_50,
		.argsz = argsz_50,
		.noreturn = false
	},
	[51] = {
		.no = 51,
		.name = "sys_acct",
		.nargs = 1,
		.argt = argt_51,
		.argsz = argsz_51,
		.noreturn = false
	},
	[52] = {
		.no = 52,
		.name = "sys_umount",
		.nargs = 2,
		.argt = argt_52,
		.argsz = argsz_52,
		.noreturn = false
	},
	[54] = {
		.no = 54,
		.name = "sys_ioctl",
		.nargs = 3,
		.argt = argt_54,
		.argsz = argsz_54,
		.noreturn = false
	},
	[55] = {
		.no = 55,
		.name = "sys_fcntl",
		.nargs = 3,
		.argt = argt_55,
		.argsz = argsz_55,
		.noreturn = false
	},
	[57] = {
		.no = 57,
		.name = "sys_setpgid",
		.nargs = 2,
		.argt = argt_57,
		.argsz = argsz_57,
		.noreturn = false
	},
	[60] = {
		.no = 60,
		.name = "sys_umask",
		.nargs = 1,
		.argt = argt_60,
		.argsz = argsz_60,
		.noreturn = false
	},
	[61] = {
		.no = 61,
		.name = "sys_chroot",
		.nargs = 1,
		.argt = argt_61,
		.argsz = argsz_61,
		.noreturn = false
	},
	[62] = {
		.no = 62,
		.name = "sys_ustat",
		.nargs = 2,
		.argt = argt_62,
		.argsz = argsz_62,
		.noreturn = false
	},
	[63] = {
		.no = 63,
		.name = "sys_dup2",
		.nargs = 2,
		.argt = argt_63,
		.argsz = argsz_63,
		.noreturn = false
	},
	[64] = {
		.no = 64,
		.name = "sys_getppid",
		.nargs = 0,
		.argt = argt_64,
		.argsz = argsz_64,
		.noreturn = false
	},
	[65] = {
		.no = 65,
		.name = "sys_getpgrp",
		.nargs = 0,
		.argt = argt_65,
		.argsz = argsz_65,
		.noreturn = false
	},
	[66] = {
		.no = 66,
		.name = "sys_setsid",
		.nargs = 0,
		.argt = argt_66,
		.argsz = argsz_66,
		.noreturn = false
	},
	[67] = {
		.no = 67,
		.name = "sys_sigaction",
		.nargs = 3,
		.argt = argt_67,
		.argsz = argsz_67,
		.noreturn = false
	},
	[70] = {
		.no = 70,
		.name = "sys_setreuid16",
		.nargs = 2,
		.argt = argt_70,
		.argsz = argsz_70,
		.noreturn = false
	},
	[71] = {
		.no = 71,
		.name = "sys_setregid16",
		.nargs = 2,
		.argt = argt_71,
		.argsz = argsz_71,
		.noreturn = false
	},
	[72] = {
		.no = 72,
		.name = "sys_sigsuspend",
		.nargs = 3,
		.argt = argt_72,
		.argsz = argsz_72,
		.noreturn = false
	},
	[73] = {
		.no = 73,
		.name = "sys_sigpending",
		.nargs = 1,
		.argt = argt_73,
		.argsz = argsz_73,
		.noreturn = false
	},
	[74] = {
		.no = 74,
		.name = "sys_sethostname",
		.nargs = 2,
		.argt = argt_74,
		.argsz = argsz_74,
		.noreturn = false
	},
	[75] = {
		.no = 75,
		.name = "sys_setrlimit",
		.nargs = 2,
		.argt = argt_75,
		.argsz = argsz_75,
		.noreturn = false
	},
	[77] = {
		.no = 77,
		.name = "sys_getrusage",
		.nargs = 2,
		.argt = argt_77,
		.argsz = argsz_77,
		.noreturn = false
	},
	[78] = {
		.no = 78,
		.name = "sys_gettimeofday",
		.nargs = 2,
		.argt = argt_78,
		.argsz = argsz_78,
		.noreturn = false
	},
	[79] = {
		.no = 79,
		.name = "sys_settimeofday",
		.nargs = 2,
		.argt = argt_79,
		.argsz = argsz_79,
		.noreturn = false
	},
	[80] = {
		.no = 80,
		.name = "sys_getgroups16",
		.nargs = 2,
		.argt = argt_80,
		.argsz = argsz_80,
		.noreturn = false
	},
	[81] = {
		.no = 81,
		.name = "sys_setgroups16",
		.nargs = 2,
		.argt = argt_81,
		.argsz = argsz_81,
		.noreturn = false
	},
	[83] = {
		.no = 83,
		.name = "sys_symlink",
		.nargs = 2,
		.argt = argt_83,
		.argsz = argsz_83,
		.noreturn = false
	},
	[85] = {
		.no = 85,
		.name = "sys_readlink",
		.nargs = 3,
		.argt = argt_85,
		.argsz = argsz_85,
		.noreturn = false
	},
	[86] = {
		.no = 86,
		.name = "sys_uselib",
		.nargs = 1,
		.argt = argt_86,
		.argsz = argsz_86,
		.noreturn = false
	},
	[87] = {
		.no = 87,
		.name = "sys_swapon",
		.nargs = 2,
		.argt = argt_87,
		.argsz = argsz_87,
		.noreturn = false
	},
	[88] = {
		.no = 88,
		.name = "sys_reboot",
		.nargs = 4,
		.argt = argt_88,
		.argsz = argsz_88,
		.noreturn = false
	},
	[91] = {
		.no = 91,
		.name = "sys_munmap",
		.nargs = 2,
		.argt = argt_91,
		.argsz = argsz_91,
		.noreturn = false
	},
	[92] = {
		.no = 92,
		.name = "sys_truncate",
		.nargs = 2,
		.argt = argt_92,
		.argsz = argsz_92,
		.noreturn = false
	},
	[93] = {
		.no = 93,
		.name = "sys_ftruncate",
		.nargs = 2,
		.argt = argt_93,
		.argsz = argsz_93,
		.noreturn = false
	},
	[94] = {
		.no = 94,
		.name = "sys_fchmod",
		.nargs = 2,
		.argt = argt_94,
		.argsz = argsz_94,
		.noreturn = false
	},
	[95] = {
		.no = 95,
		.name = "sys_fchown16",
		.nargs = 3,
		.argt = argt_95,
		.argsz = argsz_95,
		.noreturn = false
	},
	[96] = {
		.no = 96,
		.name = "sys_getpriority",
		.nargs = 2,
		.argt = argt_96,
		.argsz = argsz_96,
		.noreturn = false
	},
	[97] = {
		.no = 97,
		.name = "sys_setpriority",
		.nargs = 3,
		.argt = argt_97,
		.argsz = argsz_97,
		.noreturn = false
	},
	[99] = {
		.no = 99,
		.name = "sys_statfs",
		.nargs = 2,
		.argt = argt_99,
		.argsz = argsz_99,
		.noreturn = false
	},
	[100] = {
		.no = 100,
		.name = "sys_fstatfs",
		.nargs = 2,
		.argt = argt_100,
		.argsz = argsz_100,
		.noreturn = false
	},
	[102] = {
		.no = 102,
		.name = "sys_socketcall",
		.nargs = 2,
		.argt = argt_102,
		.argsz = argsz_102,
		.noreturn = false
	},
	[103] = {
		.no = 103,
		.name = "sys_syslog",
		.nargs = 3,
		.argt = argt_103,
		.argsz = argsz_103,
		.noreturn = false
	},
	[104] = {
		.no = 104,
		.name = "sys_setitimer",
		.nargs = 3,
		.argt = argt_104,
		.argsz = argsz_104,
		.noreturn = false
	},
	[105] = {
		.no = 105,
		.name = "sys_getitimer",
		.nargs = 2,
		.argt = argt_105,
		.argsz = argsz_105,
		.noreturn = false
	},
	[106] = {
		.no = 106,
		.name = "sys_newstat",
		.nargs = 2,
		.argt = argt_106,
		.argsz = argsz_106,
		.noreturn = false
	},
	[107] = {
		.no = 107,
		.name = "sys_newlstat",
		.nargs = 2,
		.argt = argt_107,
		.argsz = argsz_107,
		.noreturn = false
	},
	[108] = {
		.no = 108,
		.name = "sys_newfstat",
		.nargs = 2,
		.argt = argt_108,
		.argsz = argsz_108,
		.noreturn = false
	},
	[111] = {
		.no = 111,
		.name = "sys_vhangup",
		.nargs = 0,
		.argt = argt_111,
		.argsz = argsz_111,
		.noreturn = false
	},
	[114] = {
		.no = 114,
		.name = "sys_wait4",
		.nargs = 4,
		.argt = argt_114,
		.argsz = argsz_114,
		.noreturn = false
	},
	[115] = {
		.no = 115,
		.name = "sys_swapoff",
		.nargs = 1,
		.argt = argt_115,
		.argsz = argsz_115,
		.noreturn = false
	},
	[116] = {
		.no = 116,
		.name = "sys_sysinfo",
		.nargs = 1,
		.argt = argt_116,
		.argsz = argsz_116,
		.noreturn = false
	},
	[117] = {
		.no = 117,
		.name = "sys_ipc",
		.nargs = 6,
		.argt = argt_117,
		.argsz = argsz_117,
		.noreturn = false
	},
	[118] = {
		.no = 118,
		.name = "sys_fsync",
		.nargs = 1,
		.argt = argt_118,
		.argsz = argsz_118,
		.noreturn = false
	},
	[119] = {
		.no = 119,
		.name = "sys_sigreturn",
		.nargs = 1,
		.argt = argt_119,
		.argsz = argsz_119,
		.noreturn = true
	},
	[120] = {
		.no = 120,
		.name = "sys_clone",
		.nargs = 5,
		.argt = argt_120,
		.argsz = argsz_120,
		.noreturn = false
	},
	[121] = {
		.no = 121,
		.name = "sys_setdomainname",
		.nargs = 2,
		.argt = argt_121,
		.argsz = argsz_121,
		.noreturn = false
	},
	[122] = {
		.no = 122,
		.name = "sys_newuname",
		.nargs = 1,
		.argt = argt_122,
		.argsz = argsz_122,
		.noreturn = false
	},
	[124] = {
		.no = 124,
		.name = "sys_adjtimex",
		.nargs = 1,
		.argt = argt_124,
		.argsz = argsz_124,
		.noreturn = false
	},
	[125] = {
		.no = 125,
		.name = "sys_mprotect",
		.nargs = 3,
		.argt = argt_125,
		.argsz = argsz_125,
		.noreturn = false
	},
	[126] = {
		.no = 126,
		.name = "sys_sigprocmask",
		.nargs = 3,
		.argt = argt_126,
		.argsz = argsz_126,
		.noreturn = false
	},
	[128] = {
		.no = 128,
		.name = "sys_init_module",
		.nargs = 3,
		.argt = argt_128,
		.argsz = argsz_128,
		.noreturn = false
	},
	[129] = {
		.no = 129,
		.name = "sys_delete_module",
		.nargs = 2,
		.argt = argt_129,
		.argsz = argsz_129,
		.noreturn = false
	},
	[131] = {
		.no = 131,
		.name = "sys_quotactl",
		.nargs = 4,
		.argt = argt_131,
		.argsz = argsz_131,
		.noreturn = false
	},
	[132] = {
		.no = 132,
		.name = "sys_getpgid",
		.nargs = 1,
		.argt = argt_132,
		.argsz = argsz_132,
		.noreturn = false
	},
	[133] = {
		.no = 133,
		.name = "sys_fchdir",
		.nargs = 1,
		.argt = argt_133,
		.argsz = argsz_133,
		.noreturn = false
	},
	[134] = {
		.no = 134,
		.name = "sys_bdflush",
		.nargs = 2,
		.argt = argt_134,
		.argsz = argsz_134,
		.noreturn = false
	},
	[135] = {
		.no = 135,
		.name = "sys_sysfs",
		.nargs = 3,
		.argt = argt_135,
		.argsz = argsz_135,
		.noreturn = false
	},
	[136] = {
		.no = 136,
		.name = "sys_personality",
		.nargs = 1,
		.argt = argt_136,
		.argsz = argsz_136,
		.noreturn = false
	},
	[138] = {
		.no = 138,
		.name = "sys_setfsuid16",
		.nargs = 1,
		.argt = argt_138,
		.argsz = argsz_138,
		.noreturn = false
	},
	[139] = {
		.no = 139,
		.name = "sys_setfsgid16",
		.nargs = 1,
		.argt = argt_139,
		.argsz = argsz_139,
		.noreturn = false
	},
	[140] = {
		.no = 140,
		.name = "sys_llseek",
		.nargs = 5,
		.argt = argt_140,
		.argsz = argsz_140,
		.noreturn = false
	},
	[141] = {
		.no = 141,
		.name = "sys_getdents",
		.nargs = 3,
		.argt = argt_141,
		.argsz = argsz_141,
		.noreturn = false
	},
	[142] = {
		.no = 142,
		.name = "sys_select",
		.nargs = 5,
		.argt = argt_142,
		.argsz = argsz_142,
		.noreturn = false
	},
	[143] = {
		.no = 143,
		.name = "sys_flock",
		.nargs = 2,
		.argt = argt_143,
		.argsz = argsz_143,
		.noreturn = false
	},
	[144] = {
		.no = 144,
		.name = "sys_msync",
		.nargs = 3,
		.argt = argt_144,
		.argsz = argsz_144,
		.noreturn = false
	},
	[145] = {
		.no = 145,
		.name = "sys_readv",
		.nargs = 3,
		.argt = argt_145,
		.argsz = argsz_145,
		.noreturn = false
	},
	[146] = {
		.no = 146,
		.name = "sys_writev",
		.nargs = 3,
		.argt = argt_146,
		.argsz = argsz_146,
		.noreturn = false
	},
	[147] = {
		.no = 147,
		.name = "sys_getsid",
		.nargs = 1,
		.argt = argt_147,
		.argsz = argsz_147,
		.noreturn = false
	},
	[148] = {
		.no = 148,
		.name = "sys_fdatasync",
		.nargs = 1,
		.argt = argt_148,
		.argsz = argsz_148,
		.noreturn = false
	},
	[149] = {
		.no = 149,
		.name = "sys_sysctl",
		.nargs = 1,
		.argt = argt_149,
		.argsz = argsz_149,
		.noreturn = false
	},
	[150] = {
		.no = 150,
		.name = "sys_mlock",
		.nargs = 2,
		.argt = argt_150,
		.argsz = argsz_150,
		.noreturn = false
	},
	[151] = {
		.no = 151,
		.name = "sys_munlock",
		.nargs = 2,
		.argt = argt_151,
		.argsz = argsz_151,
		.noreturn = false
	},
	[152] = {
		.no = 152,
		.name = "sys_mlockall",
		.nargs = 1,
		.argt = argt_152,
		.argsz = argsz_152,
		.noreturn = false
	},
	[153] = {
		.no = 153,
		.name = "sys_munlockall",
		.nargs = 0,
		.argt = argt_153,
		.argsz = argsz_153,
		.noreturn = false
	},
	[154] = {
		.no = 154,
		.name = "sys_sched_setparam",
		.nargs = 2,
		.argt = argt_154,
		.argsz = argsz_154,
		.noreturn = false
	},
	[155] = {
		.no = 155,
		.name = "sys_sched_getparam",
		.nargs = 2,
		.argt = argt_155,
		.argsz = argsz_155,
		.noreturn = false
	},
	[156] = {
		.no = 156,
		.name = "sys_sched_setscheduler",
		.nargs = 3,
		.argt = argt_156,
		.argsz = argsz_156,
		.noreturn = false
	},
	[157] = {
		.no = 157,
		.name = "sys_sched_getscheduler",
		.nargs = 1,
		.argt = argt_157,
		.argsz = argsz_157,
		.noreturn = false
	},
	[158] = {
		.no = 158,
		.name = "sys_sched_yield",
		.nargs = 0,
		.argt = argt_158,
		.argsz = argsz_158,
		.noreturn = false
	},
	[159] = {
		.no = 159,
		.name = "sys_sched_get_priority_max",
		.nargs = 1,
		.argt = argt_159,
		.argsz = argsz_159,
		.noreturn = false
	},
	[160] = {
		.no = 160,
		.name = "sys_sched_get_priority_min",
		.nargs = 1,
		.argt = argt_160,
		.argsz = argsz_160,
		.noreturn = false
	},
	[161] = {
		.no = 161,
		.name = "sys_sched_rr_get_interval",
		.nargs = 2,
		.argt = argt_161,
		.argsz = argsz_161,
		.noreturn = false
	},
	[162] = {
		.no = 162,
		.name = "sys_nanosleep",
		.nargs = 2,
		.argt = argt_162,
		.argsz = argsz_162,
		.noreturn = false
	},
	[163] = {
		.no = 163,
		.name = "sys_mremap",
		.nargs = 5,
		.argt = argt_163,
		.argsz = argsz_163,
		.noreturn = false
	},
	[164] = {
		.no = 164,
		.name = "sys_setresuid16",
		.nargs = 3,
		.argt = argt_164,
		.argsz = argsz_164,
		.noreturn = false
	},
	[165] = {
		.no = 165,
		.name = "sys_getresuid16",
		.nargs = 3,
		.argt = argt_165,
		.argsz = argsz_165,
		.noreturn = false
	},
	[168] = {
		.no = 168,
		.name = "sys_poll",
		.nargs = 3,
		.argt = argt_168,
		.argsz = argsz_168,
		.noreturn = false
	},
	[170] = {
		.no = 170,
		.name = "sys_setresgid16",
		.nargs = 3,
		.argt = argt_170,
		.argsz = argsz_170,
		.noreturn = false
	},
	[171] = {
		.no = 171,
		.name = "sys_getresgid16",
		.nargs = 3,
		.argt = argt_171,
		.argsz = argsz_171,
		.noreturn = false
	},
	[172] = {
		.no = 172,
		.name = "sys_prctl",
		.nargs = 5,
		.argt = argt_172,
		.argsz = argsz_172,
		.noreturn = false
	},
	[173] = {
		.no = 173,
		.name = "sys_rt_sigreturn",
		.nargs = 1,
		.argt = argt_173,
		.argsz = argsz_173,
		.noreturn = false
	},
	[174] = {
		.no = 174,
		.name = "sys_rt_sigaction",
		.nargs = 4,
		.argt = argt_174,
		.argsz = argsz_174,
		.noreturn = false
	},
	[175] = {
		.no = 175,
		.name = "sys_rt_sigprocmask",
		.nargs = 4,
		.argt = argt_175,
		.argsz = argsz_175,
		.noreturn = false
	},
	[176] = {
		.no = 176,
		.name = "sys_rt_sigpending",
		.nargs = 2,
		.argt = argt_176,
		.argsz = argsz_176,
		.noreturn = false
	},
	[177] = {
		.no = 177,
		.name = "sys_rt_sigtimedwait",
		.nargs = 4,
		.argt = argt_177,
		.argsz = argsz_177,
		.noreturn = false
	},
	[178] = {
		.no = 178,
		.name = "sys_rt_sigqueueinfo",
		.nargs = 3,
		.argt = argt_178,
		.argsz = argsz_178,
		.noreturn = false
	},
	[179] = {
		.no = 179,
		.name = "sys_rt_sigsuspend",
		.nargs = 2,
		.argt = argt_179,
		.argsz = argsz_179,
		.noreturn = false
	},
	[180] = {
		.no = 180,
		.name = "sys_pread64",
		.nargs = 4,
		.argt = argt_180,
		.argsz = argsz_180,
		.noreturn = false
	},
	[181] = {
		.no = 181,
		.name = "sys_pwrite64",
		.nargs = 4,
		.argt = argt_181,
		.argsz = argsz_181,
		.noreturn = false
	},
	[182] = {
		.no = 182,
		.name = "sys_chown16",
		.nargs = 3,
		.argt = argt_182,
		.argsz = argsz_182,
		.noreturn = false
	},
	[183] = {
		.no = 183,
		.name = "sys_getcwd",
		.nargs = 2,
		.argt = argt_183,
		.argsz = argsz_183,
		.noreturn = false
	},
	[184] = {
		.no = 184,
		.name = "sys_capget",
		.nargs = 2,
		.argt = argt_184,
		.argsz = argsz_184,
		.noreturn = false
	},
	[185] = {
		.no = 185,
		.name = "sys_capset",
		.nargs = 2,
		.argt = argt_185,
		.argsz = argsz_185,
		.noreturn = false
	},
	[186] = {
		.no = 186,
		.name = "sys_sigaltstack",
		.nargs = 2,
		.argt = argt_186,
		.argsz = argsz_186,
		.noreturn = false
	},
	[187] = {
		.no = 187,
		.name = "sys_sendfile",
		.nargs = 4,
		.argt = argt_187,
		.argsz = argsz_187,
		.noreturn = false
	},
	[190] = {
		.no = 190,
		.name = "sys_vfork",
		.nargs = 0,
		.argt = argt_190,
		.argsz = argsz_190,
		.noreturn = false
	},
	[191] = {
		.no = 191,
		.name = "sys_getrlimit",
		.nargs = 2,
		.argt = argt_191,
		.argsz = argsz_191,
		.noreturn = false
	},
	[192] = {
		.no = 192,
		.name = "do_mmap2",
		.nargs = 6,
		.argt = argt_192,
		.argsz = argsz_192,
		.noreturn = false
	},
	[193] = {
		.no = 193,
		.name = "sys_truncate64",
		.nargs = 2,
		.argt = argt_193,
		.argsz = argsz_193,
		.noreturn = false
	},
	[194] = {
		.no = 194,
		.name = "sys_ftruncate64",
		.nargs = 2,
		.argt = argt_194,
		.argsz = argsz_194,
		.noreturn = false
	},
	[195] = {
		.no = 195,
		.name = "sys_stat64",
		.nargs = 2,
		.argt = argt_195,
		.argsz = argsz_195,
		.noreturn = false
	},
	[196] = {
		.no = 196,
		.name = "sys_lstat64",
		.nargs = 2,
		.argt = argt_196,
		.argsz = argsz_196,
		.noreturn = false
	},
	[197] = {
		.no = 197,
		.name = "sys_fstat64",
		.nargs = 2,
		.argt = argt_197,
		.argsz = argsz_197,
		.noreturn = false
	},
	[198] = {
		.no = 198,
		.name = "sys_lchown",
		.nargs = 3,
		.argt = argt_198,
		.argsz = argsz_198,
		.noreturn = false
	},
	[199] = {
		.no = 199,
		.name = "sys_getuid",
		.nargs = 0,
		.argt = argt_199,
		.argsz = argsz_199,
		.noreturn = false
	},
	[200] = {
		.no = 200,
		.name = "sys_getgid",
		.nargs = 0,
		.argt = argt_200,
		.argsz = argsz_200,
		.noreturn = false
	},
	[201] = {
		.no = 201,
		.name = "sys_geteuid",
		.nargs = 0,
		.argt = argt_201,
		.argsz = argsz_201,
		.noreturn = false
	},
	[202] = {
		.no = 202,
		.name = "sys_getegid",
		.nargs = 0,
		.argt = argt_202,
		.argsz = argsz_202,
		.noreturn = false
	},
	[203] = {
		.no = 203,
		.name = "sys_setreuid",
		.nargs = 2,
		.argt = argt_203,
		.argsz = argsz_203,
		.noreturn = false
	},
	[204] = {
		.no = 204,
		.name = "sys_setregid",
		.nargs = 2,
		.argt = argt_204,
		.argsz = argsz_204,
		.noreturn = false
	},
	[205] = {
		.no = 205,
		.name = "sys_getgroups",
		.nargs = 2,
		.argt = argt_205,
		.argsz = argsz_205,
		.noreturn = false
	},
	[206] = {
		.no = 206,
		.name = "sys_setgroups",
		.nargs = 2,
		.argt = argt_206,
		.argsz = argsz_206,
		.noreturn = false
	},
	[207] = {
		.no = 207,
		.name = "sys_fchown",
		.nargs = 3,
		.argt = argt_207,
		.argsz = argsz_207,
		.noreturn = false
	},
	[208] = {
		.no = 208,
		.name = "sys_setresuid",
		.nargs = 3,
		.argt = argt_208,
		.argsz = argsz_208,
		.noreturn = false
	},
	[209] = {
		.no = 209,
		.name = "sys_getresuid",
		.nargs = 3,
		.argt = argt_209,
		.argsz = argsz_209,
		.noreturn = false
	},
	[210] = {
		.no = 210,
		.name = "sys_setresgid",
		.nargs = 3,
		.argt = argt_210,
		.argsz = argsz_210,
		.noreturn = false
	},
	[211] = {
		.no = 211,
		.name = "sys_getresgid",
		.nargs = 3,
		.argt = argt_211,
		.argsz = argsz_211,
		.noreturn = false
	},
	[212] = {
		.no = 212,
		.name = "sys_chown",
		.nargs = 3,
		.argt = argt_212,
		.argsz = argsz_212,
		.noreturn = false
	},
	[213] = {
		.no = 213,
		.name = "sys_setuid",
		.nargs = 1,
		.argt = argt_213,
		.argsz = argsz_213,
		.noreturn = false
	},
	[214] = {
		.no = 214,
		.name = "sys_setgid",
		.nargs = 1,
		.argt = argt_214,
		.argsz = argsz_214,
		.noreturn = false
	},
	[215] = {
		.no = 215,
		.name = "sys_setfsuid",
		.nargs = 1,
		.argt = argt_215,
		.argsz = argsz_215,
		.noreturn = false
	},
	[216] = {
		.no = 216,
		.name = "sys_setfsgid",
		.nargs = 1,
		.argt = argt_216,
		.argsz = argsz_216,
		.noreturn = false
	},
	[217] = {
		.no = 217,
		.name = "sys_getdents64",
		.nargs = 3,
		.argt = argt_217,
		.argsz = argsz_217,
		.noreturn = false
	},
	[218] = {
		.no = 218,
		.name = "sys_pivot_root",
		.nargs = 2,
		.argt = argt_218,
		.argsz = argsz_218,
		.noreturn = false
	},
	[219] = {
		.no = 219,
		.name = "sys_mincore",
		.nargs = 3,
		.argt = argt_219,
		.argsz = argsz_219,
		.noreturn = false
	},
	[220] = {
		.no = 220,
		.name = "sys_madvise",
		.nargs = 3,
		.argt = argt_220,
		.argsz = argsz_220,
		.noreturn = false
	},
	[221] = {
		.no = 221,
		.name = "sys_fcntl64",
		.nargs = 3,
		.argt = argt_221,
		.argsz = argsz_221,
		.noreturn = false
	},
	[224] = {
		.no = 224,
		.name = "sys_gettid",
		.nargs = 0,
		.argt = argt_224,
		.argsz = argsz_224,
		.noreturn = false
	},
	[225] = {
		.no = 225,
		.name = "sys_readahead",
		.nargs = 3,
		.argt = argt_225,
		.argsz = argsz_225,
		.noreturn = false
	},
	[226] = {
		.no = 226,
		.name = "sys_setxattr",
		.nargs = 5,
		.argt = argt_226,
		.argsz = argsz_226,
		.noreturn = false
	},
	[227] = {
		.no = 227,
		.name = "sys_lsetxattr",
		.nargs = 5,
		.argt = argt_227,
		.argsz = argsz_227,
		.noreturn = false
	},
	[228] = {
		.no = 228,
		.name = "sys_fsetxattr",
		.nargs = 5,
		.argt = argt_228,
		.argsz = argsz_228,
		.noreturn = false
	},
	[229] = {
		.no = 229,
		.name = "sys_getxattr",
		.nargs = 4,
		.argt = argt_229,
		.argsz = argsz_229,
		.noreturn = false
	},
	[230] = {
		.no = 230,
		.name = "sys_lgetxattr",
		.nargs = 4,
		.argt = argt_230,
		.argsz = argsz_230,
		.noreturn = false
	},
	[231] = {
		.no = 231,
		.name = "sys_fgetxattr",
		.nargs = 4,
		.argt = argt_231,
		.argsz = argsz_231,
		.noreturn = false
	},
	[232] = {
		.no = 232,
		.name = "sys_listxattr",
		.nargs = 3,
		.argt = argt_232,
		.argsz = argsz_232,
		.noreturn = false
	},
	[233] = {
		.no = 233,
		.name = "sys_llistxattr",
		.nargs = 3,
		.argt = argt_233,
		.argsz = argsz_233,
		.noreturn = false
	},
	[234] = {
		.no = 234,
		.name = "sys_flistxattr",
		.nargs = 3,
		.argt = argt_234,
		.argsz = argsz_234,
		.noreturn = false
	},
	[235] = {
		.no = 235,
		.name = "sys_removexattr",
		.nargs = 2,
		.argt = argt_235,
		.argsz = argsz_235,
		.noreturn = false
	},
	[236] = {
		.no = 236,
		.name = "sys_lremovexattr",
		.nargs = 2,
		.argt = argt_236,
		.argsz = argsz_236,
		.noreturn = false
	},
	[237] = {
		.no = 237,
		.name = "sys_fremovexattr",
		.nargs = 2,
		.argt = argt_237,
		.argsz = argsz_237,
		.noreturn = false
	},
	[238] = {
		.no = 238,
		.name = "sys_tkill",
		.nargs = 2,
		.argt = argt_238,
		.argsz = argsz_238,
		.noreturn = false
	},
	[239] = {
		.no = 239,
		.name = "sys_sendfile64",
		.nargs = 4,
		.argt = argt_239,
		.argsz = argsz_239,
		.noreturn = false
	},
	[240] = {
		.no = 240,
		.name = "sys_futex",
		.nargs = 6,
		.argt = argt_240,
		.argsz = argsz_240,
		.noreturn = false
	},
	[241] = {
		.no = 241,
		.name = "sys_sched_setaffinity",
		.nargs = 3,
		.argt = argt_241,
		.argsz = argsz_241,
		.noreturn = false
	},
	[242] = {
		.no = 242,
		.name = "sys_sched_getaffinity",
		.nargs = 3,
		.argt = argt_242,
		.argsz = argsz_242,
		.noreturn = false
	},
	[243] = {
		.no = 243,
		.name = "sys_io_setup",
		.nargs = 2,
		.argt = argt_243,
		.argsz = argsz_243,
		.noreturn = false
	},
	[244] = {
		.no = 244,
		.name = "sys_io_destroy",
		.nargs = 1,
		.argt = argt_244,
		.argsz = argsz_244,
		.noreturn = false
	},
	[245] = {
		.no = 245,
		.name = "sys_io_getevents",
		.nargs = 5,
		.argt = argt_245,
		.argsz = argsz_245,
		.noreturn = false
	},
	[246] = {
		.no = 246,
		.name = "sys_io_submit",
		.nargs = 3,
		.argt = argt_246,
		.argsz = argsz_246,
		.noreturn = false
	},
	[247] = {
		.no = 247,
		.name = "sys_io_cancel",
		.nargs = 3,
		.argt = argt_247,
		.argsz = argsz_247,
		.noreturn = false
	},
	[248] = {
		.no = 248,
		.name = "sys_exit_group",
		.nargs = 1,
		.argt = argt_248,
		.argsz = argsz_248,
		.noreturn = true
	},
	[249] = {
		.no = 249,
		.name = "sys_lookup_dcookie",
		.nargs = 3,
		.argt = argt_249,
		.argsz = argsz_249,
		.noreturn = false
	},
	[250] = {
		.no = 250,
		.name = "sys_epoll_create",
		.nargs = 1,
		.argt = argt_250,
		.argsz = argsz_250,
		.noreturn = false
	},
	[251] = {
		.no = 251,
		.name = "sys_epoll_ctl",
		.nargs = 4,
		.argt = argt_251,
		.argsz = argsz_251,
		.noreturn = false
	},
	[252] = {
		.no = 252,
		.name = "sys_epoll_wait",
		.nargs = 4,
		.argt = argt_252,
		.argsz = argsz_252,
		.noreturn = false
	},
	[253] = {
		.no = 253,
		.name = "sys_remap_file_pages",
		.nargs = 5,
		.argt = argt_253,
		.argsz = argsz_253,
		.noreturn = false
	},
	[256] = {
		.no = 256,
		.name = "sys_set_tid_address",
		.nargs = 1,
		.argt = argt_256,
		.argsz = argsz_256,
		.noreturn = false
	},
	[257] = {
		.no = 257,
		.name = "sys_timer_create",
		.nargs = 3,
		.argt = argt_257,
		.argsz = argsz_257,
		.noreturn = false
	},
	[258] = {
		.no = 258,
		.name = "sys_timer_settime",
		.nargs = 4,
		.argt = argt_258,
		.argsz = argsz_258,
		.noreturn = false
	},
	[259] = {
		.no = 259,
		.name = "sys_timer_gettime",
		.nargs = 2,
		.argt = argt_259,
		.argsz = argsz_259,
		.noreturn = false
	},
	[260] = {
		.no = 260,
		.name = "sys_timer_getoverrun",
		.nargs = 1,
		.argt = argt_260,
		.argsz = argsz_260,
		.noreturn = false
	},
	[261] = {
		.no = 261,
		.name = "sys_timer_delete",
		.nargs = 1,
		.argt = argt_261,
		.argsz = argsz_261,
		.noreturn = false
	},
	[262] = {
		.no = 262,
		.name = "sys_clock_settime",
		.nargs = 2,
		.argt = argt_262,
		.argsz = argsz_262,
		.noreturn = false
	},
	[263] = {
		.no = 263,
		.name = "sys_clock_gettime",
		.nargs = 2,
		.argt = argt_263,
		.argsz = argsz_263,
		.noreturn = false
	},
	[264] = {
		.no = 264,
		.name = "sys_clock_getres",
		.nargs = 2,
		.argt = argt_264,
		.argsz = argsz_264,
		.noreturn = false
	},
	[265] = {
		.no = 265,
		.name = "sys_clock_nanosleep",
		.nargs = 4,
		.argt = argt_265,
		.argsz = argsz_265,
		.noreturn = false
	},
	[266] = {
		.no = 266,
		.name = "sys_statfs64",
		.nargs = 3,
		.argt = argt_266,
		.argsz = argsz_266,
		.noreturn = false
	},
	[267] = {
		.no = 267,
		.name = "sys_fstatfs64",
		.nargs = 3,
		.argt = argt_267,
		.argsz = argsz_267,
		.noreturn = false
	},
	[268] = {
		.no = 268,
		.name = "sys_tgkill",
		.nargs = 3,
		.argt = argt_268,
		.argsz = argsz_268,
		.noreturn = false
	},
	[269] = {
		.no = 269,
		.name = "sys_utimes",
		.nargs = 2,
		.argt = argt_269,
		.argsz = argsz_269,
		.noreturn = false
	},
	[270] = {
		.no = 270,
		.name = "sys_arm_fadvise64_64",
		.nargs = 4,
		.argt = argt_270,
		.argsz = argsz_270,
		.noreturn = false
	},
	[271] = {
		.no = 271,
		.name = "sys_pciconfig_iobase",
		.nargs = 3,
		.argt = argt_271,
		.argsz = argsz_271,
		.noreturn = false
	},
	[272] = {
		.no = 272,
		.name = "sys_pciconfig_read",
		.nargs = 5,
		.argt = argt_272,
		.argsz = argsz_272,
		.noreturn = false
	},
	[273] = {
		.no = 273,
		.name = "sys_pciconfig_write",
		.nargs = 5,
		.argt = argt_273,
		.argsz = argsz_273,
		.noreturn = false
	},
	[274] = {
		.no = 274,
		.name = "sys_mq_open",
		.nargs = 4,
		.argt = argt_274,
		.argsz = argsz_274,
		.noreturn = false
	},
	[275] = {
		.no = 275,
		.name = "sys_mq_unlink",
		.nargs = 1,
		.argt = argt_275,
		.argsz = argsz_275,
		.noreturn = false
	},
	[276] = {
		.no = 276,
		.name = "sys_mq_timedsend",
		.nargs = 5,
		.argt = argt_276,
		.argsz = argsz_276,
		.noreturn = false
	},
	[277] = {
		.no = 277,
		.name = "sys_mq_timedreceive",
		.nargs = 5,
		.argt = argt_277,
		.argsz = argsz_277,
		.noreturn = false
	},
	[278] = {
		.no = 278,
		.name = "sys_mq_notify",
		.nargs = 2,
		.argt = argt_278,
		.argsz = argsz_278,
		.noreturn = false
	},
	[279] = {
		.no = 279,
		.name = "sys_mq_getsetattr",
		.nargs = 3,
		.argt = argt_279,
		.argsz = argsz_279,
		.noreturn = false
	},
	[280] = {
		.no = 280,
		.name = "sys_waitid",
		.nargs = 5,
		.argt = argt_280,
		.argsz = argsz_280,
		.noreturn = false
	},
	[281] = {
		.no = 281,
		.name = "sys_socket",
		.nargs = 3,
		.argt = argt_281,
		.argsz = argsz_281,
		.noreturn = false
	},
	[282] = {
		.no = 282,
		.name = "sys_bind",
		.nargs = 3,
		.argt = argt_282,
		.argsz = argsz_282,
		.noreturn = false
	},
	[283] = {
		.no = 283,
		.name = "sys_connect",
		.nargs = 3,
		.argt = argt_283,
		.argsz = argsz_283,
		.noreturn = false
	},
	[284] = {
		.no = 284,
		.name = "sys_listen",
		.nargs = 2,
		.argt = argt_284,
		.argsz = argsz_284,
		.noreturn = false
	},
	[285] = {
		.no = 285,
		.name = "sys_accept",
		.nargs = 3,
		.argt = argt_285,
		.argsz = argsz_285,
		.noreturn = false
	},
	[286] = {
		.no = 286,
		.name = "sys_getsockname",
		.nargs = 3,
		.argt = argt_286,
		.argsz = argsz_286,
		.noreturn = false
	},
	[287] = {
		.no = 287,
		.name = "sys_getpeername",
		.nargs = 3,
		.argt = argt_287,
		.argsz = argsz_287,
		.noreturn = false
	},
	[288] = {
		.no = 288,
		.name = "sys_socketpair",
		.nargs = 4,
		.argt = argt_288,
		.argsz = argsz_288,
		.noreturn = false
	},
	[289] = {
		.no = 289,
		.name = "sys_send",
		.nargs = 4,
		.argt = argt_289,
		.argsz = argsz_289,
		.noreturn = false
	},
	[290] = {
		.no = 290,
		.name = "sys_sendto",
		.nargs = 6,
		.argt = argt_290,
		.argsz = argsz_290,
		.noreturn = false
	},
	[291] = {
		.no = 291,
		.name = "sys_recv",
		.nargs = 4,
		.argt = argt_291,
		.argsz = argsz_291,
		.noreturn = false
	},
	[292] = {
		.no = 292,
		.name = "sys_recvfrom",
		.nargs = 6,
		.argt = argt_292,
		.argsz = argsz_292,
		.noreturn = false
	},
	[293] = {
		.no = 293,
		.name = "sys_shutdown",
		.nargs = 2,
		.argt = argt_293,
		.argsz = argsz_293,
		.noreturn = false
	},
	[294] = {
		.no = 294,
		.name = "sys_setsockopt",
		.nargs = 5,
		.argt = argt_294,
		.argsz = argsz_294,
		.noreturn = false
	},
	[295] = {
		.no = 295,
		.name = "sys_getsockopt",
		.nargs = 5,
		.argt = argt_295,
		.argsz = argsz_295,
		.noreturn = false
	},
	[296] = {
		.no = 296,
		.name = "sys_sendmsg",
		.nargs = 3,
		.argt = argt_296,
		.argsz = argsz_296,
		.noreturn = false
	},
	[297] = {
		.no = 297,
		.name = "sys_recvmsg",
		.nargs = 3,
		.argt = argt_297,
		.argsz = argsz_297,
		.noreturn = false
	},
	[298] = {
		.no = 298,
		.name = "sys_semop",
		.nargs = 3,
		.argt = argt_298,
		.argsz = argsz_298,
		.noreturn = false
	},
	[299] = {
		.no = 299,
		.name = "sys_semget",
		.nargs = 3,
		.argt = argt_299,
		.argsz = argsz_299,
		.noreturn = false
	},
	[300] = {
		.no = 300,
		.name = "sys_semctl",
		.nargs = 4,
		.argt = argt_300,
		.argsz = argsz_300,
		.noreturn = false
	},
	[301] = {
		.no = 301,
		.name = "sys_msgsnd",
		.nargs = 4,
		.argt = argt_301,
		.argsz = argsz_301,
		.noreturn = false
	},
	[302] = {
		.no = 302,
		.name = "sys_msgrcv",
		.nargs = 5,
		.argt = argt_302,
		.argsz = argsz_302,
		.noreturn = false
	},
	[303] = {
		.no = 303,
		.name = "sys_msgget",
		.nargs = 2,
		.argt = argt_303,
		.argsz = argsz_303,
		.noreturn = false
	},
	[304] = {
		.no = 304,
		.name = "sys_msgctl",
		.nargs = 3,
		.argt = argt_304,
		.argsz = argsz_304,
		.noreturn = false
	},
	[305] = {
		.no = 305,
		.name = "sys_shmat",
		.nargs = 3,
		.argt = argt_305,
		.argsz = argsz_305,
		.noreturn = false
	},
	[306] = {
		.no = 306,
		.name = "sys_shmdt",
		.nargs = 1,
		.argt = argt_306,
		.argsz = argsz_306,
		.noreturn = false
	},
	[307] = {
		.no = 307,
		.name = "sys_shmget",
		.nargs = 3,
		.argt = argt_307,
		.argsz = argsz_307,
		.noreturn = false
	},
	[308] = {
		.no = 308,
		.name = "sys_shmctl",
		.nargs = 3,
		.argt = argt_308,
		.argsz = argsz_308,
		.noreturn = false
	},
	[309] = {
		.no = 309,
		.name = "sys_add_key",
		.nargs = 5,
		.argt = argt_309,
		.argsz = argsz_309,
		.noreturn = false
	},
	[310] = {
		.no = 310,
		.name = "sys_request_key",
		.nargs = 4,
		.argt = argt_310,
		.argsz = argsz_310,
		.noreturn = false
	},
	[311] = {
		.no = 311,
		.name = "sys_keyctl",
		.nargs = 5,
		.argt = argt_311,
		.argsz = argsz_311,
		.noreturn = false
	},
	[312] = {
		.no = 312,
		.name = "sys_semtimedop",
		.nargs = 4,
		.argt = argt_312,
		.argsz = argsz_312,
		.noreturn = false
	},
	[314] = {
		.no = 314,
		.name = "sys_ioprio_set",
		.nargs = 3,
		.argt = argt_314,
		.argsz = argsz_314,
		.noreturn = false
	},
	[315] = {
		.no = 315,
		.name = "sys_ioprio_get",
		.nargs = 2,
		.argt = argt_315,
		.argsz = argsz_315,
		.noreturn = false
	},
	[316] = {
		.no = 316,
		.name = "sys_inotify_init",
		.nargs = 0,
		.argt = argt_316,
		.argsz = argsz_316,
		.noreturn = false
	},
	[317] = {
		.no = 317,
		.name = "sys_inotify_add_watch",
		.nargs = 3,
		.argt = argt_317,
		.argsz = argsz_317,
		.noreturn = false
	},
	[318] = {
		.no = 318,
		.name = "sys_inotify_rm_watch",
		.nargs = 2,
		.argt = argt_318,
		.argsz = argsz_318,
		.noreturn = false
	},
	[319] = {
		.no = 319,
		.name = "sys_mbind",
		.nargs = 6,
		.argt = argt_319,
		.argsz = argsz_319,
		.noreturn = false
	},
	[320] = {
		.no = 320,
		.name = "sys_get_mempolicy",
		.nargs = 5,
		.argt = argt_320,
		.argsz = argsz_320,
		.noreturn = false
	},
	[321] = {
		.no = 321,
		.name = "sys_set_mempolicy",
		.nargs = 3,
		.argt = argt_321,
		.argsz = argsz_321,
		.noreturn = false
	},
	[322] = {
		.no = 322,
		.name = "sys_openat",
		.nargs = 4,
		.argt = argt_322,
		.argsz = argsz_322,
		.noreturn = false
	},
	[323] = {
		.no = 323,
		.name = "sys_mkdirat",
		.nargs = 3,
		.argt = argt_323,
		.argsz = argsz_323,
		.noreturn = false
	},
	[324] = {
		.no = 324,
		.name = "sys_mknodat",
		.nargs = 4,
		.argt = argt_324,
		.argsz = argsz_324,
		.noreturn = false
	},
	[325] = {
		.no = 325,
		.name = "sys_fchownat",
		.nargs = 5,
		.argt = argt_325,
		.argsz = argsz_325,
		.noreturn = false
	},
	[326] = {
		.no = 326,
		.name = "sys_futimesat",
		.nargs = 3,
		.argt = argt_326,
		.argsz = argsz_326,
		.noreturn = false
	},
	[327] = {
		.no = 327,
		.name = "sys_fstatat64",
		.nargs = 4,
		.argt = argt_327,
		.argsz = argsz_327,
		.noreturn = false
	},
	[328] = {
		.no = 328,
		.name = "sys_unlinkat",
		.nargs = 3,
		.argt = argt_328,
		.argsz = argsz_328,
		.noreturn = false
	},
	[329] = {
		.no = 329,
		.name = "sys_renameat",
		.nargs = 4,
		.argt = argt_329,
		.argsz = argsz_329,
		.noreturn = false
	},
	[330] = {
		.no = 330,
		.name = "sys_linkat",
		.nargs = 5,
		.argt = argt_330,
		.argsz = argsz_330,
		.noreturn = false
	},
	[331] = {
		.no = 331,
		.name = "sys_symlinkat",
		.nargs = 3,
		.argt = argt_331,
		.argsz = argsz_331,
		.noreturn = false
	},
	[332] = {
		.no = 332,
		.name = "sys_readlinkat",
		.nargs = 4,
		.argt = argt_332,
		.argsz = argsz_332,
		.noreturn = false
	},
	[333] = {
		.no = 333,
		.name = "sys_fchmodat",
		.nargs = 3,
		.argt = argt_333,
		.argsz = argsz_333,
		.noreturn = false
	},
	[334] = {
		.no = 334,
		.name = "sys_faccessat",
		.nargs = 3,
		.argt = argt_334,
		.argsz = argsz_334,
		.noreturn = false
	},
	[335] = {
		.no = 335,
		.name = "sys_pselect6",
		.nargs = 6,
		.argt = argt_335,
		.argsz = argsz_335,
		.noreturn = false
	},
	[336] = {
		.no = 336,
		.name = "sys_ppoll",
		.nargs = 5,
		.argt = argt_336,
		.argsz = argsz_336,
		.noreturn = false
	},
	[337] = {
		.no = 337,
		.name = "sys_unshare",
		.nargs = 1,
		.argt = argt_337,
		.argsz = argsz_337,
		.noreturn = false
	},
	[338] = {
		.no = 338,
		.name = "sys_set_robust_list",
		.nargs = 2,
		.argt = argt_338,
		.argsz = argsz_338,
		.noreturn = false
	},
	[339] = {
		.no = 339,
		.name = "sys_get_robust_list",
		.nargs = 3,
		.argt = argt_339,
		.argsz = argsz_339,
		.noreturn = false
	},
	[340] = {
		.no = 340,
		.name = "sys_splice",
		.nargs = 6,
		.argt = argt_340,
		.argsz = argsz_340,
		.noreturn = false
	},
	[341] = {
		.no = 341,
		.name = "sys_sync_file_range2",
		.nargs = 4,
		.argt = argt_341,
		.argsz = argsz_341,
		.noreturn = false
	},
	[342] = {
		.no = 342,
		.name = "sys_tee",
		.nargs = 4,
		.argt = argt_342,
		.argsz = argsz_342,
		.noreturn = false
	},
	[343] = {
		.no = 343,
		.name = "sys_vmsplice",
		.nargs = 4,
		.argt = argt_343,
		.argsz = argsz_343,
		.noreturn = false
	},
	[344] = {
		.no = 344,
		.name = "sys_move_pages",
		.nargs = 6,
		.argt = argt_344,
		.argsz = argsz_344,
		.noreturn = false
	},
	[345] = {
		.no = 345,
		.name = "sys_getcpu",
		.nargs = 3,
		.argt = argt_345,
		.argsz = argsz_345,
		.noreturn = false
	},
	[346] = {
		.no = 346,
		.name = "sys_epoll_pwait",
		.nargs = 6,
		.argt = argt_346,
		.argsz = argsz_346,
		.noreturn = false
	},
	[347] = {
		.no = 347,
		.name = "sys_kexec_load",
		.nargs = 4,
		.argt = argt_347,
		.argsz = argsz_347,
		.noreturn = false
	},
	[348] = {
		.no = 348,
		.name = "sys_utimensat",
		.nargs = 4,
		.argt = argt_348,
		.argsz = argsz_348,
		.noreturn = false
	},
	[349] = {
		.no = 349,
		.name = "sys_signalfd",
		.nargs = 3,
		.argt = argt_349,
		.argsz = argsz_349,
		.noreturn = false
	},
	[350] = {
		.no = 350,
		.name = "sys_timerfd_create",
		.nargs = 2,
		.argt = argt_350,
		.argsz = argsz_350,
		.noreturn = false
	},
	[351] = {
		.no = 351,
		.name = "sys_eventfd",
		.nargs = 1,
		.argt = argt_351,
		.argsz = argsz_351,
		.noreturn = false
	},
	[352] = {
		.no = 352,
		.name = "sys_fallocate",
		.nargs = 4,
		.argt = argt_352,
		.argsz = argsz_352,
		.noreturn = false
	},
	[353] = {
		.no = 353,
		.name = "sys_timerfd_settime",
		.nargs = 4,
		.argt = argt_353,
		.argsz = argsz_353,
		.noreturn = false
	},
	[354] = {
		.no = 354,
		.name = "sys_timerfd_gettime",
		.nargs = 2,
		.argt = argt_354,
		.argsz = argsz_354,
		.noreturn = false
	},
	[355] = {
		.no = 355,
		.name = "sys_signalfd4",
		.nargs = 4,
		.argt = argt_355,
		.argsz = argsz_355,
		.noreturn = false
	},
	[356] = {
		.no = 356,
		.name = "sys_eventfd2",
		.nargs = 2,
		.argt = argt_356,
		.argsz = argsz_356,
		.noreturn = false
	},
	[357] = {
		.no = 357,
		.name = "sys_epoll_create1",
		.nargs = 1,
		.argt = argt_357,
		.argsz = argsz_357,
		.noreturn = false
	},
	[358] = {
		.no = 358,
		.name = "sys_dup3",
		.nargs = 3,
		.argt = argt_358,
		.argsz = argsz_358,
		.noreturn = false
	},
	[359] = {
		.no = 359,
		.name = "sys_pipe2",
		.nargs = 2,
		.argt = argt_359,
		.argsz = argsz_359,
		.noreturn = false
	},
	[360] = {
		.no = 360,
		.name = "sys_inotify_init1",
		.nargs = 1,
		.argt = argt_360,
		.argsz = argsz_360,
		.noreturn = false
	},
	[361] = {
		.no = 361,
		.name = "sys_preadv",
		.nargs = 5,
		.argt = argt_361,
		.argsz = argsz_361,
		.noreturn = false
	},
	[362] = {
		.no = 362,
		.name = "sys_pwritev",
		.nargs = 5,
		.argt = argt_362,
		.argsz = argsz_362,
		.noreturn = false
	},
	[363] = {
		.no = 363,
		.name = "sys_rt_tgsigqueueinfo",
		.nargs = 4,
		.argt = argt_363,
		.argsz = argsz_363,
		.noreturn = false
	},
	[364] = {
		.no = 364,
		.name = "sys_perf_event_open",
		.nargs = 5,
		.argt = argt_364,
		.argsz = argsz_364,
		.noreturn = false
	},
	[365] = {
		.no = 365,
		.name = "sys_recvmmsg",
		.nargs = 5,
		.argt = argt_365,
		.argsz = argsz_365,
		.noreturn = false
	},
	[366] = {
		.no = 366,
		.name = "sys_accept4",
		.nargs = 4,
		.argt = argt_366,
		.argsz = argsz_366,
		.noreturn = false
	},
	[367] = {
		.no = 367,
		.name = "sys_fanotify_init",
		.nargs = 2,
		.argt = argt_367,
		.argsz = argsz_367,
		.noreturn = false
	},
	[368] = {
		.no = 368,
		.name = "sys_fanotify_mark",
		.nargs = 5,
		.argt = argt_368,
		.argsz = argsz_368,
		.noreturn = false
	},
	[369] = {
		.no = 369,
		.name = "sys_prlimit64",
		.nargs = 4,
		.argt = argt_369,
		.argsz = argsz_369,
		.noreturn = false
	},
	[370] = {
		.no = 370,
		.name = "sys_name_to_handle_at",
		.nargs = 5,
		.argt = argt_370,
		.argsz = argsz_370,
		.noreturn = false
	},
	[371] = {
		.no = 371,
		.name = "sys_open_by_handle_at",
		.nargs = 3,
		.argt = argt_371,
		.argsz = argsz_371,
		.noreturn = false
	},
	[372] = {
		.no = 372,
		.name = "sys_clock_adjtime",
		.nargs = 2,
		.argt = argt_372,
		.argsz = argsz_372,
		.noreturn = false
	},
	[373] = {
		.no = 373,
		.name = "sys_syncfs",
		.nargs = 1,
		.argt = argt_373,
		.argsz = argsz_373,
		.noreturn = false
	},
	[374] = {
		.no = 374,
		.name = "sys_sendmmsg",
		.nargs = 4,
		.argt = argt_374,
		.argsz = argsz_374,
		.noreturn = false
	},
	[375] = {
		.no = 375,
		.name = "sys_setns",
		.nargs = 2,
		.argt = argt_375,
		.argsz = argsz_375,
		.noreturn = false
	},
	[376] = {
		.no = 376,
		.name = "sys_process_vm_readv",
		.nargs = 6,
		.argt = argt_376,
		.argsz = argsz_376,
		.noreturn = false
	},
	[377] = {
		.no = 377,
		.name = "sys_process_vm_writev",
		.nargs = 6,
		.argt = argt_377,
		.argsz = argsz_377,
		.noreturn = false
	},
	[378] = {
		.no = 378,
		.name = "sys_kcmp",
		.nargs = 5,
		.argt = argt_378,
		.argsz = argsz_378,
		.noreturn = false
	},
	[379] = {
		.no = 379,
		.name = "sys_finit_module",
		.nargs = 3,
		.argt = argt_379,
		.argsz = argsz_379,
		.noreturn = false
	},
	[380] = {
		.no = 380,
		.name = "sys_sched_setattr",
		.nargs = 3,
		.argt = argt_380,
		.argsz = argsz_380,
		.noreturn = false
	},
	[381] = {
		.no = 381,
		.name = "sys_sched_getattr",
		.nargs = 4,
		.argt = argt_381,
		.argsz = argsz_381,
		.noreturn = false
	},
	[382] = {
		.no = 382,
		.name = "sys_renameat2",
		.nargs = 5,
		.argt = argt_382,
		.argsz = argsz_382,
		.noreturn = false
	},
	[383] = {
		.no = 383,
		.name = "sys_seccomp",
		.nargs = 3,
		.argt = argt_383,
		.argsz = argsz_383,
		.noreturn = false
	},
	[384] = {
		.no = 384,
		.name = "sys_getrandom",
		.nargs = 3,
		.argt = argt_384,
		.argsz = argsz_384,
		.noreturn = false
	},
	[385] = {
		.no = 385,
		.name = "sys_memfd_create",
		.nargs = 2,
		.argt = argt_385,
		.argsz = argsz_385,
		.noreturn = false
	},
	[386] = {
		.no = 386,
		.name = "sys_bpf",
		.nargs = 3,
		.argt = argt_386,
		.argsz = argsz_386,
		.noreturn = false
	},
	[387] = {
		.no = 387,
		.name = "sys_execveat",
		.nargs = 5,
		.argt = argt_387,
		.argsz = argsz_387,
		.noreturn = false
	},
	[388] = {
		.no = 388,
		.name = "sys_userfaultfd",
		.nargs = 1,
		.argt = argt_388,
		.argsz = argsz_388,
		.noreturn = false
	},
	[389] = {
		.no = 389,
		.name = "sys_membarrier",
		.nargs = 2,
		.argt = argt_389,
		.argsz = argsz_389,
		.noreturn = false
	},
	[390] = {
		.no = 390,
		.name = "sys_mlock2",
		.nargs = 3,
		.argt = argt_390,
		.argsz = argsz_390,
		.noreturn = false
	},
	/* skipping non generic system call 983041 (ARM_breakpoint) */
	/* skipping non generic system call 983042 (ARM_cacheflush) */
	/* skipping non generic system call 983043 (ARM_user26_mode) */
	/* skipping non generic system call 983044 (ARM_usr32_mode) */
	/* skipping non generic system call 983045 (ARM_set_tls) */
	
};

syscall_meta_t __syscall_meta = {
	.max = MAX_SYSCALL_NO,
	.max_generic = MAX_SYSCALL_GENERIC_NO,
	.max_args = MAX_SYSCALL_ARGS
};

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=c: */