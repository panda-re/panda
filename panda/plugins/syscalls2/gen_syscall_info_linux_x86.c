#include <stdint.h>
#include "syscalls2_info.h"
#define MAX_SYSCALL_NO 348
#define MAX_SYSCALL_GENERIC_NO 348
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
static syscall_argtype_t argt_1[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_1[] = {sizeof(int32_t)};
static syscall_argtype_t argt_2[] = {};
static uint8_t argsz_2[] = {};
static syscall_argtype_t argt_3[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_3[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_4[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_5[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_5[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_6[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_6[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_7[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_7[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_8[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_8[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_9[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_9[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_10[] = {SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_10[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_11[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_11[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_12[] = {SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_12[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_13[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_13[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_14[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE};
static uint8_t argsz_14[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_15[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE};
static uint8_t argsz_15[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_16[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_16[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_18[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER};
static uint8_t argsz_18[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_19[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_19[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_20[] = {};
static uint8_t argsz_20[] = {};
static syscall_argtype_t argt_21[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_21[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_22[] = {SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_22[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_23[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_23[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_24[] = {};
static uint8_t argsz_24[] = {};
static syscall_argtype_t argt_25[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_25[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_26[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_26[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_27[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_27[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_28[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_28[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_29[] = {};
static uint8_t argsz_29[] = {};
static syscall_argtype_t argt_30[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER};
static uint8_t argsz_30[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_33[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_33[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_34[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_34[] = {sizeof(int32_t)};
static syscall_argtype_t argt_36[] = {};
static uint8_t argsz_36[] = {};
static syscall_argtype_t argt_37[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_37[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_38[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_38[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_39[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_39[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_40[] = {SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_40[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_41[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_41[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_42[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_42[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_43[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_43[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_45[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_45[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_46[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_46[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_47[] = {};
static uint8_t argsz_47[] = {};
static syscall_argtype_t argt_48[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_48[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_49[] = {};
static uint8_t argsz_49[] = {};
static syscall_argtype_t argt_50[] = {};
static uint8_t argsz_50[] = {};
static syscall_argtype_t argt_51[] = {SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_51[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_52[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_52[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_54[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_54[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_55[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_55[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_57[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_57[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_59[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_59[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_60[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_60[] = {sizeof(int32_t)};
static syscall_argtype_t argt_61[] = {SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_61[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_62[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_62[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_63[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_63[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_64[] = {};
static uint8_t argsz_64[] = {};
static syscall_argtype_t argt_65[] = {};
static uint8_t argsz_65[] = {};
static syscall_argtype_t argt_66[] = {};
static uint8_t argsz_66[] = {};
static syscall_argtype_t argt_67[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_67[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_68[] = {};
static uint8_t argsz_68[] = {};
static syscall_argtype_t argt_69[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_69[] = {sizeof(int32_t)};
static syscall_argtype_t argt_70[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_70[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_71[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_71[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_72[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_72[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_73[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_73[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_74[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_74[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_75[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_75[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_76[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_76[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_77[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_77[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_78[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_78[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_79[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_79[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_80[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_80[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_81[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_81[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_82[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_82[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_83[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_83[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_84[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER};
static uint8_t argsz_84[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_85[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_85[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_86[] = {SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_86[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_87[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_87[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_88[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_88[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_89[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_89[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_90[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_90[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_91[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_91[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_92[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_92[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_93[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_93[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_94[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_94[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_95[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_95[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_96[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_96[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_97[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_97[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_99[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER};
static uint8_t argsz_99[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_100[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_100[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_101[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_101[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_102[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_102[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_103[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_103[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_104[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_104[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_105[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_105[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_106[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER};
static uint8_t argsz_106[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_107[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER};
static uint8_t argsz_107[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_108[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_108[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_109[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_109[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_110[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_110[] = {sizeof(int32_t)};
static syscall_argtype_t argt_111[] = {};
static uint8_t argsz_111[] = {};
static syscall_argtype_t argt_113[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_113[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_114[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_114[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_115[] = {SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_115[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_116[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_116[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_117[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_117[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_118[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_118[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_119[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_119[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_120[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_120[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_121[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_121[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_122[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_122[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_123[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_123[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_124[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_124[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_125[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_125[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_126[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_126[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_128[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_128[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_129[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE};
static uint8_t argsz_129[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_131[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_131[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_132[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_132[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_133[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_133[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_134[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_134[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_135[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_135[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_136[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_136[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_138[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_138[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_139[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_139[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_140[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_140[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_141[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_141[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_142[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_142[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_143[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_143[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_144[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_144[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_145[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_145[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_146[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_146[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_147[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_147[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_148[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_148[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_149[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_149[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_150[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_150[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_151[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_151[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_152[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_152[] = {sizeof(int32_t)};
static syscall_argtype_t argt_153[] = {};
static uint8_t argsz_153[] = {};
static syscall_argtype_t argt_154[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_154[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_155[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_155[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_156[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_156[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_157[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_157[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_158[] = {};
static uint8_t argsz_158[] = {};
static syscall_argtype_t argt_159[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_159[] = {sizeof(int32_t)};
static syscall_argtype_t argt_160[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_160[] = {sizeof(int32_t)};
static syscall_argtype_t argt_161[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_161[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_162[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_162[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_163[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_163[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_164[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_164[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_165[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_165[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_166[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_166[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_168[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_168[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_170[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_170[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_171[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_171[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_172[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_172[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_173[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_173[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_174[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_174[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_175[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_175[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_176[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_176[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_177[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_177[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_178[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_178[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_179[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_179[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_180[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_8BYTE};
static uint8_t argsz_180[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_181[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_8BYTE};
static uint8_t argsz_181[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_182[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_182[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_183[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_183[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_184[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_184[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_185[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_185[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_186[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_186[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_187[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_187[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_190[] = {};
static uint8_t argsz_190[] = {};
static syscall_argtype_t argt_191[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_191[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_192[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_192[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_193[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_8BYTE};
static uint8_t argsz_193[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_194[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_8BYTE};
static uint8_t argsz_194[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_195[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER};
static uint8_t argsz_195[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_196[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER};
static uint8_t argsz_196[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_197[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_197[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_198[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_198[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_199[] = {};
static uint8_t argsz_199[] = {};
static syscall_argtype_t argt_200[] = {};
static uint8_t argsz_200[] = {};
static syscall_argtype_t argt_201[] = {};
static uint8_t argsz_201[] = {};
static syscall_argtype_t argt_202[] = {};
static uint8_t argsz_202[] = {};
static syscall_argtype_t argt_203[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_203[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_204[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_204[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_205[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_205[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_206[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_206[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_207[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_207[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_208[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_208[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_209[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_209[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_210[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_210[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_211[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_211[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_212[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_212[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_213[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_213[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_214[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_214[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_215[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_215[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_216[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_216[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_217[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_217[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_218[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_218[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_219[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_219[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_220[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_220[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_221[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_221[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_224[] = {};
static uint8_t argsz_224[] = {};
static syscall_argtype_t argt_225[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_8BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_225[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_226[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_226[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_227[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_227[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_228[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_228[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_229[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_229[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_230[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_230[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_231[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_231[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_232[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE};
static uint8_t argsz_232[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_233[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE};
static uint8_t argsz_233[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_234[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE};
static uint8_t argsz_234[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_235[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_235[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_236[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_236[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_237[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_237[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_238[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_238[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_239[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_239[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_240[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_240[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_241[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_241[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_242[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_242[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_243[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_243[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_244[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_244[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_245[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_245[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_246[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_246[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_247[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_247[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_248[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_248[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_249[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_249[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_250[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_8BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_250[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_252[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_252[] = {sizeof(int32_t)};
static syscall_argtype_t argt_253[] = {SYSCALL_ARG_8BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_253[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_254[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_254[] = {sizeof(int32_t)};
static syscall_argtype_t argt_255[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_255[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_256[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_256[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_257[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_257[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_258[] = {SYSCALL_ARG_POINTER};
static uint8_t argsz_258[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_259[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_259[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_260[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_260[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_261[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_261[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_262[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_262[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_263[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_263[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_264[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_264[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_265[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_265[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_266[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_266[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_267[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_267[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_268[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_268[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_269[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_269[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_270[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_270[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_271[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER};
static uint8_t argsz_271[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_272[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_8BYTE, SYSCALL_ARG_8BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_272[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_274[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_274[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_275[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_275[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_276[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_276[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_277[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_277[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_278[] = {SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_278[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_279[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_279[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_280[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_280[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_281[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_281[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_282[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_282[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_283[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_283[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_284[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_284[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_286[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_286[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_287[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE};
static uint8_t argsz_287[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_288[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_288[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_289[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_289[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_290[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_290[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_291[] = {};
static uint8_t argsz_291[] = {};
static syscall_argtype_t argt_292[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE};
static uint8_t argsz_292[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_293[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_293[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_294[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_294[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_295[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_295[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_296[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_296[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_297[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE};
static uint8_t argsz_297[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_298[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_298[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_299[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER};
static uint8_t argsz_299[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_300[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_300[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_301[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_301[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_302[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_302[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_303[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_303[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_304[] = {SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_304[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_305[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_305[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_306[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4BYTE};
static uint8_t argsz_306[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_307[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_307[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_308[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_308[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_309[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_309[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_310[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_310[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_311[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_311[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_312[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_312[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_313[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_313[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_314[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_8BYTE, SYSCALL_ARG_8BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_314[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_315[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_315[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_316[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_316[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_317[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_317[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_318[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_318[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_319[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_319[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_320[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_320[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_321[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE};
static uint8_t argsz_321[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_322[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_322[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_323[] = {SYSCALL_ARG_4BYTE};
static uint8_t argsz_323[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_324[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_8BYTE, SYSCALL_ARG_8BYTE};
static uint8_t argsz_324[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_325[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_325[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_326[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_326[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_327[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_327[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_328[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_328[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_329[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_329[] = {sizeof(int32_t)};
static syscall_argtype_t argt_330[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_330[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_331[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_331[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_332[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_332[] = {sizeof(int32_t)};
static syscall_argtype_t argt_333[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_333[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_334[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_334[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_335[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER};
static uint8_t argsz_335[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_336[] = {SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE};
static uint8_t argsz_336[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_337[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_337[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_338[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_338[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_339[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4BYTE, SYSCALL_ARG_8BYTE, SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR};
static uint8_t argsz_339[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_340[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER};
static uint8_t argsz_340[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_341[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_CHAR_STAR, SYSCALL_ARG_POINTER, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_341[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_342[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_342[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_343[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER};
static uint8_t argsz_343[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_344[] = {SYSCALL_ARG_4SIGNED};
static uint8_t argsz_344[] = {sizeof(int32_t)};
static syscall_argtype_t argt_345[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_345[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_346[] = {SYSCALL_ARG_4SIGNED, SYSCALL_ARG_4SIGNED};
static uint8_t argsz_346[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_347[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_347[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_348[] = {SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_POINTER, SYSCALL_ARG_4BYTE, SYSCALL_ARG_4BYTE};
static uint8_t argsz_348[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};


syscall_info_t __syscall_info_a[] = {
	/* note that uninitialized values will be zeroed-out */
	[0] = {
		.no = 0,
		.name = "sys_restart_syscall",
		.nargs = 0,
		.argt = argt_0,
		.argsz = argsz_0
	},
	[1] = {
		.no = 1,
		.name = "sys_exit",
		.nargs = 1,
		.argt = argt_1,
		.argsz = argsz_1
	},
	[2] = {
		.no = 2,
		.name = "sys_fork",
		.nargs = 0,
		.argt = argt_2,
		.argsz = argsz_2
	},
	[3] = {
		.no = 3,
		.name = "sys_read",
		.nargs = 3,
		.argt = argt_3,
		.argsz = argsz_3
	},
	[4] = {
		.no = 4,
		.name = "sys_write",
		.nargs = 3,
		.argt = argt_4,
		.argsz = argsz_4
	},
	[5] = {
		.no = 5,
		.name = "sys_open",
		.nargs = 3,
		.argt = argt_5,
		.argsz = argsz_5
	},
	[6] = {
		.no = 6,
		.name = "sys_close",
		.nargs = 1,
		.argt = argt_6,
		.argsz = argsz_6
	},
	[7] = {
		.no = 7,
		.name = "sys_waitpid",
		.nargs = 3,
		.argt = argt_7,
		.argsz = argsz_7
	},
	[8] = {
		.no = 8,
		.name = "sys_creat",
		.nargs = 2,
		.argt = argt_8,
		.argsz = argsz_8
	},
	[9] = {
		.no = 9,
		.name = "sys_link",
		.nargs = 2,
		.argt = argt_9,
		.argsz = argsz_9
	},
	[10] = {
		.no = 10,
		.name = "sys_unlink",
		.nargs = 1,
		.argt = argt_10,
		.argsz = argsz_10
	},
	[11] = {
		.no = 11,
		.name = "sys_execve",
		.nargs = 3,
		.argt = argt_11,
		.argsz = argsz_11
	},
	[12] = {
		.no = 12,
		.name = "sys_chdir",
		.nargs = 1,
		.argt = argt_12,
		.argsz = argsz_12
	},
	[13] = {
		.no = 13,
		.name = "sys_time",
		.nargs = 1,
		.argt = argt_13,
		.argsz = argsz_13
	},
	[14] = {
		.no = 14,
		.name = "sys_mknod",
		.nargs = 3,
		.argt = argt_14,
		.argsz = argsz_14
	},
	[15] = {
		.no = 15,
		.name = "sys_chmod",
		.nargs = 2,
		.argt = argt_15,
		.argsz = argsz_15
	},
	[16] = {
		.no = 16,
		.name = "sys_lchown16",
		.nargs = 3,
		.argt = argt_16,
		.argsz = argsz_16
	},
	[18] = {
		.no = 18,
		.name = "sys_stat",
		.nargs = 2,
		.argt = argt_18,
		.argsz = argsz_18
	},
	[19] = {
		.no = 19,
		.name = "sys_lseek",
		.nargs = 3,
		.argt = argt_19,
		.argsz = argsz_19
	},
	[20] = {
		.no = 20,
		.name = "sys_getpid",
		.nargs = 0,
		.argt = argt_20,
		.argsz = argsz_20
	},
	[21] = {
		.no = 21,
		.name = "sys_mount",
		.nargs = 5,
		.argt = argt_21,
		.argsz = argsz_21
	},
	[22] = {
		.no = 22,
		.name = "sys_oldumount",
		.nargs = 1,
		.argt = argt_22,
		.argsz = argsz_22
	},
	[23] = {
		.no = 23,
		.name = "sys_setuid16",
		.nargs = 1,
		.argt = argt_23,
		.argsz = argsz_23
	},
	[24] = {
		.no = 24,
		.name = "sys_getuid16",
		.nargs = 0,
		.argt = argt_24,
		.argsz = argsz_24
	},
	[25] = {
		.no = 25,
		.name = "sys_stime",
		.nargs = 1,
		.argt = argt_25,
		.argsz = argsz_25
	},
	[26] = {
		.no = 26,
		.name = "sys_ptrace",
		.nargs = 4,
		.argt = argt_26,
		.argsz = argsz_26
	},
	[27] = {
		.no = 27,
		.name = "sys_alarm",
		.nargs = 1,
		.argt = argt_27,
		.argsz = argsz_27
	},
	[28] = {
		.no = 28,
		.name = "sys_fstat",
		.nargs = 2,
		.argt = argt_28,
		.argsz = argsz_28
	},
	[29] = {
		.no = 29,
		.name = "sys_pause",
		.nargs = 0,
		.argt = argt_29,
		.argsz = argsz_29
	},
	[30] = {
		.no = 30,
		.name = "sys_utime",
		.nargs = 2,
		.argt = argt_30,
		.argsz = argsz_30
	},
	[33] = {
		.no = 33,
		.name = "sys_access",
		.nargs = 2,
		.argt = argt_33,
		.argsz = argsz_33
	},
	[34] = {
		.no = 34,
		.name = "sys_nice",
		.nargs = 1,
		.argt = argt_34,
		.argsz = argsz_34
	},
	[36] = {
		.no = 36,
		.name = "sys_sync",
		.nargs = 0,
		.argt = argt_36,
		.argsz = argsz_36
	},
	[37] = {
		.no = 37,
		.name = "sys_kill",
		.nargs = 2,
		.argt = argt_37,
		.argsz = argsz_37
	},
	[38] = {
		.no = 38,
		.name = "sys_rename",
		.nargs = 2,
		.argt = argt_38,
		.argsz = argsz_38
	},
	[39] = {
		.no = 39,
		.name = "sys_mkdir",
		.nargs = 2,
		.argt = argt_39,
		.argsz = argsz_39
	},
	[40] = {
		.no = 40,
		.name = "sys_rmdir",
		.nargs = 1,
		.argt = argt_40,
		.argsz = argsz_40
	},
	[41] = {
		.no = 41,
		.name = "sys_dup",
		.nargs = 1,
		.argt = argt_41,
		.argsz = argsz_41
	},
	[42] = {
		.no = 42,
		.name = "sys_pipe",
		.nargs = 1,
		.argt = argt_42,
		.argsz = argsz_42
	},
	[43] = {
		.no = 43,
		.name = "sys_times",
		.nargs = 1,
		.argt = argt_43,
		.argsz = argsz_43
	},
	[45] = {
		.no = 45,
		.name = "sys_brk",
		.nargs = 1,
		.argt = argt_45,
		.argsz = argsz_45
	},
	[46] = {
		.no = 46,
		.name = "sys_setgid16",
		.nargs = 1,
		.argt = argt_46,
		.argsz = argsz_46
	},
	[47] = {
		.no = 47,
		.name = "sys_getgid16",
		.nargs = 0,
		.argt = argt_47,
		.argsz = argsz_47
	},
	[48] = {
		.no = 48,
		.name = "sys_signal",
		.nargs = 2,
		.argt = argt_48,
		.argsz = argsz_48
	},
	[49] = {
		.no = 49,
		.name = "sys_geteuid16",
		.nargs = 0,
		.argt = argt_49,
		.argsz = argsz_49
	},
	[50] = {
		.no = 50,
		.name = "sys_getegid16",
		.nargs = 0,
		.argt = argt_50,
		.argsz = argsz_50
	},
	[51] = {
		.no = 51,
		.name = "sys_acct",
		.nargs = 1,
		.argt = argt_51,
		.argsz = argsz_51
	},
	[52] = {
		.no = 52,
		.name = "sys_umount",
		.nargs = 2,
		.argt = argt_52,
		.argsz = argsz_52
	},
	[54] = {
		.no = 54,
		.name = "sys_ioctl",
		.nargs = 3,
		.argt = argt_54,
		.argsz = argsz_54
	},
	[55] = {
		.no = 55,
		.name = "sys_fcntl",
		.nargs = 3,
		.argt = argt_55,
		.argsz = argsz_55
	},
	[57] = {
		.no = 57,
		.name = "sys_setpgid",
		.nargs = 2,
		.argt = argt_57,
		.argsz = argsz_57
	},
	[59] = {
		.no = 59,
		.name = "sys_olduname",
		.nargs = 1,
		.argt = argt_59,
		.argsz = argsz_59
	},
	[60] = {
		.no = 60,
		.name = "sys_umask",
		.nargs = 1,
		.argt = argt_60,
		.argsz = argsz_60
	},
	[61] = {
		.no = 61,
		.name = "sys_chroot",
		.nargs = 1,
		.argt = argt_61,
		.argsz = argsz_61
	},
	[62] = {
		.no = 62,
		.name = "sys_ustat",
		.nargs = 2,
		.argt = argt_62,
		.argsz = argsz_62
	},
	[63] = {
		.no = 63,
		.name = "sys_dup2",
		.nargs = 2,
		.argt = argt_63,
		.argsz = argsz_63
	},
	[64] = {
		.no = 64,
		.name = "sys_getppid",
		.nargs = 0,
		.argt = argt_64,
		.argsz = argsz_64
	},
	[65] = {
		.no = 65,
		.name = "sys_getpgrp",
		.nargs = 0,
		.argt = argt_65,
		.argsz = argsz_65
	},
	[66] = {
		.no = 66,
		.name = "sys_setsid",
		.nargs = 0,
		.argt = argt_66,
		.argsz = argsz_66
	},
	[67] = {
		.no = 67,
		.name = "sigaction",
		.nargs = 3,
		.argt = argt_67,
		.argsz = argsz_67
	},
	[68] = {
		.no = 68,
		.name = "sys_sgetmask",
		.nargs = 0,
		.argt = argt_68,
		.argsz = argsz_68
	},
	[69] = {
		.no = 69,
		.name = "sys_ssetmask",
		.nargs = 1,
		.argt = argt_69,
		.argsz = argsz_69
	},
	[70] = {
		.no = 70,
		.name = "sys_setreuid16",
		.nargs = 2,
		.argt = argt_70,
		.argsz = argsz_70
	},
	[71] = {
		.no = 71,
		.name = "sys_setregid16",
		.nargs = 2,
		.argt = argt_71,
		.argsz = argsz_71
	},
	[72] = {
		.no = 72,
		.name = "sigsuspend",
		.nargs = 3,
		.argt = argt_72,
		.argsz = argsz_72
	},
	[73] = {
		.no = 73,
		.name = "sys_sigpending",
		.nargs = 1,
		.argt = argt_73,
		.argsz = argsz_73
	},
	[74] = {
		.no = 74,
		.name = "sys_sethostname",
		.nargs = 2,
		.argt = argt_74,
		.argsz = argsz_74
	},
	[75] = {
		.no = 75,
		.name = "sys_setrlimit",
		.nargs = 2,
		.argt = argt_75,
		.argsz = argsz_75
	},
	[76] = {
		.no = 76,
		.name = "sys_old_getrlimit",
		.nargs = 2,
		.argt = argt_76,
		.argsz = argsz_76
	},
	[77] = {
		.no = 77,
		.name = "sys_getrusage",
		.nargs = 2,
		.argt = argt_77,
		.argsz = argsz_77
	},
	[78] = {
		.no = 78,
		.name = "sys_gettimeofday",
		.nargs = 2,
		.argt = argt_78,
		.argsz = argsz_78
	},
	[79] = {
		.no = 79,
		.name = "sys_settimeofday",
		.nargs = 2,
		.argt = argt_79,
		.argsz = argsz_79
	},
	[80] = {
		.no = 80,
		.name = "sys_getgroups16",
		.nargs = 2,
		.argt = argt_80,
		.argsz = argsz_80
	},
	[81] = {
		.no = 81,
		.name = "sys_setgroups16",
		.nargs = 2,
		.argt = argt_81,
		.argsz = argsz_81
	},
	[82] = {
		.no = 82,
		.name = "sys_old_select",
		.nargs = 1,
		.argt = argt_82,
		.argsz = argsz_82
	},
	[83] = {
		.no = 83,
		.name = "sys_symlink",
		.nargs = 2,
		.argt = argt_83,
		.argsz = argsz_83
	},
	[84] = {
		.no = 84,
		.name = "sys_lstat",
		.nargs = 2,
		.argt = argt_84,
		.argsz = argsz_84
	},
	[85] = {
		.no = 85,
		.name = "sys_readlink",
		.nargs = 3,
		.argt = argt_85,
		.argsz = argsz_85
	},
	[86] = {
		.no = 86,
		.name = "sys_uselib",
		.nargs = 1,
		.argt = argt_86,
		.argsz = argsz_86
	},
	[87] = {
		.no = 87,
		.name = "sys_swapon",
		.nargs = 2,
		.argt = argt_87,
		.argsz = argsz_87
	},
	[88] = {
		.no = 88,
		.name = "sys_reboot",
		.nargs = 4,
		.argt = argt_88,
		.argsz = argsz_88
	},
	[89] = {
		.no = 89,
		.name = "sys_old_readdir",
		.nargs = 3,
		.argt = argt_89,
		.argsz = argsz_89
	},
	[90] = {
		.no = 90,
		.name = "sys_old_mmap",
		.nargs = 1,
		.argt = argt_90,
		.argsz = argsz_90
	},
	[91] = {
		.no = 91,
		.name = "sys_munmap",
		.nargs = 2,
		.argt = argt_91,
		.argsz = argsz_91
	},
	[92] = {
		.no = 92,
		.name = "sys_truncate",
		.nargs = 2,
		.argt = argt_92,
		.argsz = argsz_92
	},
	[93] = {
		.no = 93,
		.name = "sys_ftruncate",
		.nargs = 2,
		.argt = argt_93,
		.argsz = argsz_93
	},
	[94] = {
		.no = 94,
		.name = "sys_fchmod",
		.nargs = 2,
		.argt = argt_94,
		.argsz = argsz_94
	},
	[95] = {
		.no = 95,
		.name = "sys_fchown16",
		.nargs = 3,
		.argt = argt_95,
		.argsz = argsz_95
	},
	[96] = {
		.no = 96,
		.name = "sys_getpriority",
		.nargs = 2,
		.argt = argt_96,
		.argsz = argsz_96
	},
	[97] = {
		.no = 97,
		.name = "sys_setpriority",
		.nargs = 3,
		.argt = argt_97,
		.argsz = argsz_97
	},
	[99] = {
		.no = 99,
		.name = "sys_statfs",
		.nargs = 2,
		.argt = argt_99,
		.argsz = argsz_99
	},
	[100] = {
		.no = 100,
		.name = "sys_fstatfs",
		.nargs = 2,
		.argt = argt_100,
		.argsz = argsz_100
	},
	[101] = {
		.no = 101,
		.name = "sys_ioperm",
		.nargs = 3,
		.argt = argt_101,
		.argsz = argsz_101
	},
	[102] = {
		.no = 102,
		.name = "sys_socketcall",
		.nargs = 2,
		.argt = argt_102,
		.argsz = argsz_102
	},
	[103] = {
		.no = 103,
		.name = "sys_syslog",
		.nargs = 3,
		.argt = argt_103,
		.argsz = argsz_103
	},
	[104] = {
		.no = 104,
		.name = "sys_setitimer",
		.nargs = 3,
		.argt = argt_104,
		.argsz = argsz_104
	},
	[105] = {
		.no = 105,
		.name = "sys_getitimer",
		.nargs = 2,
		.argt = argt_105,
		.argsz = argsz_105
	},
	[106] = {
		.no = 106,
		.name = "sys_newstat",
		.nargs = 2,
		.argt = argt_106,
		.argsz = argsz_106
	},
	[107] = {
		.no = 107,
		.name = "sys_newlstat",
		.nargs = 2,
		.argt = argt_107,
		.argsz = argsz_107
	},
	[108] = {
		.no = 108,
		.name = "sys_newfstat",
		.nargs = 2,
		.argt = argt_108,
		.argsz = argsz_108
	},
	[109] = {
		.no = 109,
		.name = "sys_uname",
		.nargs = 1,
		.argt = argt_109,
		.argsz = argsz_109
	},
	[110] = {
		.no = 110,
		.name = "sys_iopl",
		.nargs = 1,
		.argt = argt_110,
		.argsz = argsz_110
	},
	[111] = {
		.no = 111,
		.name = "sys_vhangup",
		.nargs = 0,
		.argt = argt_111,
		.argsz = argsz_111
	},
	[113] = {
		.no = 113,
		.name = "sys_vm86old",
		.nargs = 1,
		.argt = argt_113,
		.argsz = argsz_113
	},
	[114] = {
		.no = 114,
		.name = "sys_wait4",
		.nargs = 4,
		.argt = argt_114,
		.argsz = argsz_114
	},
	[115] = {
		.no = 115,
		.name = "sys_swapoff",
		.nargs = 1,
		.argt = argt_115,
		.argsz = argsz_115
	},
	[116] = {
		.no = 116,
		.name = "sys_sysinfo",
		.nargs = 1,
		.argt = argt_116,
		.argsz = argsz_116
	},
	[117] = {
		.no = 117,
		.name = "sys_ipc",
		.nargs = 6,
		.argt = argt_117,
		.argsz = argsz_117
	},
	[118] = {
		.no = 118,
		.name = "sys_fsync",
		.nargs = 1,
		.argt = argt_118,
		.argsz = argsz_118
	},
	[119] = {
		.no = 119,
		.name = "sys_sigreturn",
		.nargs = 1,
		.argt = argt_119,
		.argsz = argsz_119
	},
	[120] = {
		.no = 120,
		.name = "sys_clone",
		.nargs = 5,
		.argt = argt_120,
		.argsz = argsz_120
	},
	[121] = {
		.no = 121,
		.name = "sys_setdomainname",
		.nargs = 2,
		.argt = argt_121,
		.argsz = argsz_121
	},
	[122] = {
		.no = 122,
		.name = "sys_newuname",
		.nargs = 1,
		.argt = argt_122,
		.argsz = argsz_122
	},
	[123] = {
		.no = 123,
		.name = "sys_modify_ldt",
		.nargs = 3,
		.argt = argt_123,
		.argsz = argsz_123
	},
	[124] = {
		.no = 124,
		.name = "sys_adjtimex",
		.nargs = 1,
		.argt = argt_124,
		.argsz = argsz_124
	},
	[125] = {
		.no = 125,
		.name = "sys_mprotect",
		.nargs = 3,
		.argt = argt_125,
		.argsz = argsz_125
	},
	[126] = {
		.no = 126,
		.name = "sys_sigprocmask",
		.nargs = 3,
		.argt = argt_126,
		.argsz = argsz_126
	},
	[128] = {
		.no = 128,
		.name = "sys_init_module",
		.nargs = 3,
		.argt = argt_128,
		.argsz = argsz_128
	},
	[129] = {
		.no = 129,
		.name = "sys_delete_module",
		.nargs = 2,
		.argt = argt_129,
		.argsz = argsz_129
	},
	[131] = {
		.no = 131,
		.name = "sys_quotactl",
		.nargs = 4,
		.argt = argt_131,
		.argsz = argsz_131
	},
	[132] = {
		.no = 132,
		.name = "sys_getpgid",
		.nargs = 1,
		.argt = argt_132,
		.argsz = argsz_132
	},
	[133] = {
		.no = 133,
		.name = "sys_fchdir",
		.nargs = 1,
		.argt = argt_133,
		.argsz = argsz_133
	},
	[134] = {
		.no = 134,
		.name = "sys_bdflush",
		.nargs = 2,
		.argt = argt_134,
		.argsz = argsz_134
	},
	[135] = {
		.no = 135,
		.name = "sys_sysfs",
		.nargs = 3,
		.argt = argt_135,
		.argsz = argsz_135
	},
	[136] = {
		.no = 136,
		.name = "sys_personality",
		.nargs = 1,
		.argt = argt_136,
		.argsz = argsz_136
	},
	[138] = {
		.no = 138,
		.name = "sys_setfsuid16",
		.nargs = 1,
		.argt = argt_138,
		.argsz = argsz_138
	},
	[139] = {
		.no = 139,
		.name = "sys_setfsgid16",
		.nargs = 1,
		.argt = argt_139,
		.argsz = argsz_139
	},
	[140] = {
		.no = 140,
		.name = "sys_llseek",
		.nargs = 5,
		.argt = argt_140,
		.argsz = argsz_140
	},
	[141] = {
		.no = 141,
		.name = "sys_getdents",
		.nargs = 3,
		.argt = argt_141,
		.argsz = argsz_141
	},
	[142] = {
		.no = 142,
		.name = "sys_select",
		.nargs = 5,
		.argt = argt_142,
		.argsz = argsz_142
	},
	[143] = {
		.no = 143,
		.name = "sys_flock",
		.nargs = 2,
		.argt = argt_143,
		.argsz = argsz_143
	},
	[144] = {
		.no = 144,
		.name = "sys_msync",
		.nargs = 3,
		.argt = argt_144,
		.argsz = argsz_144
	},
	[145] = {
		.no = 145,
		.name = "sys_readv",
		.nargs = 3,
		.argt = argt_145,
		.argsz = argsz_145
	},
	[146] = {
		.no = 146,
		.name = "sys_writev",
		.nargs = 3,
		.argt = argt_146,
		.argsz = argsz_146
	},
	[147] = {
		.no = 147,
		.name = "sys_getsid",
		.nargs = 1,
		.argt = argt_147,
		.argsz = argsz_147
	},
	[148] = {
		.no = 148,
		.name = "sys_fdatasync",
		.nargs = 1,
		.argt = argt_148,
		.argsz = argsz_148
	},
	[149] = {
		.no = 149,
		.name = "sys_sysctl",
		.nargs = 1,
		.argt = argt_149,
		.argsz = argsz_149
	},
	[150] = {
		.no = 150,
		.name = "sys_mlock",
		.nargs = 2,
		.argt = argt_150,
		.argsz = argsz_150
	},
	[151] = {
		.no = 151,
		.name = "sys_munlock",
		.nargs = 2,
		.argt = argt_151,
		.argsz = argsz_151
	},
	[152] = {
		.no = 152,
		.name = "sys_mlockall",
		.nargs = 1,
		.argt = argt_152,
		.argsz = argsz_152
	},
	[153] = {
		.no = 153,
		.name = "sys_munlockall",
		.nargs = 0,
		.argt = argt_153,
		.argsz = argsz_153
	},
	[154] = {
		.no = 154,
		.name = "sys_sched_setparam",
		.nargs = 2,
		.argt = argt_154,
		.argsz = argsz_154
	},
	[155] = {
		.no = 155,
		.name = "sys_sched_getparam",
		.nargs = 2,
		.argt = argt_155,
		.argsz = argsz_155
	},
	[156] = {
		.no = 156,
		.name = "sys_sched_setscheduler",
		.nargs = 3,
		.argt = argt_156,
		.argsz = argsz_156
	},
	[157] = {
		.no = 157,
		.name = "sys_sched_getscheduler",
		.nargs = 1,
		.argt = argt_157,
		.argsz = argsz_157
	},
	[158] = {
		.no = 158,
		.name = "sys_sched_yield",
		.nargs = 0,
		.argt = argt_158,
		.argsz = argsz_158
	},
	[159] = {
		.no = 159,
		.name = "sys_sched_get_priority_max",
		.nargs = 1,
		.argt = argt_159,
		.argsz = argsz_159
	},
	[160] = {
		.no = 160,
		.name = "sys_sched_get_priority_min",
		.nargs = 1,
		.argt = argt_160,
		.argsz = argsz_160
	},
	[161] = {
		.no = 161,
		.name = "sys_sched_rr_get_interval",
		.nargs = 2,
		.argt = argt_161,
		.argsz = argsz_161
	},
	[162] = {
		.no = 162,
		.name = "sys_nanosleep",
		.nargs = 2,
		.argt = argt_162,
		.argsz = argsz_162
	},
	[163] = {
		.no = 163,
		.name = "sys_mremap",
		.nargs = 5,
		.argt = argt_163,
		.argsz = argsz_163
	},
	[164] = {
		.no = 164,
		.name = "sys_setresuid16",
		.nargs = 3,
		.argt = argt_164,
		.argsz = argsz_164
	},
	[165] = {
		.no = 165,
		.name = "sys_getresuid16",
		.nargs = 3,
		.argt = argt_165,
		.argsz = argsz_165
	},
	[166] = {
		.no = 166,
		.name = "sys_vm86",
		.nargs = 2,
		.argt = argt_166,
		.argsz = argsz_166
	},
	[168] = {
		.no = 168,
		.name = "sys_poll",
		.nargs = 3,
		.argt = argt_168,
		.argsz = argsz_168
	},
	[170] = {
		.no = 170,
		.name = "sys_setresgid16",
		.nargs = 3,
		.argt = argt_170,
		.argsz = argsz_170
	},
	[171] = {
		.no = 171,
		.name = "sys_getresgid16",
		.nargs = 3,
		.argt = argt_171,
		.argsz = argsz_171
	},
	[172] = {
		.no = 172,
		.name = "sys_prctl",
		.nargs = 5,
		.argt = argt_172,
		.argsz = argsz_172
	},
	[173] = {
		.no = 173,
		.name = "sys_rt_sigreturn",
		.nargs = 1,
		.argt = argt_173,
		.argsz = argsz_173
	},
	[174] = {
		.no = 174,
		.name = "rt_sigaction",
		.nargs = 4,
		.argt = argt_174,
		.argsz = argsz_174
	},
	[175] = {
		.no = 175,
		.name = "sys_rt_sigprocmask",
		.nargs = 4,
		.argt = argt_175,
		.argsz = argsz_175
	},
	[176] = {
		.no = 176,
		.name = "sys_rt_sigpending",
		.nargs = 2,
		.argt = argt_176,
		.argsz = argsz_176
	},
	[177] = {
		.no = 177,
		.name = "sys_rt_sigtimedwait",
		.nargs = 4,
		.argt = argt_177,
		.argsz = argsz_177
	},
	[178] = {
		.no = 178,
		.name = "sys_rt_sigqueueinfo",
		.nargs = 3,
		.argt = argt_178,
		.argsz = argsz_178
	},
	[179] = {
		.no = 179,
		.name = "sys_rt_sigsuspend",
		.nargs = 2,
		.argt = argt_179,
		.argsz = argsz_179
	},
	[180] = {
		.no = 180,
		.name = "sys_pread64",
		.nargs = 4,
		.argt = argt_180,
		.argsz = argsz_180
	},
	[181] = {
		.no = 181,
		.name = "sys_pwrite64",
		.nargs = 4,
		.argt = argt_181,
		.argsz = argsz_181
	},
	[182] = {
		.no = 182,
		.name = "sys_chown16",
		.nargs = 3,
		.argt = argt_182,
		.argsz = argsz_182
	},
	[183] = {
		.no = 183,
		.name = "sys_getcwd",
		.nargs = 2,
		.argt = argt_183,
		.argsz = argsz_183
	},
	[184] = {
		.no = 184,
		.name = "sys_capget",
		.nargs = 2,
		.argt = argt_184,
		.argsz = argsz_184
	},
	[185] = {
		.no = 185,
		.name = "sys_capset",
		.nargs = 2,
		.argt = argt_185,
		.argsz = argsz_185
	},
	[186] = {
		.no = 186,
		.name = "sys_sigaltstack",
		.nargs = 2,
		.argt = argt_186,
		.argsz = argsz_186
	},
	[187] = {
		.no = 187,
		.name = "sys_sendfile",
		.nargs = 4,
		.argt = argt_187,
		.argsz = argsz_187
	},
	[190] = {
		.no = 190,
		.name = "sys_vfork",
		.nargs = 0,
		.argt = argt_190,
		.argsz = argsz_190
	},
	[191] = {
		.no = 191,
		.name = "sys_getrlimit",
		.nargs = 2,
		.argt = argt_191,
		.argsz = argsz_191
	},
	[192] = {
		.no = 192,
		.name = "sys_mmap_pgoff",
		.nargs = 6,
		.argt = argt_192,
		.argsz = argsz_192
	},
	[193] = {
		.no = 193,
		.name = "sys_truncate64",
		.nargs = 2,
		.argt = argt_193,
		.argsz = argsz_193
	},
	[194] = {
		.no = 194,
		.name = "sys_ftruncate64",
		.nargs = 2,
		.argt = argt_194,
		.argsz = argsz_194
	},
	[195] = {
		.no = 195,
		.name = "sys_stat64",
		.nargs = 2,
		.argt = argt_195,
		.argsz = argsz_195
	},
	[196] = {
		.no = 196,
		.name = "sys_lstat64",
		.nargs = 2,
		.argt = argt_196,
		.argsz = argsz_196
	},
	[197] = {
		.no = 197,
		.name = "sys_fstat64",
		.nargs = 2,
		.argt = argt_197,
		.argsz = argsz_197
	},
	[198] = {
		.no = 198,
		.name = "sys_lchown",
		.nargs = 3,
		.argt = argt_198,
		.argsz = argsz_198
	},
	[199] = {
		.no = 199,
		.name = "sys_getuid",
		.nargs = 0,
		.argt = argt_199,
		.argsz = argsz_199
	},
	[200] = {
		.no = 200,
		.name = "sys_getgid",
		.nargs = 0,
		.argt = argt_200,
		.argsz = argsz_200
	},
	[201] = {
		.no = 201,
		.name = "sys_geteuid",
		.nargs = 0,
		.argt = argt_201,
		.argsz = argsz_201
	},
	[202] = {
		.no = 202,
		.name = "sys_getegid",
		.nargs = 0,
		.argt = argt_202,
		.argsz = argsz_202
	},
	[203] = {
		.no = 203,
		.name = "sys_setreuid",
		.nargs = 2,
		.argt = argt_203,
		.argsz = argsz_203
	},
	[204] = {
		.no = 204,
		.name = "sys_setregid",
		.nargs = 2,
		.argt = argt_204,
		.argsz = argsz_204
	},
	[205] = {
		.no = 205,
		.name = "sys_getgroups",
		.nargs = 2,
		.argt = argt_205,
		.argsz = argsz_205
	},
	[206] = {
		.no = 206,
		.name = "sys_setgroups",
		.nargs = 2,
		.argt = argt_206,
		.argsz = argsz_206
	},
	[207] = {
		.no = 207,
		.name = "sys_fchown",
		.nargs = 3,
		.argt = argt_207,
		.argsz = argsz_207
	},
	[208] = {
		.no = 208,
		.name = "sys_setresuid",
		.nargs = 3,
		.argt = argt_208,
		.argsz = argsz_208
	},
	[209] = {
		.no = 209,
		.name = "sys_getresuid",
		.nargs = 3,
		.argt = argt_209,
		.argsz = argsz_209
	},
	[210] = {
		.no = 210,
		.name = "sys_setresgid",
		.nargs = 3,
		.argt = argt_210,
		.argsz = argsz_210
	},
	[211] = {
		.no = 211,
		.name = "sys_getresgid",
		.nargs = 3,
		.argt = argt_211,
		.argsz = argsz_211
	},
	[212] = {
		.no = 212,
		.name = "sys_chown",
		.nargs = 3,
		.argt = argt_212,
		.argsz = argsz_212
	},
	[213] = {
		.no = 213,
		.name = "sys_setuid",
		.nargs = 1,
		.argt = argt_213,
		.argsz = argsz_213
	},
	[214] = {
		.no = 214,
		.name = "sys_setgid",
		.nargs = 1,
		.argt = argt_214,
		.argsz = argsz_214
	},
	[215] = {
		.no = 215,
		.name = "sys_setfsuid",
		.nargs = 1,
		.argt = argt_215,
		.argsz = argsz_215
	},
	[216] = {
		.no = 216,
		.name = "sys_setfsgid",
		.nargs = 1,
		.argt = argt_216,
		.argsz = argsz_216
	},
	[217] = {
		.no = 217,
		.name = "sys_pivot_root",
		.nargs = 2,
		.argt = argt_217,
		.argsz = argsz_217
	},
	[218] = {
		.no = 218,
		.name = "sys_mincore",
		.nargs = 3,
		.argt = argt_218,
		.argsz = argsz_218
	},
	[219] = {
		.no = 219,
		.name = "sys_madvise",
		.nargs = 3,
		.argt = argt_219,
		.argsz = argsz_219
	},
	[220] = {
		.no = 220,
		.name = "sys_getdents64",
		.nargs = 3,
		.argt = argt_220,
		.argsz = argsz_220
	},
	[221] = {
		.no = 221,
		.name = "sys_fcntl64",
		.nargs = 3,
		.argt = argt_221,
		.argsz = argsz_221
	},
	[224] = {
		.no = 224,
		.name = "sys_gettid",
		.nargs = 0,
		.argt = argt_224,
		.argsz = argsz_224
	},
	[225] = {
		.no = 225,
		.name = "sys_readahead",
		.nargs = 3,
		.argt = argt_225,
		.argsz = argsz_225
	},
	[226] = {
		.no = 226,
		.name = "sys_setxattr",
		.nargs = 5,
		.argt = argt_226,
		.argsz = argsz_226
	},
	[227] = {
		.no = 227,
		.name = "sys_lsetxattr",
		.nargs = 5,
		.argt = argt_227,
		.argsz = argsz_227
	},
	[228] = {
		.no = 228,
		.name = "sys_fsetxattr",
		.nargs = 5,
		.argt = argt_228,
		.argsz = argsz_228
	},
	[229] = {
		.no = 229,
		.name = "sys_getxattr",
		.nargs = 4,
		.argt = argt_229,
		.argsz = argsz_229
	},
	[230] = {
		.no = 230,
		.name = "sys_lgetxattr",
		.nargs = 4,
		.argt = argt_230,
		.argsz = argsz_230
	},
	[231] = {
		.no = 231,
		.name = "sys_fgetxattr",
		.nargs = 4,
		.argt = argt_231,
		.argsz = argsz_231
	},
	[232] = {
		.no = 232,
		.name = "sys_listxattr",
		.nargs = 3,
		.argt = argt_232,
		.argsz = argsz_232
	},
	[233] = {
		.no = 233,
		.name = "sys_llistxattr",
		.nargs = 3,
		.argt = argt_233,
		.argsz = argsz_233
	},
	[234] = {
		.no = 234,
		.name = "sys_flistxattr",
		.nargs = 3,
		.argt = argt_234,
		.argsz = argsz_234
	},
	[235] = {
		.no = 235,
		.name = "sys_removexattr",
		.nargs = 2,
		.argt = argt_235,
		.argsz = argsz_235
	},
	[236] = {
		.no = 236,
		.name = "sys_lremovexattr",
		.nargs = 2,
		.argt = argt_236,
		.argsz = argsz_236
	},
	[237] = {
		.no = 237,
		.name = "sys_fremovexattr",
		.nargs = 2,
		.argt = argt_237,
		.argsz = argsz_237
	},
	[238] = {
		.no = 238,
		.name = "sys_tkill",
		.nargs = 2,
		.argt = argt_238,
		.argsz = argsz_238
	},
	[239] = {
		.no = 239,
		.name = "sys_sendfile64",
		.nargs = 4,
		.argt = argt_239,
		.argsz = argsz_239
	},
	[240] = {
		.no = 240,
		.name = "sys_futex",
		.nargs = 6,
		.argt = argt_240,
		.argsz = argsz_240
	},
	[241] = {
		.no = 241,
		.name = "sys_sched_setaffinity",
		.nargs = 3,
		.argt = argt_241,
		.argsz = argsz_241
	},
	[242] = {
		.no = 242,
		.name = "sys_sched_getaffinity",
		.nargs = 3,
		.argt = argt_242,
		.argsz = argsz_242
	},
	[243] = {
		.no = 243,
		.name = "set_thread_area",
		.nargs = 1,
		.argt = argt_243,
		.argsz = argsz_243
	},
	[244] = {
		.no = 244,
		.name = "get_thread_area",
		.nargs = 1,
		.argt = argt_244,
		.argsz = argsz_244
	},
	[245] = {
		.no = 245,
		.name = "sys_io_setup",
		.nargs = 2,
		.argt = argt_245,
		.argsz = argsz_245
	},
	[246] = {
		.no = 246,
		.name = "sys_io_destroy",
		.nargs = 1,
		.argt = argt_246,
		.argsz = argsz_246
	},
	[247] = {
		.no = 247,
		.name = "sys_io_getevents",
		.nargs = 5,
		.argt = argt_247,
		.argsz = argsz_247
	},
	[248] = {
		.no = 248,
		.name = "sys_io_submit",
		.nargs = 3,
		.argt = argt_248,
		.argsz = argsz_248
	},
	[249] = {
		.no = 249,
		.name = "sys_io_cancel",
		.nargs = 3,
		.argt = argt_249,
		.argsz = argsz_249
	},
	[250] = {
		.no = 250,
		.name = "sys_fadvise64",
		.nargs = 4,
		.argt = argt_250,
		.argsz = argsz_250
	},
	[252] = {
		.no = 252,
		.name = "sys_exit_group",
		.nargs = 1,
		.argt = argt_252,
		.argsz = argsz_252
	},
	[253] = {
		.no = 253,
		.name = "sys_lookup_dcookie",
		.nargs = 3,
		.argt = argt_253,
		.argsz = argsz_253
	},
	[254] = {
		.no = 254,
		.name = "sys_epoll_create",
		.nargs = 1,
		.argt = argt_254,
		.argsz = argsz_254
	},
	[255] = {
		.no = 255,
		.name = "sys_epoll_ctl",
		.nargs = 4,
		.argt = argt_255,
		.argsz = argsz_255
	},
	[256] = {
		.no = 256,
		.name = "sys_epoll_wait",
		.nargs = 4,
		.argt = argt_256,
		.argsz = argsz_256
	},
	[257] = {
		.no = 257,
		.name = "sys_remap_file_pages",
		.nargs = 5,
		.argt = argt_257,
		.argsz = argsz_257
	},
	[258] = {
		.no = 258,
		.name = "sys_set_tid_address",
		.nargs = 1,
		.argt = argt_258,
		.argsz = argsz_258
	},
	[259] = {
		.no = 259,
		.name = "sys_timer_create",
		.nargs = 3,
		.argt = argt_259,
		.argsz = argsz_259
	},
	[260] = {
		.no = 260,
		.name = "sys_timer_settime",
		.nargs = 4,
		.argt = argt_260,
		.argsz = argsz_260
	},
	[261] = {
		.no = 261,
		.name = "sys_timer_gettime",
		.nargs = 2,
		.argt = argt_261,
		.argsz = argsz_261
	},
	[262] = {
		.no = 262,
		.name = "sys_timer_getoverrun",
		.nargs = 1,
		.argt = argt_262,
		.argsz = argsz_262
	},
	[263] = {
		.no = 263,
		.name = "sys_timer_delete",
		.nargs = 1,
		.argt = argt_263,
		.argsz = argsz_263
	},
	[264] = {
		.no = 264,
		.name = "sys_clock_settime",
		.nargs = 2,
		.argt = argt_264,
		.argsz = argsz_264
	},
	[265] = {
		.no = 265,
		.name = "sys_clock_gettime",
		.nargs = 2,
		.argt = argt_265,
		.argsz = argsz_265
	},
	[266] = {
		.no = 266,
		.name = "sys_clock_getres",
		.nargs = 2,
		.argt = argt_266,
		.argsz = argsz_266
	},
	[267] = {
		.no = 267,
		.name = "sys_clock_nanosleep",
		.nargs = 4,
		.argt = argt_267,
		.argsz = argsz_267
	},
	[268] = {
		.no = 268,
		.name = "sys_statfs64",
		.nargs = 3,
		.argt = argt_268,
		.argsz = argsz_268
	},
	[269] = {
		.no = 269,
		.name = "sys_fstatfs64",
		.nargs = 3,
		.argt = argt_269,
		.argsz = argsz_269
	},
	[270] = {
		.no = 270,
		.name = "sys_tgkill",
		.nargs = 3,
		.argt = argt_270,
		.argsz = argsz_270
	},
	[271] = {
		.no = 271,
		.name = "sys_utimes",
		.nargs = 2,
		.argt = argt_271,
		.argsz = argsz_271
	},
	[272] = {
		.no = 272,
		.name = "sys_fadvise64_64",
		.nargs = 4,
		.argt = argt_272,
		.argsz = argsz_272
	},
	[274] = {
		.no = 274,
		.name = "sys_mbind",
		.nargs = 6,
		.argt = argt_274,
		.argsz = argsz_274
	},
	[275] = {
		.no = 275,
		.name = "sys_get_mempolicy",
		.nargs = 5,
		.argt = argt_275,
		.argsz = argsz_275
	},
	[276] = {
		.no = 276,
		.name = "sys_set_mempolicy",
		.nargs = 3,
		.argt = argt_276,
		.argsz = argsz_276
	},
	[277] = {
		.no = 277,
		.name = "sys_mq_open",
		.nargs = 4,
		.argt = argt_277,
		.argsz = argsz_277
	},
	[278] = {
		.no = 278,
		.name = "sys_mq_unlink",
		.nargs = 1,
		.argt = argt_278,
		.argsz = argsz_278
	},
	[279] = {
		.no = 279,
		.name = "sys_mq_timedsend",
		.nargs = 5,
		.argt = argt_279,
		.argsz = argsz_279
	},
	[280] = {
		.no = 280,
		.name = "sys_mq_timedreceive",
		.nargs = 5,
		.argt = argt_280,
		.argsz = argsz_280
	},
	[281] = {
		.no = 281,
		.name = "sys_mq_notify",
		.nargs = 2,
		.argt = argt_281,
		.argsz = argsz_281
	},
	[282] = {
		.no = 282,
		.name = "sys_mq_getsetattr",
		.nargs = 3,
		.argt = argt_282,
		.argsz = argsz_282
	},
	[283] = {
		.no = 283,
		.name = "sys_kexec_load",
		.nargs = 4,
		.argt = argt_283,
		.argsz = argsz_283
	},
	[284] = {
		.no = 284,
		.name = "sys_waitid",
		.nargs = 5,
		.argt = argt_284,
		.argsz = argsz_284
	},
	[286] = {
		.no = 286,
		.name = "sys_add_key",
		.nargs = 5,
		.argt = argt_286,
		.argsz = argsz_286
	},
	[287] = {
		.no = 287,
		.name = "sys_request_key",
		.nargs = 4,
		.argt = argt_287,
		.argsz = argsz_287
	},
	[288] = {
		.no = 288,
		.name = "sys_keyctl",
		.nargs = 5,
		.argt = argt_288,
		.argsz = argsz_288
	},
	[289] = {
		.no = 289,
		.name = "sys_ioprio_set",
		.nargs = 3,
		.argt = argt_289,
		.argsz = argsz_289
	},
	[290] = {
		.no = 290,
		.name = "sys_ioprio_get",
		.nargs = 2,
		.argt = argt_290,
		.argsz = argsz_290
	},
	[291] = {
		.no = 291,
		.name = "sys_inotify_init",
		.nargs = 0,
		.argt = argt_291,
		.argsz = argsz_291
	},
	[292] = {
		.no = 292,
		.name = "sys_inotify_add_watch",
		.nargs = 3,
		.argt = argt_292,
		.argsz = argsz_292
	},
	[293] = {
		.no = 293,
		.name = "sys_inotify_rm_watch",
		.nargs = 2,
		.argt = argt_293,
		.argsz = argsz_293
	},
	[294] = {
		.no = 294,
		.name = "sys_migrate_pages",
		.nargs = 4,
		.argt = argt_294,
		.argsz = argsz_294
	},
	[295] = {
		.no = 295,
		.name = "sys_openat",
		.nargs = 4,
		.argt = argt_295,
		.argsz = argsz_295
	},
	[296] = {
		.no = 296,
		.name = "sys_mkdirat",
		.nargs = 3,
		.argt = argt_296,
		.argsz = argsz_296
	},
	[297] = {
		.no = 297,
		.name = "sys_mknodat",
		.nargs = 4,
		.argt = argt_297,
		.argsz = argsz_297
	},
	[298] = {
		.no = 298,
		.name = "sys_fchownat",
		.nargs = 5,
		.argt = argt_298,
		.argsz = argsz_298
	},
	[299] = {
		.no = 299,
		.name = "sys_futimesat",
		.nargs = 3,
		.argt = argt_299,
		.argsz = argsz_299
	},
	[300] = {
		.no = 300,
		.name = "sys_fstatat64",
		.nargs = 4,
		.argt = argt_300,
		.argsz = argsz_300
	},
	[301] = {
		.no = 301,
		.name = "sys_unlinkat",
		.nargs = 3,
		.argt = argt_301,
		.argsz = argsz_301
	},
	[302] = {
		.no = 302,
		.name = "sys_renameat",
		.nargs = 4,
		.argt = argt_302,
		.argsz = argsz_302
	},
	[303] = {
		.no = 303,
		.name = "sys_linkat",
		.nargs = 5,
		.argt = argt_303,
		.argsz = argsz_303
	},
	[304] = {
		.no = 304,
		.name = "sys_symlinkat",
		.nargs = 3,
		.argt = argt_304,
		.argsz = argsz_304
	},
	[305] = {
		.no = 305,
		.name = "sys_readlinkat",
		.nargs = 4,
		.argt = argt_305,
		.argsz = argsz_305
	},
	[306] = {
		.no = 306,
		.name = "sys_fchmodat",
		.nargs = 3,
		.argt = argt_306,
		.argsz = argsz_306
	},
	[307] = {
		.no = 307,
		.name = "sys_faccessat",
		.nargs = 3,
		.argt = argt_307,
		.argsz = argsz_307
	},
	[308] = {
		.no = 308,
		.name = "sys_pselect6",
		.nargs = 6,
		.argt = argt_308,
		.argsz = argsz_308
	},
	[309] = {
		.no = 309,
		.name = "sys_ppoll",
		.nargs = 5,
		.argt = argt_309,
		.argsz = argsz_309
	},
	[310] = {
		.no = 310,
		.name = "sys_unshare",
		.nargs = 1,
		.argt = argt_310,
		.argsz = argsz_310
	},
	[311] = {
		.no = 311,
		.name = "sys_set_robust_list",
		.nargs = 2,
		.argt = argt_311,
		.argsz = argsz_311
	},
	[312] = {
		.no = 312,
		.name = "sys_get_robust_list",
		.nargs = 3,
		.argt = argt_312,
		.argsz = argsz_312
	},
	[313] = {
		.no = 313,
		.name = "sys_splice",
		.nargs = 6,
		.argt = argt_313,
		.argsz = argsz_313
	},
	[314] = {
		.no = 314,
		.name = "sys_sync_file_range",
		.nargs = 4,
		.argt = argt_314,
		.argsz = argsz_314
	},
	[315] = {
		.no = 315,
		.name = "sys_tee",
		.nargs = 4,
		.argt = argt_315,
		.argsz = argsz_315
	},
	[316] = {
		.no = 316,
		.name = "sys_vmsplice",
		.nargs = 4,
		.argt = argt_316,
		.argsz = argsz_316
	},
	[317] = {
		.no = 317,
		.name = "sys_move_pages",
		.nargs = 6,
		.argt = argt_317,
		.argsz = argsz_317
	},
	[318] = {
		.no = 318,
		.name = "sys_getcpu",
		.nargs = 3,
		.argt = argt_318,
		.argsz = argsz_318
	},
	[319] = {
		.no = 319,
		.name = "sys_epoll_pwait",
		.nargs = 6,
		.argt = argt_319,
		.argsz = argsz_319
	},
	[320] = {
		.no = 320,
		.name = "sys_utimensat",
		.nargs = 4,
		.argt = argt_320,
		.argsz = argsz_320
	},
	[321] = {
		.no = 321,
		.name = "sys_signalfd",
		.nargs = 3,
		.argt = argt_321,
		.argsz = argsz_321
	},
	[322] = {
		.no = 322,
		.name = "sys_timerfd_create",
		.nargs = 2,
		.argt = argt_322,
		.argsz = argsz_322
	},
	[323] = {
		.no = 323,
		.name = "sys_eventfd",
		.nargs = 1,
		.argt = argt_323,
		.argsz = argsz_323
	},
	[324] = {
		.no = 324,
		.name = "sys_fallocate",
		.nargs = 4,
		.argt = argt_324,
		.argsz = argsz_324
	},
	[325] = {
		.no = 325,
		.name = "sys_timerfd_settime",
		.nargs = 4,
		.argt = argt_325,
		.argsz = argsz_325
	},
	[326] = {
		.no = 326,
		.name = "sys_timerfd_gettime",
		.nargs = 2,
		.argt = argt_326,
		.argsz = argsz_326
	},
	[327] = {
		.no = 327,
		.name = "sys_signalfd4",
		.nargs = 4,
		.argt = argt_327,
		.argsz = argsz_327
	},
	[328] = {
		.no = 328,
		.name = "sys_eventfd2",
		.nargs = 2,
		.argt = argt_328,
		.argsz = argsz_328
	},
	[329] = {
		.no = 329,
		.name = "sys_epoll_create1",
		.nargs = 1,
		.argt = argt_329,
		.argsz = argsz_329
	},
	[330] = {
		.no = 330,
		.name = "sys_dup3",
		.nargs = 3,
		.argt = argt_330,
		.argsz = argsz_330
	},
	[331] = {
		.no = 331,
		.name = "sys_pipe2",
		.nargs = 2,
		.argt = argt_331,
		.argsz = argsz_331
	},
	[332] = {
		.no = 332,
		.name = "sys_inotify_init1",
		.nargs = 1,
		.argt = argt_332,
		.argsz = argsz_332
	},
	[333] = {
		.no = 333,
		.name = "sys_preadv",
		.nargs = 5,
		.argt = argt_333,
		.argsz = argsz_333
	},
	[334] = {
		.no = 334,
		.name = "sys_pwritev",
		.nargs = 5,
		.argt = argt_334,
		.argsz = argsz_334
	},
	[335] = {
		.no = 335,
		.name = "sys_rt_tgsigqueueinfo",
		.nargs = 4,
		.argt = argt_335,
		.argsz = argsz_335
	},
	[336] = {
		.no = 336,
		.name = "sys_perf_event_open",
		.nargs = 5,
		.argt = argt_336,
		.argsz = argsz_336
	},
	[337] = {
		.no = 337,
		.name = "sys_recvmmsg",
		.nargs = 5,
		.argt = argt_337,
		.argsz = argsz_337
	},
	[338] = {
		.no = 338,
		.name = "sys_fanotify_init",
		.nargs = 2,
		.argt = argt_338,
		.argsz = argsz_338
	},
	[339] = {
		.no = 339,
		.name = "sys_fanotify_mark",
		.nargs = 5,
		.argt = argt_339,
		.argsz = argsz_339
	},
	[340] = {
		.no = 340,
		.name = "sys_prlimit64",
		.nargs = 4,
		.argt = argt_340,
		.argsz = argsz_340
	},
	[341] = {
		.no = 341,
		.name = "sys_name_to_handle_at",
		.nargs = 5,
		.argt = argt_341,
		.argsz = argsz_341
	},
	[342] = {
		.no = 342,
		.name = "sys_open_by_handle_at",
		.nargs = 3,
		.argt = argt_342,
		.argsz = argsz_342
	},
	[343] = {
		.no = 343,
		.name = "sys_clock_adjtime",
		.nargs = 2,
		.argt = argt_343,
		.argsz = argsz_343
	},
	[344] = {
		.no = 344,
		.name = "sys_syncfs",
		.nargs = 1,
		.argt = argt_344,
		.argsz = argsz_344
	},
	[345] = {
		.no = 345,
		.name = "sys_sendmmsg",
		.nargs = 4,
		.argt = argt_345,
		.argsz = argsz_345
	},
	[346] = {
		.no = 346,
		.name = "sys_setns",
		.nargs = 2,
		.argt = argt_346,
		.argsz = argsz_346
	},
	[347] = {
		.no = 347,
		.name = "sys_process_vm_readv",
		.nargs = 6,
		.argt = argt_347,
		.argsz = argsz_347
	},
	[348] = {
		.no = 348,
		.name = "sys_process_vm_writev",
		.nargs = 6,
		.argt = argt_348,
		.argsz = argsz_348
	},
	
};

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=c: */