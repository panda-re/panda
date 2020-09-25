#include <stdint.h>
#include <stdbool.h>
#include "../syscalls2_info.h"
#define MAX_SYSCALL_NO 4439
#define MAX_SYSCALL_GENERIC_NO 4439
#define MAX_SYSCALL_ARGS 6

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

static syscall_argtype_t argt_4001[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4001[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4002[] = {};
static uint8_t argsz_4002[] = {};
static syscall_argtype_t argt_4003[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4003[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4004[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4004[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4005[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_4005[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4006[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4006[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4007[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4007[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4008[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4008[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4009[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_4009[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4010[] = {SYSCALL_ARG_STR};
static uint8_t argsz_4010[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4011[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_4011[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4012[] = {SYSCALL_ARG_STR};
static uint8_t argsz_4012[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4013[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4013[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4014[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4014[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4015[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4015[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4016[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4016[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4018[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_4018[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4019[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4019[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4020[] = {};
static uint8_t argsz_4020[] = {};
static syscall_argtype_t argt_4021[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4021[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4022[] = {SYSCALL_ARG_STR};
static uint8_t argsz_4022[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4023[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4023[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4024[] = {};
static uint8_t argsz_4024[] = {};
static syscall_argtype_t argt_4025[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4025[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4026[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4026[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4027[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4027[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4028[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4028[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4029[] = {};
static uint8_t argsz_4029[] = {};
static syscall_argtype_t argt_4030[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_4030[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4033[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4033[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4034[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4034[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4036[] = {};
static uint8_t argsz_4036[] = {};
static syscall_argtype_t argt_4037[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4037[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4038[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_4038[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4039[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4039[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4040[] = {SYSCALL_ARG_STR};
static uint8_t argsz_4040[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4041[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4041[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4042[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4042[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4043[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4043[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4045[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4045[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4046[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4046[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4047[] = {};
static uint8_t argsz_4047[] = {};
static syscall_argtype_t argt_4048[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4048[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4049[] = {};
static uint8_t argsz_4049[] = {};
static syscall_argtype_t argt_4050[] = {};
static uint8_t argsz_4050[] = {};
static syscall_argtype_t argt_4051[] = {SYSCALL_ARG_STR};
static uint8_t argsz_4051[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4052[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4052[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4054[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4054[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4055[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4055[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4057[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4057[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4059[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4059[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4060[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4060[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4061[] = {SYSCALL_ARG_STR};
static uint8_t argsz_4061[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4062[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4062[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4063[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4063[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4064[] = {};
static uint8_t argsz_4064[] = {};
static syscall_argtype_t argt_4065[] = {};
static uint8_t argsz_4065[] = {};
static syscall_argtype_t argt_4066[] = {};
static uint8_t argsz_4066[] = {};
static syscall_argtype_t argt_4067[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4067[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4068[] = {};
static uint8_t argsz_4068[] = {};
static syscall_argtype_t argt_4069[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4069[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4070[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4070[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4071[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4071[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4072[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_4072[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4073[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4073[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4074[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4074[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4075[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4075[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4076[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4076[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4077[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4077[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4078[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4078[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4079[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4079[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4080[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4080[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4081[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4081[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4083[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_4083[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4084[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_4084[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4085[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4085[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4086[] = {SYSCALL_ARG_STR};
static uint8_t argsz_4086[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4087[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4087[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4088[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4088[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4089[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4089[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4090[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4090[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4091[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4091[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4092[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4092[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4093[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4093[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4094[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4094[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4095[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4095[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4096[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4096[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4097[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4097[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4099[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_4099[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4100[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4100[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4101[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4101[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4102[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4102[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4103[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4103[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4104[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4104[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4105[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4105[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4106[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_4106[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4107[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_4107[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4108[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4108[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4109[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4109[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4110[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4110[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4111[] = {};
static uint8_t argsz_4111[] = {};
static syscall_argtype_t argt_4112[] = {};
static uint8_t argsz_4112[] = {};
static syscall_argtype_t argt_4114[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4114[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4115[] = {SYSCALL_ARG_STR};
static uint8_t argsz_4115[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4116[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4116[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4117[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4117[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4118[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4118[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4119[] = {};
static uint8_t argsz_4119[] = {};
static syscall_argtype_t argt_4120[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4120[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4121[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4121[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4122[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4122[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4123[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4123[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4124[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4124[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4125[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4125[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4126[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4126[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4127[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4127[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4128[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_STR};
static uint8_t argsz_4128[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4129[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4129[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4130[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4130[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4131[] = {SYSCALL_ARG_U32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4131[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4132[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4132[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4133[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4133[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4134[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4134[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4135[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4135[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4136[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4136[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4138[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4138[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4139[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4139[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4140[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4140[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4141[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4141[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4142[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4142[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4143[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4143[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4144[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4144[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4145[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4145[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4146[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4146[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4147[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4147[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4150[] = {};
static uint8_t argsz_4150[] = {};
static syscall_argtype_t argt_4151[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4151[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4152[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4152[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4153[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4153[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4154[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4154[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4155[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4155[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4156[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4156[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4157[] = {};
static uint8_t argsz_4157[] = {};
static syscall_argtype_t argt_4158[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4158[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4159[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4159[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4160[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4160[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4161[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4161[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4162[] = {};
static uint8_t argsz_4162[] = {};
static syscall_argtype_t argt_4163[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4163[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4164[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4164[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4165[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4165[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4166[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4166[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4167[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4167[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4168[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4168[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4169[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4169[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4170[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4170[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4171[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4171[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4172[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4172[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4173[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_4173[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4174[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4174[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4175[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4175[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4176[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4176[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4177[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4177[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4178[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4178[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4179[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4179[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4180[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4180[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4181[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4181[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4182[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4182[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4183[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4183[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4184[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4184[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4185[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4185[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4186[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4186[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4187[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4187[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4188[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4188[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4189[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4189[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4190[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4190[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4191[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4191[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4192[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4192[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4193[] = {};
static uint8_t argsz_4193[] = {};
static syscall_argtype_t argt_4194[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4194[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4195[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4195[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4196[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4196[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4197[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4197[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4198[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4198[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4199[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4199[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4200[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U64};
static uint8_t argsz_4200[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_4201[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U64};
static uint8_t argsz_4201[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_4202[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4202[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4203[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4203[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4204[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4204[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4205[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4205[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4206[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4206[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4207[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4207[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4210[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_4210[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4211[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U64};
static uint8_t argsz_4211[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_4212[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U64};
static uint8_t argsz_4212[] = {sizeof(uint32_t), sizeof(uint64_t)};
static syscall_argtype_t argt_4213[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_4213[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4214[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_4214[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4215[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4215[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4216[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_4216[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4217[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_STR};
static uint8_t argsz_4217[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4218[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4218[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4219[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4219[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4220[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4220[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4222[] = {};
static uint8_t argsz_4222[] = {};
static syscall_argtype_t argt_4223[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U64, SYSCALL_ARG_U32};
static uint8_t argsz_4223[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4224[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4224[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4225[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4225[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4226[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4226[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4227[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4227[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4228[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4228[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4229[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4229[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4230[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4230[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4231[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4231[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4232[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4232[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4233[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_4233[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4234[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR};
static uint8_t argsz_4234[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4235[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_4235[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4236[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4236[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4237[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4237[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4238[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4238[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4239[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4239[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4240[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4240[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4241[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4241[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4242[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4242[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4243[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4243[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4244[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4244[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4245[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4245[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4246[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4246[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4247[] = {SYSCALL_ARG_U64, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4247[] = {sizeof(uint64_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4248[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4248[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4249[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4249[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4250[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4250[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4251[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4251[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4252[] = {SYSCALL_ARG_PTR};
static uint8_t argsz_4252[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4253[] = {};
static uint8_t argsz_4253[] = {};
static syscall_argtype_t argt_4254[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U64, SYSCALL_ARG_U64, SYSCALL_ARG_S32};
static uint8_t argsz_4254[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(int32_t)};
static syscall_argtype_t argt_4255[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4255[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4256[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4256[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4257[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4257[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4258[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4258[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4259[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4259[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4260[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4260[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4261[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4261[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4262[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4262[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4263[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4263[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4264[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4264[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4265[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4265[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4266[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4266[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4267[] = {SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_4267[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4268[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4268[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4269[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4269[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4270[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4270[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4271[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4271[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4272[] = {SYSCALL_ARG_STR};
static uint8_t argsz_4272[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4273[] = {SYSCALL_ARG_U32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4273[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4274[] = {SYSCALL_ARG_U32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4274[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4275[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4275[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4276[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4276[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4278[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4278[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4280[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4280[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4281[] = {SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4281[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4282[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4282[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4283[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4283[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4284[] = {};
static uint8_t argsz_4284[] = {};
static syscall_argtype_t argt_4285[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4285[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4286[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4286[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4287[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4287[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4288[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_4288[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4289[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4289[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4290[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4290[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4291[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4291[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4292[] = {SYSCALL_ARG_U32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR};
static uint8_t argsz_4292[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4293[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4293[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4294[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4294[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4295[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_4295[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4296[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4296[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4297[] = {SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_4297[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4298[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4298[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4299[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4299[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4300[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4300[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4301[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4301[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4302[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4302[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4303[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4303[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4304[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4304[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4305[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U64, SYSCALL_ARG_U64, SYSCALL_ARG_U32};
static uint8_t argsz_4305[] = {sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4306[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4306[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4307[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4307[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4308[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4308[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4309[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4309[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4310[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4310[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4311[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4311[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4312[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4312[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4313[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4313[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4314[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4314[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4315[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4315[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4316[] = {SYSCALL_ARG_U32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4316[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4317[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4317[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4318[] = {};
static uint8_t argsz_4318[] = {};
static syscall_argtype_t argt_4319[] = {SYSCALL_ARG_U32};
static uint8_t argsz_4319[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4320[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U64, SYSCALL_ARG_U64};
static uint8_t argsz_4320[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint64_t), sizeof(uint64_t)};
static syscall_argtype_t argt_4321[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4321[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4322[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4322[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4323[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4323[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4324[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4324[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4325[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4325[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4326[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4326[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4327[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4327[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4328[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4328[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4329[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4329[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4330[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4330[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4331[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4331[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4332[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4332[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4333[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_4333[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4334[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4334[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4335[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4335[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4336[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4336[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4337[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U64, SYSCALL_ARG_S32, SYSCALL_ARG_STR};
static uint8_t argsz_4337[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4338[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4338[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4339[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4339[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4340[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4340[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4341[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4341[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4342[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4342[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4343[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4343[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4344[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4344[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4345[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4345[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4346[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4346[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4347[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4347[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4348[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4348[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4349[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4349[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4350[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4350[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4351[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4351[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4352[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4352[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4353[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4353[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4354[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4354[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4355[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4355[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4356[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4356[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4357[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4357[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4358[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4358[] = {sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4359[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4359[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4360[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4360[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4361[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4361[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4362[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4362[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4363[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4363[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4364[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4364[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4365[] = {SYSCALL_ARG_S32};
static uint8_t argsz_4365[] = {sizeof(int32_t)};
static syscall_argtype_t argt_4366[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4366[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4367[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4367[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4368[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4368[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4393[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4393[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4394[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_4394[] = {sizeof(int32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4395[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4395[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4396[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4396[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4397[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32};
static uint8_t argsz_4397[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4398[] = {SYSCALL_ARG_STR};
static uint8_t argsz_4398[] = {sizeof(uint32_t)};
static syscall_argtype_t argt_4399[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4399[] = {sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4400[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32};
static uint8_t argsz_4400[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4401[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4401[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4402[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4402[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4403[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4403[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4404[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4404[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4405[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4405[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4406[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4406[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4407[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4407[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4408[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4408[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4409[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4409[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4410[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4410[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4411[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4411[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4412[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4412[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4413[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4413[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4414[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4414[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4416[] = {SYSCALL_ARG_U32, SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4416[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4417[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4417[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4418[] = {SYSCALL_ARG_U32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4418[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4419[] = {SYSCALL_ARG_U32, SYSCALL_ARG_STR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR};
static uint8_t argsz_4419[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4420[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4420[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4421[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4421[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4422[] = {SYSCALL_ARG_PTR, SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4422[] = {sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4423[] = {SYSCALL_ARG_S32, SYSCALL_ARG_PTR};
static uint8_t argsz_4423[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4424[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4424[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4425[] = {SYSCALL_ARG_U32, SYSCALL_ARG_PTR};
static uint8_t argsz_4425[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4426[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4426[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4427[] = {SYSCALL_ARG_U32, SYSCALL_ARG_U32, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4427[] = {sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4428[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4428[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4429[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4429[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4430[] = {SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4430[] = {sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4431[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_S32};
static uint8_t argsz_4431[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(int32_t)};
static syscall_argtype_t argt_4432[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32, SYSCALL_ARG_U32};
static uint8_t argsz_4432[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4433[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_U32};
static uint8_t argsz_4433[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4434[] = {SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_4434[] = {sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4437[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_PTR, SYSCALL_ARG_U32};
static uint8_t argsz_4437[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4438[] = {SYSCALL_ARG_S32, SYSCALL_ARG_S32, SYSCALL_ARG_U32};
static uint8_t argsz_4438[] = {sizeof(int32_t), sizeof(int32_t), sizeof(uint32_t)};
static syscall_argtype_t argt_4439[] = {SYSCALL_ARG_S32, SYSCALL_ARG_STR, SYSCALL_ARG_S32, SYSCALL_ARG_S32};
static uint8_t argsz_4439[] = {sizeof(int32_t), sizeof(uint32_t), sizeof(int32_t), sizeof(int32_t)};


syscall_info_t __syscall_info_a[] = {
	/* note that uninitialized values will be zeroed-out */
	[4001] = {
		.no = 4001,
		.name = "sys_exit",
		.nargs = 1,
		.argt = argt_4001,
		.argsz = argsz_4001,
		.noreturn = false
	},
	[4002] = {
		.no = 4002,
		.name = "sys_fork",
		.nargs = 0,
		.argt = argt_4002,
		.argsz = argsz_4002,
		.noreturn = false
	},
	[4003] = {
		.no = 4003,
		.name = "sys_read",
		.nargs = 3,
		.argt = argt_4003,
		.argsz = argsz_4003,
		.noreturn = false
	},
	[4004] = {
		.no = 4004,
		.name = "sys_write",
		.nargs = 3,
		.argt = argt_4004,
		.argsz = argsz_4004,
		.noreturn = false
	},
	[4005] = {
		.no = 4005,
		.name = "sys_open",
		.nargs = 3,
		.argt = argt_4005,
		.argsz = argsz_4005,
		.noreturn = false
	},
	[4006] = {
		.no = 4006,
		.name = "sys_close",
		.nargs = 1,
		.argt = argt_4006,
		.argsz = argsz_4006,
		.noreturn = false
	},
	[4007] = {
		.no = 4007,
		.name = "sys_waitpid",
		.nargs = 3,
		.argt = argt_4007,
		.argsz = argsz_4007,
		.noreturn = false
	},
	[4008] = {
		.no = 4008,
		.name = "sys_creat",
		.nargs = 2,
		.argt = argt_4008,
		.argsz = argsz_4008,
		.noreturn = false
	},
	[4009] = {
		.no = 4009,
		.name = "sys_link",
		.nargs = 2,
		.argt = argt_4009,
		.argsz = argsz_4009,
		.noreturn = false
	},
	[4010] = {
		.no = 4010,
		.name = "sys_unlink",
		.nargs = 1,
		.argt = argt_4010,
		.argsz = argsz_4010,
		.noreturn = false
	},
	[4011] = {
		.no = 4011,
		.name = "sys_execve",
		.nargs = 3,
		.argt = argt_4011,
		.argsz = argsz_4011,
		.noreturn = false
	},
	[4012] = {
		.no = 4012,
		.name = "sys_chdir",
		.nargs = 1,
		.argt = argt_4012,
		.argsz = argsz_4012,
		.noreturn = false
	},
	[4013] = {
		.no = 4013,
		.name = "sys_time32",
		.nargs = 1,
		.argt = argt_4013,
		.argsz = argsz_4013,
		.noreturn = false
	},
	[4014] = {
		.no = 4014,
		.name = "sys_mknod",
		.nargs = 3,
		.argt = argt_4014,
		.argsz = argsz_4014,
		.noreturn = false
	},
	[4015] = {
		.no = 4015,
		.name = "sys_chmod",
		.nargs = 2,
		.argt = argt_4015,
		.argsz = argsz_4015,
		.noreturn = false
	},
	[4016] = {
		.no = 4016,
		.name = "sys_lchown",
		.nargs = 3,
		.argt = argt_4016,
		.argsz = argsz_4016,
		.noreturn = false
	},
	[4018] = {
		.no = 4018,
		.name = "sys_stat",
		.nargs = 2,
		.argt = argt_4018,
		.argsz = argsz_4018,
		.noreturn = false
	},
	[4019] = {
		.no = 4019,
		.name = "sys_lseek",
		.nargs = 3,
		.argt = argt_4019,
		.argsz = argsz_4019,
		.noreturn = false
	},
	[4020] = {
		.no = 4020,
		.name = "sys_getpid",
		.nargs = 0,
		.argt = argt_4020,
		.argsz = argsz_4020,
		.noreturn = false
	},
	[4021] = {
		.no = 4021,
		.name = "sys_mount",
		.nargs = 5,
		.argt = argt_4021,
		.argsz = argsz_4021,
		.noreturn = false
	},
	[4022] = {
		.no = 4022,
		.name = "sys_oldumount",
		.nargs = 1,
		.argt = argt_4022,
		.argsz = argsz_4022,
		.noreturn = false
	},
	[4023] = {
		.no = 4023,
		.name = "sys_setuid",
		.nargs = 1,
		.argt = argt_4023,
		.argsz = argsz_4023,
		.noreturn = false
	},
	[4024] = {
		.no = 4024,
		.name = "sys_getuid",
		.nargs = 0,
		.argt = argt_4024,
		.argsz = argsz_4024,
		.noreturn = false
	},
	[4025] = {
		.no = 4025,
		.name = "sys_stime32",
		.nargs = 1,
		.argt = argt_4025,
		.argsz = argsz_4025,
		.noreturn = false
	},
	[4026] = {
		.no = 4026,
		.name = "sys_ptrace",
		.nargs = 4,
		.argt = argt_4026,
		.argsz = argsz_4026,
		.noreturn = false
	},
	[4027] = {
		.no = 4027,
		.name = "sys_alarm",
		.nargs = 1,
		.argt = argt_4027,
		.argsz = argsz_4027,
		.noreturn = false
	},
	[4028] = {
		.no = 4028,
		.name = "sys_fstat",
		.nargs = 2,
		.argt = argt_4028,
		.argsz = argsz_4028,
		.noreturn = false
	},
	[4029] = {
		.no = 4029,
		.name = "sys_pause",
		.nargs = 0,
		.argt = argt_4029,
		.argsz = argsz_4029,
		.noreturn = false
	},
	[4030] = {
		.no = 4030,
		.name = "sys_utime32",
		.nargs = 2,
		.argt = argt_4030,
		.argsz = argsz_4030,
		.noreturn = false
	},
	[4033] = {
		.no = 4033,
		.name = "sys_access",
		.nargs = 2,
		.argt = argt_4033,
		.argsz = argsz_4033,
		.noreturn = false
	},
	[4034] = {
		.no = 4034,
		.name = "sys_nice",
		.nargs = 1,
		.argt = argt_4034,
		.argsz = argsz_4034,
		.noreturn = false
	},
	[4036] = {
		.no = 4036,
		.name = "sys_sync",
		.nargs = 0,
		.argt = argt_4036,
		.argsz = argsz_4036,
		.noreturn = false
	},
	[4037] = {
		.no = 4037,
		.name = "sys_kill",
		.nargs = 2,
		.argt = argt_4037,
		.argsz = argsz_4037,
		.noreturn = false
	},
	[4038] = {
		.no = 4038,
		.name = "sys_rename",
		.nargs = 2,
		.argt = argt_4038,
		.argsz = argsz_4038,
		.noreturn = false
	},
	[4039] = {
		.no = 4039,
		.name = "sys_mkdir",
		.nargs = 2,
		.argt = argt_4039,
		.argsz = argsz_4039,
		.noreturn = false
	},
	[4040] = {
		.no = 4040,
		.name = "sys_rmdir",
		.nargs = 1,
		.argt = argt_4040,
		.argsz = argsz_4040,
		.noreturn = false
	},
	[4041] = {
		.no = 4041,
		.name = "sys_dup",
		.nargs = 1,
		.argt = argt_4041,
		.argsz = argsz_4041,
		.noreturn = false
	},
	[4042] = {
		.no = 4042,
		.name = "sys_pipe",
		.nargs = 1,
		.argt = argt_4042,
		.argsz = argsz_4042,
		.noreturn = false
	},
	[4043] = {
		.no = 4043,
		.name = "sys_times",
		.nargs = 1,
		.argt = argt_4043,
		.argsz = argsz_4043,
		.noreturn = false
	},
	[4045] = {
		.no = 4045,
		.name = "sys_brk",
		.nargs = 1,
		.argt = argt_4045,
		.argsz = argsz_4045,
		.noreturn = false
	},
	[4046] = {
		.no = 4046,
		.name = "sys_setgid",
		.nargs = 1,
		.argt = argt_4046,
		.argsz = argsz_4046,
		.noreturn = false
	},
	[4047] = {
		.no = 4047,
		.name = "sys_getgid",
		.nargs = 0,
		.argt = argt_4047,
		.argsz = argsz_4047,
		.noreturn = false
	},
	[4048] = {
		.no = 4048,
		.name = "sys_signal",
		.nargs = 2,
		.argt = argt_4048,
		.argsz = argsz_4048,
		.noreturn = false
	},
	[4049] = {
		.no = 4049,
		.name = "sys_geteuid",
		.nargs = 0,
		.argt = argt_4049,
		.argsz = argsz_4049,
		.noreturn = false
	},
	[4050] = {
		.no = 4050,
		.name = "sys_getegid",
		.nargs = 0,
		.argt = argt_4050,
		.argsz = argsz_4050,
		.noreturn = false
	},
	[4051] = {
		.no = 4051,
		.name = "sys_acct",
		.nargs = 1,
		.argt = argt_4051,
		.argsz = argsz_4051,
		.noreturn = false
	},
	[4052] = {
		.no = 4052,
		.name = "sys_umount",
		.nargs = 2,
		.argt = argt_4052,
		.argsz = argsz_4052,
		.noreturn = false
	},
	[4054] = {
		.no = 4054,
		.name = "sys_ioctl",
		.nargs = 3,
		.argt = argt_4054,
		.argsz = argsz_4054,
		.noreturn = false
	},
	[4055] = {
		.no = 4055,
		.name = "sys_fcntl",
		.nargs = 3,
		.argt = argt_4055,
		.argsz = argsz_4055,
		.noreturn = false
	},
	[4057] = {
		.no = 4057,
		.name = "sys_setpgid",
		.nargs = 2,
		.argt = argt_4057,
		.argsz = argsz_4057,
		.noreturn = false
	},
	[4059] = {
		.no = 4059,
		.name = "sys_olduname",
		.nargs = 1,
		.argt = argt_4059,
		.argsz = argsz_4059,
		.noreturn = false
	},
	[4060] = {
		.no = 4060,
		.name = "sys_umask",
		.nargs = 1,
		.argt = argt_4060,
		.argsz = argsz_4060,
		.noreturn = false
	},
	[4061] = {
		.no = 4061,
		.name = "sys_chroot",
		.nargs = 1,
		.argt = argt_4061,
		.argsz = argsz_4061,
		.noreturn = false
	},
	[4062] = {
		.no = 4062,
		.name = "sys_ustat",
		.nargs = 2,
		.argt = argt_4062,
		.argsz = argsz_4062,
		.noreturn = false
	},
	[4063] = {
		.no = 4063,
		.name = "sys_dup2",
		.nargs = 2,
		.argt = argt_4063,
		.argsz = argsz_4063,
		.noreturn = false
	},
	[4064] = {
		.no = 4064,
		.name = "sys_getppid",
		.nargs = 0,
		.argt = argt_4064,
		.argsz = argsz_4064,
		.noreturn = false
	},
	[4065] = {
		.no = 4065,
		.name = "sys_getpgrp",
		.nargs = 0,
		.argt = argt_4065,
		.argsz = argsz_4065,
		.noreturn = false
	},
	[4066] = {
		.no = 4066,
		.name = "sys_setsid",
		.nargs = 0,
		.argt = argt_4066,
		.argsz = argsz_4066,
		.noreturn = false
	},
	[4067] = {
		.no = 4067,
		.name = "sys_sigaction",
		.nargs = 3,
		.argt = argt_4067,
		.argsz = argsz_4067,
		.noreturn = false
	},
	[4068] = {
		.no = 4068,
		.name = "sys_sgetmask",
		.nargs = 0,
		.argt = argt_4068,
		.argsz = argsz_4068,
		.noreturn = false
	},
	[4069] = {
		.no = 4069,
		.name = "sys_ssetmask",
		.nargs = 1,
		.argt = argt_4069,
		.argsz = argsz_4069,
		.noreturn = false
	},
	[4070] = {
		.no = 4070,
		.name = "sys_setreuid",
		.nargs = 2,
		.argt = argt_4070,
		.argsz = argsz_4070,
		.noreturn = false
	},
	[4071] = {
		.no = 4071,
		.name = "sys_setregid",
		.nargs = 2,
		.argt = argt_4071,
		.argsz = argsz_4071,
		.noreturn = false
	},
	[4072] = {
		.no = 4072,
		.name = "sys_sigsuspend",
		.nargs = 3,
		.argt = argt_4072,
		.argsz = argsz_4072,
		.noreturn = false
	},
	[4073] = {
		.no = 4073,
		.name = "sys_sigpending",
		.nargs = 1,
		.argt = argt_4073,
		.argsz = argsz_4073,
		.noreturn = false
	},
	[4074] = {
		.no = 4074,
		.name = "sys_sethostname",
		.nargs = 2,
		.argt = argt_4074,
		.argsz = argsz_4074,
		.noreturn = false
	},
	[4075] = {
		.no = 4075,
		.name = "sys_setrlimit",
		.nargs = 2,
		.argt = argt_4075,
		.argsz = argsz_4075,
		.noreturn = false
	},
	[4076] = {
		.no = 4076,
		.name = "sys_getrlimit",
		.nargs = 2,
		.argt = argt_4076,
		.argsz = argsz_4076,
		.noreturn = false
	},
	[4077] = {
		.no = 4077,
		.name = "sys_getrusage",
		.nargs = 2,
		.argt = argt_4077,
		.argsz = argsz_4077,
		.noreturn = false
	},
	[4078] = {
		.no = 4078,
		.name = "sys_gettimeofday",
		.nargs = 2,
		.argt = argt_4078,
		.argsz = argsz_4078,
		.noreturn = false
	},
	[4079] = {
		.no = 4079,
		.name = "sys_settimeofday",
		.nargs = 2,
		.argt = argt_4079,
		.argsz = argsz_4079,
		.noreturn = false
	},
	[4080] = {
		.no = 4080,
		.name = "sys_getgroups",
		.nargs = 2,
		.argt = argt_4080,
		.argsz = argsz_4080,
		.noreturn = false
	},
	[4081] = {
		.no = 4081,
		.name = "sys_setgroups",
		.nargs = 2,
		.argt = argt_4081,
		.argsz = argsz_4081,
		.noreturn = false
	},
	[4083] = {
		.no = 4083,
		.name = "sys_symlink",
		.nargs = 2,
		.argt = argt_4083,
		.argsz = argsz_4083,
		.noreturn = false
	},
	[4084] = {
		.no = 4084,
		.name = "sys_lstat",
		.nargs = 2,
		.argt = argt_4084,
		.argsz = argsz_4084,
		.noreturn = false
	},
	[4085] = {
		.no = 4085,
		.name = "sys_readlink",
		.nargs = 3,
		.argt = argt_4085,
		.argsz = argsz_4085,
		.noreturn = false
	},
	[4086] = {
		.no = 4086,
		.name = "sys_uselib",
		.nargs = 1,
		.argt = argt_4086,
		.argsz = argsz_4086,
		.noreturn = false
	},
	[4087] = {
		.no = 4087,
		.name = "sys_swapon",
		.nargs = 2,
		.argt = argt_4087,
		.argsz = argsz_4087,
		.noreturn = false
	},
	[4088] = {
		.no = 4088,
		.name = "sys_reboot",
		.nargs = 4,
		.argt = argt_4088,
		.argsz = argsz_4088,
		.noreturn = false
	},
	[4089] = {
		.no = 4089,
		.name = "sys_old_readdir",
		.nargs = 3,
		.argt = argt_4089,
		.argsz = argsz_4089,
		.noreturn = false
	},
	[4090] = {
		.no = 4090,
		.name = "sys_mmap",
		.nargs = 6,
		.argt = argt_4090,
		.argsz = argsz_4090,
		.noreturn = false
	},
	[4091] = {
		.no = 4091,
		.name = "sys_munmap",
		.nargs = 2,
		.argt = argt_4091,
		.argsz = argsz_4091,
		.noreturn = false
	},
	[4092] = {
		.no = 4092,
		.name = "sys_truncate",
		.nargs = 2,
		.argt = argt_4092,
		.argsz = argsz_4092,
		.noreturn = false
	},
	[4093] = {
		.no = 4093,
		.name = "sys_ftruncate",
		.nargs = 2,
		.argt = argt_4093,
		.argsz = argsz_4093,
		.noreturn = false
	},
	[4094] = {
		.no = 4094,
		.name = "sys_fchmod",
		.nargs = 2,
		.argt = argt_4094,
		.argsz = argsz_4094,
		.noreturn = false
	},
	[4095] = {
		.no = 4095,
		.name = "sys_fchown",
		.nargs = 3,
		.argt = argt_4095,
		.argsz = argsz_4095,
		.noreturn = false
	},
	[4096] = {
		.no = 4096,
		.name = "sys_getpriority",
		.nargs = 2,
		.argt = argt_4096,
		.argsz = argsz_4096,
		.noreturn = false
	},
	[4097] = {
		.no = 4097,
		.name = "sys_setpriority",
		.nargs = 3,
		.argt = argt_4097,
		.argsz = argsz_4097,
		.noreturn = false
	},
	[4099] = {
		.no = 4099,
		.name = "sys_statfs",
		.nargs = 2,
		.argt = argt_4099,
		.argsz = argsz_4099,
		.noreturn = false
	},
	[4100] = {
		.no = 4100,
		.name = "sys_fstatfs",
		.nargs = 2,
		.argt = argt_4100,
		.argsz = argsz_4100,
		.noreturn = false
	},
	[4101] = {
		.no = 4101,
		.name = "sys_ioperm",
		.nargs = 3,
		.argt = argt_4101,
		.argsz = argsz_4101,
		.noreturn = false
	},
	[4102] = {
		.no = 4102,
		.name = "sys_socketcall",
		.nargs = 2,
		.argt = argt_4102,
		.argsz = argsz_4102,
		.noreturn = false
	},
	[4103] = {
		.no = 4103,
		.name = "sys_syslog",
		.nargs = 3,
		.argt = argt_4103,
		.argsz = argsz_4103,
		.noreturn = false
	},
	[4104] = {
		.no = 4104,
		.name = "sys_setitimer",
		.nargs = 3,
		.argt = argt_4104,
		.argsz = argsz_4104,
		.noreturn = false
	},
	[4105] = {
		.no = 4105,
		.name = "sys_getitimer",
		.nargs = 2,
		.argt = argt_4105,
		.argsz = argsz_4105,
		.noreturn = false
	},
	[4106] = {
		.no = 4106,
		.name = "sys_newstat",
		.nargs = 2,
		.argt = argt_4106,
		.argsz = argsz_4106,
		.noreturn = false
	},
	[4107] = {
		.no = 4107,
		.name = "sys_newlstat",
		.nargs = 2,
		.argt = argt_4107,
		.argsz = argsz_4107,
		.noreturn = false
	},
	[4108] = {
		.no = 4108,
		.name = "sys_newfstat",
		.nargs = 2,
		.argt = argt_4108,
		.argsz = argsz_4108,
		.noreturn = false
	},
	[4109] = {
		.no = 4109,
		.name = "sys_uname",
		.nargs = 1,
		.argt = argt_4109,
		.argsz = argsz_4109,
		.noreturn = false
	},
	[4110] = {
		.no = 4110,
		.name = "sys_iopl",
		.nargs = 1,
		.argt = argt_4110,
		.argsz = argsz_4110,
		.noreturn = false
	},
	[4111] = {
		.no = 4111,
		.name = "sys_vhangup",
		.nargs = 0,
		.argt = argt_4111,
		.argsz = argsz_4111,
		.noreturn = false
	},
	[4112] = {
		.no = 4112,
		.name = "sys_idle",
		.nargs = 0,
		.argt = argt_4112,
		.argsz = argsz_4112,
		.noreturn = false
	},
	[4114] = {
		.no = 4114,
		.name = "sys_wait4",
		.nargs = 4,
		.argt = argt_4114,
		.argsz = argsz_4114,
		.noreturn = false
	},
	[4115] = {
		.no = 4115,
		.name = "sys_swapoff",
		.nargs = 1,
		.argt = argt_4115,
		.argsz = argsz_4115,
		.noreturn = false
	},
	[4116] = {
		.no = 4116,
		.name = "sys_sysinfo",
		.nargs = 1,
		.argt = argt_4116,
		.argsz = argsz_4116,
		.noreturn = false
	},
	[4117] = {
		.no = 4117,
		.name = "sys_ipc",
		.nargs = 6,
		.argt = argt_4117,
		.argsz = argsz_4117,
		.noreturn = false
	},
	[4118] = {
		.no = 4118,
		.name = "sys_fsync",
		.nargs = 1,
		.argt = argt_4118,
		.argsz = argsz_4118,
		.noreturn = false
	},
	[4119] = {
		.no = 4119,
		.name = "sys_sigreturn",
		.nargs = 0,
		.argt = argt_4119,
		.argsz = argsz_4119,
		.noreturn = false
	},
	[4120] = {
		.no = 4120,
		.name = "sys_clone",
		.nargs = 5,
		.argt = argt_4120,
		.argsz = argsz_4120,
		.noreturn = false
	},
	[4121] = {
		.no = 4121,
		.name = "sys_setdomainname",
		.nargs = 2,
		.argt = argt_4121,
		.argsz = argsz_4121,
		.noreturn = false
	},
	[4122] = {
		.no = 4122,
		.name = "sys_newuname",
		.nargs = 1,
		.argt = argt_4122,
		.argsz = argsz_4122,
		.noreturn = false
	},
	[4123] = {
		.no = 4123,
		.name = "modify_ldt",
		.nargs = 3,
		.argt = argt_4123,
		.argsz = argsz_4123,
		.noreturn = false
	},
	[4124] = {
		.no = 4124,
		.name = "sys_adjtimex_time32",
		.nargs = 1,
		.argt = argt_4124,
		.argsz = argsz_4124,
		.noreturn = false
	},
	[4125] = {
		.no = 4125,
		.name = "sys_mprotect",
		.nargs = 3,
		.argt = argt_4125,
		.argsz = argsz_4125,
		.noreturn = false
	},
	[4126] = {
		.no = 4126,
		.name = "sys_sigprocmask",
		.nargs = 3,
		.argt = argt_4126,
		.argsz = argsz_4126,
		.noreturn = false
	},
	[4127] = {
		.no = 4127,
		.name = "create_module",
		.nargs = 2,
		.argt = argt_4127,
		.argsz = argsz_4127,
		.noreturn = false
	},
	[4128] = {
		.no = 4128,
		.name = "sys_init_module",
		.nargs = 3,
		.argt = argt_4128,
		.argsz = argsz_4128,
		.noreturn = false
	},
	[4129] = {
		.no = 4129,
		.name = "sys_delete_module",
		.nargs = 2,
		.argt = argt_4129,
		.argsz = argsz_4129,
		.noreturn = false
	},
	[4130] = {
		.no = 4130,
		.name = "get_kernel_syms",
		.nargs = 1,
		.argt = argt_4130,
		.argsz = argsz_4130,
		.noreturn = false
	},
	[4131] = {
		.no = 4131,
		.name = "sys_quotactl",
		.nargs = 4,
		.argt = argt_4131,
		.argsz = argsz_4131,
		.noreturn = false
	},
	[4132] = {
		.no = 4132,
		.name = "sys_getpgid",
		.nargs = 1,
		.argt = argt_4132,
		.argsz = argsz_4132,
		.noreturn = false
	},
	[4133] = {
		.no = 4133,
		.name = "sys_fchdir",
		.nargs = 1,
		.argt = argt_4133,
		.argsz = argsz_4133,
		.noreturn = false
	},
	[4134] = {
		.no = 4134,
		.name = "sys_bdflush",
		.nargs = 2,
		.argt = argt_4134,
		.argsz = argsz_4134,
		.noreturn = false
	},
	[4135] = {
		.no = 4135,
		.name = "sys_sysfs",
		.nargs = 3,
		.argt = argt_4135,
		.argsz = argsz_4135,
		.noreturn = false
	},
	[4136] = {
		.no = 4136,
		.name = "sys_personality",
		.nargs = 1,
		.argt = argt_4136,
		.argsz = argsz_4136,
		.noreturn = false
	},
	[4138] = {
		.no = 4138,
		.name = "sys_setfsuid",
		.nargs = 1,
		.argt = argt_4138,
		.argsz = argsz_4138,
		.noreturn = false
	},
	[4139] = {
		.no = 4139,
		.name = "sys_setfsgid",
		.nargs = 1,
		.argt = argt_4139,
		.argsz = argsz_4139,
		.noreturn = false
	},
	[4140] = {
		.no = 4140,
		.name = "sys_llseek",
		.nargs = 5,
		.argt = argt_4140,
		.argsz = argsz_4140,
		.noreturn = false
	},
	[4141] = {
		.no = 4141,
		.name = "sys_getdents",
		.nargs = 3,
		.argt = argt_4141,
		.argsz = argsz_4141,
		.noreturn = false
	},
	[4142] = {
		.no = 4142,
		.name = "sys_select",
		.nargs = 5,
		.argt = argt_4142,
		.argsz = argsz_4142,
		.noreturn = false
	},
	[4143] = {
		.no = 4143,
		.name = "sys_flock",
		.nargs = 2,
		.argt = argt_4143,
		.argsz = argsz_4143,
		.noreturn = false
	},
	[4144] = {
		.no = 4144,
		.name = "sys_msync",
		.nargs = 3,
		.argt = argt_4144,
		.argsz = argsz_4144,
		.noreturn = false
	},
	[4145] = {
		.no = 4145,
		.name = "sys_readv",
		.nargs = 3,
		.argt = argt_4145,
		.argsz = argsz_4145,
		.noreturn = false
	},
	[4146] = {
		.no = 4146,
		.name = "sys_writev",
		.nargs = 3,
		.argt = argt_4146,
		.argsz = argsz_4146,
		.noreturn = false
	},
	[4147] = {
		.no = 4147,
		.name = "sys_cacheflush",
		.nargs = 3,
		.argt = argt_4147,
		.argsz = argsz_4147,
		.noreturn = false
	},
	[4150] = {
		.no = 4150,
		.name = "sys_setup",
		.nargs = 0,
		.argt = argt_4150,
		.argsz = argsz_4150,
		.noreturn = false
	},
	[4151] = {
		.no = 4151,
		.name = "sys_getsid",
		.nargs = 1,
		.argt = argt_4151,
		.argsz = argsz_4151,
		.noreturn = false
	},
	[4152] = {
		.no = 4152,
		.name = "sys_fdatasync",
		.nargs = 1,
		.argt = argt_4152,
		.argsz = argsz_4152,
		.noreturn = false
	},
	[4153] = {
		.no = 4153,
		.name = "sys_sysctl",
		.nargs = 1,
		.argt = argt_4153,
		.argsz = argsz_4153,
		.noreturn = false
	},
	[4154] = {
		.no = 4154,
		.name = "sys_mlock",
		.nargs = 2,
		.argt = argt_4154,
		.argsz = argsz_4154,
		.noreturn = false
	},
	[4155] = {
		.no = 4155,
		.name = "sys_munlock",
		.nargs = 2,
		.argt = argt_4155,
		.argsz = argsz_4155,
		.noreturn = false
	},
	[4156] = {
		.no = 4156,
		.name = "sys_mlockall",
		.nargs = 1,
		.argt = argt_4156,
		.argsz = argsz_4156,
		.noreturn = false
	},
	[4157] = {
		.no = 4157,
		.name = "sys_munlockall",
		.nargs = 0,
		.argt = argt_4157,
		.argsz = argsz_4157,
		.noreturn = false
	},
	[4158] = {
		.no = 4158,
		.name = "sys_sched_setparam",
		.nargs = 2,
		.argt = argt_4158,
		.argsz = argsz_4158,
		.noreturn = false
	},
	[4159] = {
		.no = 4159,
		.name = "sys_sched_getparam",
		.nargs = 2,
		.argt = argt_4159,
		.argsz = argsz_4159,
		.noreturn = false
	},
	[4160] = {
		.no = 4160,
		.name = "sys_sched_setscheduler",
		.nargs = 3,
		.argt = argt_4160,
		.argsz = argsz_4160,
		.noreturn = false
	},
	[4161] = {
		.no = 4161,
		.name = "sys_sched_getscheduler",
		.nargs = 1,
		.argt = argt_4161,
		.argsz = argsz_4161,
		.noreturn = false
	},
	[4162] = {
		.no = 4162,
		.name = "sys_sched_yield",
		.nargs = 0,
		.argt = argt_4162,
		.argsz = argsz_4162,
		.noreturn = false
	},
	[4163] = {
		.no = 4163,
		.name = "sys_sched_get_priority_max",
		.nargs = 1,
		.argt = argt_4163,
		.argsz = argsz_4163,
		.noreturn = false
	},
	[4164] = {
		.no = 4164,
		.name = "sys_sched_get_priority_min",
		.nargs = 1,
		.argt = argt_4164,
		.argsz = argsz_4164,
		.noreturn = false
	},
	[4165] = {
		.no = 4165,
		.name = "sys_sched_rr_get_interval_time32",
		.nargs = 2,
		.argt = argt_4165,
		.argsz = argsz_4165,
		.noreturn = false
	},
	[4166] = {
		.no = 4166,
		.name = "sys_nanosleep_time32",
		.nargs = 2,
		.argt = argt_4166,
		.argsz = argsz_4166,
		.noreturn = false
	},
	[4167] = {
		.no = 4167,
		.name = "sys_mremap",
		.nargs = 5,
		.argt = argt_4167,
		.argsz = argsz_4167,
		.noreturn = false
	},
	[4168] = {
		.no = 4168,
		.name = "sys_accept",
		.nargs = 3,
		.argt = argt_4168,
		.argsz = argsz_4168,
		.noreturn = false
	},
	[4169] = {
		.no = 4169,
		.name = "sys_bind",
		.nargs = 3,
		.argt = argt_4169,
		.argsz = argsz_4169,
		.noreturn = false
	},
	[4170] = {
		.no = 4170,
		.name = "sys_connect",
		.nargs = 3,
		.argt = argt_4170,
		.argsz = argsz_4170,
		.noreturn = false
	},
	[4171] = {
		.no = 4171,
		.name = "sys_getpeername",
		.nargs = 3,
		.argt = argt_4171,
		.argsz = argsz_4171,
		.noreturn = false
	},
	[4172] = {
		.no = 4172,
		.name = "sys_getsockname",
		.nargs = 3,
		.argt = argt_4172,
		.argsz = argsz_4172,
		.noreturn = false
	},
	[4173] = {
		.no = 4173,
		.name = "sys_getsockopt",
		.nargs = 5,
		.argt = argt_4173,
		.argsz = argsz_4173,
		.noreturn = false
	},
	[4174] = {
		.no = 4174,
		.name = "sys_listen",
		.nargs = 2,
		.argt = argt_4174,
		.argsz = argsz_4174,
		.noreturn = false
	},
	[4175] = {
		.no = 4175,
		.name = "sys_recv",
		.nargs = 4,
		.argt = argt_4175,
		.argsz = argsz_4175,
		.noreturn = false
	},
	[4176] = {
		.no = 4176,
		.name = "sys_recvfrom",
		.nargs = 6,
		.argt = argt_4176,
		.argsz = argsz_4176,
		.noreturn = false
	},
	[4177] = {
		.no = 4177,
		.name = "sys_recvmsg",
		.nargs = 3,
		.argt = argt_4177,
		.argsz = argsz_4177,
		.noreturn = false
	},
	[4178] = {
		.no = 4178,
		.name = "sys_send",
		.nargs = 4,
		.argt = argt_4178,
		.argsz = argsz_4178,
		.noreturn = false
	},
	[4179] = {
		.no = 4179,
		.name = "sys_sendmsg",
		.nargs = 3,
		.argt = argt_4179,
		.argsz = argsz_4179,
		.noreturn = false
	},
	[4180] = {
		.no = 4180,
		.name = "sys_sendto",
		.nargs = 6,
		.argt = argt_4180,
		.argsz = argsz_4180,
		.noreturn = false
	},
	[4181] = {
		.no = 4181,
		.name = "sys_setsockopt",
		.nargs = 5,
		.argt = argt_4181,
		.argsz = argsz_4181,
		.noreturn = false
	},
	[4182] = {
		.no = 4182,
		.name = "sys_shutdown",
		.nargs = 2,
		.argt = argt_4182,
		.argsz = argsz_4182,
		.noreturn = false
	},
	[4183] = {
		.no = 4183,
		.name = "sys_socket",
		.nargs = 3,
		.argt = argt_4183,
		.argsz = argsz_4183,
		.noreturn = false
	},
	[4184] = {
		.no = 4184,
		.name = "sys_socketpair",
		.nargs = 4,
		.argt = argt_4184,
		.argsz = argsz_4184,
		.noreturn = false
	},
	[4185] = {
		.no = 4185,
		.name = "sys_setresuid",
		.nargs = 3,
		.argt = argt_4185,
		.argsz = argsz_4185,
		.noreturn = false
	},
	[4186] = {
		.no = 4186,
		.name = "sys_getresuid",
		.nargs = 3,
		.argt = argt_4186,
		.argsz = argsz_4186,
		.noreturn = false
	},
	[4187] = {
		.no = 4187,
		.name = "sys_query_module",
		.nargs = 5,
		.argt = argt_4187,
		.argsz = argsz_4187,
		.noreturn = false
	},
	[4188] = {
		.no = 4188,
		.name = "sys_poll",
		.nargs = 3,
		.argt = argt_4188,
		.argsz = argsz_4188,
		.noreturn = false
	},
	[4189] = {
		.no = 4189,
		.name = "sys_nfsservctl",
		.nargs = 3,
		.argt = argt_4189,
		.argsz = argsz_4189,
		.noreturn = false
	},
	[4190] = {
		.no = 4190,
		.name = "sys_setresgid",
		.nargs = 3,
		.argt = argt_4190,
		.argsz = argsz_4190,
		.noreturn = false
	},
	[4191] = {
		.no = 4191,
		.name = "sys_getresgid",
		.nargs = 3,
		.argt = argt_4191,
		.argsz = argsz_4191,
		.noreturn = false
	},
	[4192] = {
		.no = 4192,
		.name = "sys_prctl",
		.nargs = 5,
		.argt = argt_4192,
		.argsz = argsz_4192,
		.noreturn = false
	},
	[4193] = {
		.no = 4193,
		.name = "sys_rt_sigreturn",
		.nargs = 0,
		.argt = argt_4193,
		.argsz = argsz_4193,
		.noreturn = false
	},
	[4194] = {
		.no = 4194,
		.name = "sys_rt_sigaction",
		.nargs = 4,
		.argt = argt_4194,
		.argsz = argsz_4194,
		.noreturn = false
	},
	[4195] = {
		.no = 4195,
		.name = "sys_rt_sigprocmask",
		.nargs = 4,
		.argt = argt_4195,
		.argsz = argsz_4195,
		.noreturn = false
	},
	[4196] = {
		.no = 4196,
		.name = "sys_rt_sigpending",
		.nargs = 2,
		.argt = argt_4196,
		.argsz = argsz_4196,
		.noreturn = false
	},
	[4197] = {
		.no = 4197,
		.name = "sys_rt_sigtimedwait_time32",
		.nargs = 4,
		.argt = argt_4197,
		.argsz = argsz_4197,
		.noreturn = false
	},
	[4198] = {
		.no = 4198,
		.name = "sys_rt_sigqueueinfo",
		.nargs = 3,
		.argt = argt_4198,
		.argsz = argsz_4198,
		.noreturn = false
	},
	[4199] = {
		.no = 4199,
		.name = "sys_rt_sigsuspend",
		.nargs = 2,
		.argt = argt_4199,
		.argsz = argsz_4199,
		.noreturn = false
	},
	[4200] = {
		.no = 4200,
		.name = "sys_pread64",
		.nargs = 4,
		.argt = argt_4200,
		.argsz = argsz_4200,
		.noreturn = false
	},
	[4201] = {
		.no = 4201,
		.name = "sys_pwrite64",
		.nargs = 4,
		.argt = argt_4201,
		.argsz = argsz_4201,
		.noreturn = false
	},
	[4202] = {
		.no = 4202,
		.name = "sys_chown",
		.nargs = 3,
		.argt = argt_4202,
		.argsz = argsz_4202,
		.noreturn = false
	},
	[4203] = {
		.no = 4203,
		.name = "sys_getcwd",
		.nargs = 2,
		.argt = argt_4203,
		.argsz = argsz_4203,
		.noreturn = false
	},
	[4204] = {
		.no = 4204,
		.name = "sys_capget",
		.nargs = 2,
		.argt = argt_4204,
		.argsz = argsz_4204,
		.noreturn = false
	},
	[4205] = {
		.no = 4205,
		.name = "sys_capset",
		.nargs = 2,
		.argt = argt_4205,
		.argsz = argsz_4205,
		.noreturn = false
	},
	[4206] = {
		.no = 4206,
		.name = "sys_sigaltstack",
		.nargs = 2,
		.argt = argt_4206,
		.argsz = argsz_4206,
		.noreturn = false
	},
	[4207] = {
		.no = 4207,
		.name = "sys_sendfile",
		.nargs = 4,
		.argt = argt_4207,
		.argsz = argsz_4207,
		.noreturn = false
	},
	[4210] = {
		.no = 4210,
		.name = "mmap2",
		.nargs = 6,
		.argt = argt_4210,
		.argsz = argsz_4210,
		.noreturn = false
	},
	[4211] = {
		.no = 4211,
		.name = "sys_truncate64",
		.nargs = 2,
		.argt = argt_4211,
		.argsz = argsz_4211,
		.noreturn = false
	},
	[4212] = {
		.no = 4212,
		.name = "sys_ftruncate64",
		.nargs = 2,
		.argt = argt_4212,
		.argsz = argsz_4212,
		.noreturn = false
	},
	[4213] = {
		.no = 4213,
		.name = "sys_stat64",
		.nargs = 2,
		.argt = argt_4213,
		.argsz = argsz_4213,
		.noreturn = false
	},
	[4214] = {
		.no = 4214,
		.name = "sys_lstat64",
		.nargs = 2,
		.argt = argt_4214,
		.argsz = argsz_4214,
		.noreturn = false
	},
	[4215] = {
		.no = 4215,
		.name = "sys_fstat64",
		.nargs = 2,
		.argt = argt_4215,
		.argsz = argsz_4215,
		.noreturn = false
	},
	[4216] = {
		.no = 4216,
		.name = "sys_pivot_root",
		.nargs = 2,
		.argt = argt_4216,
		.argsz = argsz_4216,
		.noreturn = false
	},
	[4217] = {
		.no = 4217,
		.name = "sys_mincore",
		.nargs = 3,
		.argt = argt_4217,
		.argsz = argsz_4217,
		.noreturn = false
	},
	[4218] = {
		.no = 4218,
		.name = "sys_madvise",
		.nargs = 3,
		.argt = argt_4218,
		.argsz = argsz_4218,
		.noreturn = false
	},
	[4219] = {
		.no = 4219,
		.name = "sys_getdents64",
		.nargs = 3,
		.argt = argt_4219,
		.argsz = argsz_4219,
		.noreturn = false
	},
	[4220] = {
		.no = 4220,
		.name = "sys_fcntl64",
		.nargs = 3,
		.argt = argt_4220,
		.argsz = argsz_4220,
		.noreturn = false
	},
	[4222] = {
		.no = 4222,
		.name = "sys_gettid",
		.nargs = 0,
		.argt = argt_4222,
		.argsz = argsz_4222,
		.noreturn = false
	},
	[4223] = {
		.no = 4223,
		.name = "sys_readahead",
		.nargs = 3,
		.argt = argt_4223,
		.argsz = argsz_4223,
		.noreturn = false
	},
	[4224] = {
		.no = 4224,
		.name = "sys_setxattr",
		.nargs = 5,
		.argt = argt_4224,
		.argsz = argsz_4224,
		.noreturn = false
	},
	[4225] = {
		.no = 4225,
		.name = "sys_lsetxattr",
		.nargs = 5,
		.argt = argt_4225,
		.argsz = argsz_4225,
		.noreturn = false
	},
	[4226] = {
		.no = 4226,
		.name = "sys_fsetxattr",
		.nargs = 5,
		.argt = argt_4226,
		.argsz = argsz_4226,
		.noreturn = false
	},
	[4227] = {
		.no = 4227,
		.name = "sys_getxattr",
		.nargs = 4,
		.argt = argt_4227,
		.argsz = argsz_4227,
		.noreturn = false
	},
	[4228] = {
		.no = 4228,
		.name = "sys_lgetxattr",
		.nargs = 4,
		.argt = argt_4228,
		.argsz = argsz_4228,
		.noreturn = false
	},
	[4229] = {
		.no = 4229,
		.name = "sys_fgetxattr",
		.nargs = 4,
		.argt = argt_4229,
		.argsz = argsz_4229,
		.noreturn = false
	},
	[4230] = {
		.no = 4230,
		.name = "sys_listxattr",
		.nargs = 3,
		.argt = argt_4230,
		.argsz = argsz_4230,
		.noreturn = false
	},
	[4231] = {
		.no = 4231,
		.name = "sys_llistxattr",
		.nargs = 3,
		.argt = argt_4231,
		.argsz = argsz_4231,
		.noreturn = false
	},
	[4232] = {
		.no = 4232,
		.name = "sys_flistxattr",
		.nargs = 3,
		.argt = argt_4232,
		.argsz = argsz_4232,
		.noreturn = false
	},
	[4233] = {
		.no = 4233,
		.name = "sys_removexattr",
		.nargs = 2,
		.argt = argt_4233,
		.argsz = argsz_4233,
		.noreturn = false
	},
	[4234] = {
		.no = 4234,
		.name = "sys_lremovexattr",
		.nargs = 2,
		.argt = argt_4234,
		.argsz = argsz_4234,
		.noreturn = false
	},
	[4235] = {
		.no = 4235,
		.name = "sys_fremovexattr",
		.nargs = 2,
		.argt = argt_4235,
		.argsz = argsz_4235,
		.noreturn = false
	},
	[4236] = {
		.no = 4236,
		.name = "sys_tkill",
		.nargs = 2,
		.argt = argt_4236,
		.argsz = argsz_4236,
		.noreturn = false
	},
	[4237] = {
		.no = 4237,
		.name = "sys_sendfile64",
		.nargs = 4,
		.argt = argt_4237,
		.argsz = argsz_4237,
		.noreturn = false
	},
	[4238] = {
		.no = 4238,
		.name = "sys_futex_time32",
		.nargs = 6,
		.argt = argt_4238,
		.argsz = argsz_4238,
		.noreturn = false
	},
	[4239] = {
		.no = 4239,
		.name = "sys_sched_setaffinity",
		.nargs = 3,
		.argt = argt_4239,
		.argsz = argsz_4239,
		.noreturn = false
	},
	[4240] = {
		.no = 4240,
		.name = "sys_sched_getaffinity",
		.nargs = 3,
		.argt = argt_4240,
		.argsz = argsz_4240,
		.noreturn = false
	},
	[4241] = {
		.no = 4241,
		.name = "sys_io_setup",
		.nargs = 2,
		.argt = argt_4241,
		.argsz = argsz_4241,
		.noreturn = false
	},
	[4242] = {
		.no = 4242,
		.name = "sys_io_destroy",
		.nargs = 1,
		.argt = argt_4242,
		.argsz = argsz_4242,
		.noreturn = false
	},
	[4243] = {
		.no = 4243,
		.name = "sys_io_getevents_time32",
		.nargs = 5,
		.argt = argt_4243,
		.argsz = argsz_4243,
		.noreturn = false
	},
	[4244] = {
		.no = 4244,
		.name = "sys_io_submit",
		.nargs = 3,
		.argt = argt_4244,
		.argsz = argsz_4244,
		.noreturn = false
	},
	[4245] = {
		.no = 4245,
		.name = "sys_io_cancel",
		.nargs = 3,
		.argt = argt_4245,
		.argsz = argsz_4245,
		.noreturn = false
	},
	[4246] = {
		.no = 4246,
		.name = "sys_exit_group",
		.nargs = 1,
		.argt = argt_4246,
		.argsz = argsz_4246,
		.noreturn = false
	},
	[4247] = {
		.no = 4247,
		.name = "sys_lookup_dcookie",
		.nargs = 3,
		.argt = argt_4247,
		.argsz = argsz_4247,
		.noreturn = false
	},
	[4248] = {
		.no = 4248,
		.name = "sys_epoll_create",
		.nargs = 1,
		.argt = argt_4248,
		.argsz = argsz_4248,
		.noreturn = false
	},
	[4249] = {
		.no = 4249,
		.name = "sys_epoll_ctl",
		.nargs = 4,
		.argt = argt_4249,
		.argsz = argsz_4249,
		.noreturn = false
	},
	[4250] = {
		.no = 4250,
		.name = "sys_epoll_wait",
		.nargs = 4,
		.argt = argt_4250,
		.argsz = argsz_4250,
		.noreturn = false
	},
	[4251] = {
		.no = 4251,
		.name = "sys_remap_file_pages",
		.nargs = 5,
		.argt = argt_4251,
		.argsz = argsz_4251,
		.noreturn = false
	},
	[4252] = {
		.no = 4252,
		.name = "sys_set_tid_address",
		.nargs = 1,
		.argt = argt_4252,
		.argsz = argsz_4252,
		.noreturn = false
	},
	[4253] = {
		.no = 4253,
		.name = "sys_restart_syscall",
		.nargs = 0,
		.argt = argt_4253,
		.argsz = argsz_4253,
		.noreturn = false
	},
	[4254] = {
		.no = 4254,
		.name = "sys_fadvise64_64",
		.nargs = 4,
		.argt = argt_4254,
		.argsz = argsz_4254,
		.noreturn = false
	},
	[4255] = {
		.no = 4255,
		.name = "sys_statfs64",
		.nargs = 3,
		.argt = argt_4255,
		.argsz = argsz_4255,
		.noreturn = false
	},
	[4256] = {
		.no = 4256,
		.name = "sys_fstatfs64",
		.nargs = 3,
		.argt = argt_4256,
		.argsz = argsz_4256,
		.noreturn = false
	},
	[4257] = {
		.no = 4257,
		.name = "sys_timer_create",
		.nargs = 3,
		.argt = argt_4257,
		.argsz = argsz_4257,
		.noreturn = false
	},
	[4258] = {
		.no = 4258,
		.name = "sys_timer_settime32",
		.nargs = 4,
		.argt = argt_4258,
		.argsz = argsz_4258,
		.noreturn = false
	},
	[4259] = {
		.no = 4259,
		.name = "sys_timer_gettime32",
		.nargs = 2,
		.argt = argt_4259,
		.argsz = argsz_4259,
		.noreturn = false
	},
	[4260] = {
		.no = 4260,
		.name = "sys_timer_getoverrun",
		.nargs = 1,
		.argt = argt_4260,
		.argsz = argsz_4260,
		.noreturn = false
	},
	[4261] = {
		.no = 4261,
		.name = "sys_timer_delete",
		.nargs = 1,
		.argt = argt_4261,
		.argsz = argsz_4261,
		.noreturn = false
	},
	[4262] = {
		.no = 4262,
		.name = "sys_clock_settime32",
		.nargs = 2,
		.argt = argt_4262,
		.argsz = argsz_4262,
		.noreturn = false
	},
	[4263] = {
		.no = 4263,
		.name = "sys_clock_gettime32",
		.nargs = 2,
		.argt = argt_4263,
		.argsz = argsz_4263,
		.noreturn = false
	},
	[4264] = {
		.no = 4264,
		.name = "sys_clock_getres_time32",
		.nargs = 2,
		.argt = argt_4264,
		.argsz = argsz_4264,
		.noreturn = false
	},
	[4265] = {
		.no = 4265,
		.name = "sys_clock_nanosleep_time32",
		.nargs = 4,
		.argt = argt_4265,
		.argsz = argsz_4265,
		.noreturn = false
	},
	[4266] = {
		.no = 4266,
		.name = "sys_tgkill",
		.nargs = 3,
		.argt = argt_4266,
		.argsz = argsz_4266,
		.noreturn = false
	},
	[4267] = {
		.no = 4267,
		.name = "sys_utimes_time32",
		.nargs = 2,
		.argt = argt_4267,
		.argsz = argsz_4267,
		.noreturn = false
	},
	[4268] = {
		.no = 4268,
		.name = "sys_mbind",
		.nargs = 6,
		.argt = argt_4268,
		.argsz = argsz_4268,
		.noreturn = false
	},
	[4269] = {
		.no = 4269,
		.name = "sys_get_mempolicy",
		.nargs = 5,
		.argt = argt_4269,
		.argsz = argsz_4269,
		.noreturn = false
	},
	[4270] = {
		.no = 4270,
		.name = "sys_set_mempolicy",
		.nargs = 3,
		.argt = argt_4270,
		.argsz = argsz_4270,
		.noreturn = false
	},
	[4271] = {
		.no = 4271,
		.name = "sys_mq_open",
		.nargs = 4,
		.argt = argt_4271,
		.argsz = argsz_4271,
		.noreturn = false
	},
	[4272] = {
		.no = 4272,
		.name = "sys_mq_unlink",
		.nargs = 1,
		.argt = argt_4272,
		.argsz = argsz_4272,
		.noreturn = false
	},
	[4273] = {
		.no = 4273,
		.name = "sys_mq_timedsend_time32",
		.nargs = 5,
		.argt = argt_4273,
		.argsz = argsz_4273,
		.noreturn = false
	},
	[4274] = {
		.no = 4274,
		.name = "sys_mq_timedreceive_time32",
		.nargs = 5,
		.argt = argt_4274,
		.argsz = argsz_4274,
		.noreturn = false
	},
	[4275] = {
		.no = 4275,
		.name = "sys_mq_notify",
		.nargs = 2,
		.argt = argt_4275,
		.argsz = argsz_4275,
		.noreturn = false
	},
	[4276] = {
		.no = 4276,
		.name = "sys_mq_getsetattr",
		.nargs = 3,
		.argt = argt_4276,
		.argsz = argsz_4276,
		.noreturn = false
	},
	[4278] = {
		.no = 4278,
		.name = "sys_waitid",
		.nargs = 5,
		.argt = argt_4278,
		.argsz = argsz_4278,
		.noreturn = false
	},
	[4280] = {
		.no = 4280,
		.name = "sys_add_key",
		.nargs = 5,
		.argt = argt_4280,
		.argsz = argsz_4280,
		.noreturn = false
	},
	[4281] = {
		.no = 4281,
		.name = "sys_request_key",
		.nargs = 4,
		.argt = argt_4281,
		.argsz = argsz_4281,
		.noreturn = false
	},
	[4282] = {
		.no = 4282,
		.name = "sys_keyctl",
		.nargs = 5,
		.argt = argt_4282,
		.argsz = argsz_4282,
		.noreturn = false
	},
	[4283] = {
		.no = 4283,
		.name = "set_thread_area",
		.nargs = 1,
		.argt = argt_4283,
		.argsz = argsz_4283,
		.noreturn = false
	},
	[4284] = {
		.no = 4284,
		.name = "sys_inotify_init",
		.nargs = 0,
		.argt = argt_4284,
		.argsz = argsz_4284,
		.noreturn = false
	},
	[4285] = {
		.no = 4285,
		.name = "sys_inotify_add_watch",
		.nargs = 3,
		.argt = argt_4285,
		.argsz = argsz_4285,
		.noreturn = false
	},
	[4286] = {
		.no = 4286,
		.name = "sys_inotify_rm_watch",
		.nargs = 2,
		.argt = argt_4286,
		.argsz = argsz_4286,
		.noreturn = false
	},
	[4287] = {
		.no = 4287,
		.name = "sys_migrate_pages",
		.nargs = 4,
		.argt = argt_4287,
		.argsz = argsz_4287,
		.noreturn = false
	},
	[4288] = {
		.no = 4288,
		.name = "sys_openat",
		.nargs = 4,
		.argt = argt_4288,
		.argsz = argsz_4288,
		.noreturn = false
	},
	[4289] = {
		.no = 4289,
		.name = "sys_mkdirat",
		.nargs = 3,
		.argt = argt_4289,
		.argsz = argsz_4289,
		.noreturn = false
	},
	[4290] = {
		.no = 4290,
		.name = "sys_mknodat",
		.nargs = 4,
		.argt = argt_4290,
		.argsz = argsz_4290,
		.noreturn = false
	},
	[4291] = {
		.no = 4291,
		.name = "sys_fchownat",
		.nargs = 5,
		.argt = argt_4291,
		.argsz = argsz_4291,
		.noreturn = false
	},
	[4292] = {
		.no = 4292,
		.name = "sys_futimesat_time32",
		.nargs = 3,
		.argt = argt_4292,
		.argsz = argsz_4292,
		.noreturn = false
	},
	[4293] = {
		.no = 4293,
		.name = "sys_fstatat64",
		.nargs = 4,
		.argt = argt_4293,
		.argsz = argsz_4293,
		.noreturn = false
	},
	[4294] = {
		.no = 4294,
		.name = "sys_unlinkat",
		.nargs = 3,
		.argt = argt_4294,
		.argsz = argsz_4294,
		.noreturn = false
	},
	[4295] = {
		.no = 4295,
		.name = "sys_renameat",
		.nargs = 4,
		.argt = argt_4295,
		.argsz = argsz_4295,
		.noreturn = false
	},
	[4296] = {
		.no = 4296,
		.name = "sys_linkat",
		.nargs = 5,
		.argt = argt_4296,
		.argsz = argsz_4296,
		.noreturn = false
	},
	[4297] = {
		.no = 4297,
		.name = "sys_symlinkat",
		.nargs = 3,
		.argt = argt_4297,
		.argsz = argsz_4297,
		.noreturn = false
	},
	[4298] = {
		.no = 4298,
		.name = "sys_readlinkat",
		.nargs = 4,
		.argt = argt_4298,
		.argsz = argsz_4298,
		.noreturn = false
	},
	[4299] = {
		.no = 4299,
		.name = "sys_fchmodat",
		.nargs = 3,
		.argt = argt_4299,
		.argsz = argsz_4299,
		.noreturn = false
	},
	[4300] = {
		.no = 4300,
		.name = "sys_faccessat",
		.nargs = 3,
		.argt = argt_4300,
		.argsz = argsz_4300,
		.noreturn = false
	},
	[4301] = {
		.no = 4301,
		.name = "sys_pselect6_time32",
		.nargs = 6,
		.argt = argt_4301,
		.argsz = argsz_4301,
		.noreturn = false
	},
	[4302] = {
		.no = 4302,
		.name = "sys_ppoll_time32",
		.nargs = 5,
		.argt = argt_4302,
		.argsz = argsz_4302,
		.noreturn = false
	},
	[4303] = {
		.no = 4303,
		.name = "sys_unshare",
		.nargs = 1,
		.argt = argt_4303,
		.argsz = argsz_4303,
		.noreturn = false
	},
	[4304] = {
		.no = 4304,
		.name = "sys_splice",
		.nargs = 6,
		.argt = argt_4304,
		.argsz = argsz_4304,
		.noreturn = false
	},
	[4305] = {
		.no = 4305,
		.name = "sys_sync_file_range",
		.nargs = 4,
		.argt = argt_4305,
		.argsz = argsz_4305,
		.noreturn = false
	},
	[4306] = {
		.no = 4306,
		.name = "sys_tee",
		.nargs = 4,
		.argt = argt_4306,
		.argsz = argsz_4306,
		.noreturn = false
	},
	[4307] = {
		.no = 4307,
		.name = "sys_vmsplice",
		.nargs = 4,
		.argt = argt_4307,
		.argsz = argsz_4307,
		.noreturn = false
	},
	[4308] = {
		.no = 4308,
		.name = "sys_move_pages",
		.nargs = 6,
		.argt = argt_4308,
		.argsz = argsz_4308,
		.noreturn = false
	},
	[4309] = {
		.no = 4309,
		.name = "sys_set_robust_list",
		.nargs = 2,
		.argt = argt_4309,
		.argsz = argsz_4309,
		.noreturn = false
	},
	[4310] = {
		.no = 4310,
		.name = "sys_get_robust_list",
		.nargs = 3,
		.argt = argt_4310,
		.argsz = argsz_4310,
		.noreturn = false
	},
	[4311] = {
		.no = 4311,
		.name = "sys_kexec_load",
		.nargs = 4,
		.argt = argt_4311,
		.argsz = argsz_4311,
		.noreturn = false
	},
	[4312] = {
		.no = 4312,
		.name = "sys_getcpu",
		.nargs = 3,
		.argt = argt_4312,
		.argsz = argsz_4312,
		.noreturn = false
	},
	[4313] = {
		.no = 4313,
		.name = "sys_epoll_pwait",
		.nargs = 6,
		.argt = argt_4313,
		.argsz = argsz_4313,
		.noreturn = false
	},
	[4314] = {
		.no = 4314,
		.name = "sys_ioprio_set",
		.nargs = 3,
		.argt = argt_4314,
		.argsz = argsz_4314,
		.noreturn = false
	},
	[4315] = {
		.no = 4315,
		.name = "sys_ioprio_get",
		.nargs = 2,
		.argt = argt_4315,
		.argsz = argsz_4315,
		.noreturn = false
	},
	[4316] = {
		.no = 4316,
		.name = "sys_utimensat_time32",
		.nargs = 4,
		.argt = argt_4316,
		.argsz = argsz_4316,
		.noreturn = false
	},
	[4317] = {
		.no = 4317,
		.name = "sys_signalfd",
		.nargs = 3,
		.argt = argt_4317,
		.argsz = argsz_4317,
		.noreturn = false
	},
	[4318] = {
		.no = 4318,
		.name = "sys_ni_syscall",
		.nargs = 0,
		.argt = argt_4318,
		.argsz = argsz_4318,
		.noreturn = false
	},
	[4319] = {
		.no = 4319,
		.name = "sys_eventfd",
		.nargs = 1,
		.argt = argt_4319,
		.argsz = argsz_4319,
		.noreturn = false
	},
	[4320] = {
		.no = 4320,
		.name = "sys_fallocate",
		.nargs = 4,
		.argt = argt_4320,
		.argsz = argsz_4320,
		.noreturn = false
	},
	[4321] = {
		.no = 4321,
		.name = "sys_timerfd_create",
		.nargs = 2,
		.argt = argt_4321,
		.argsz = argsz_4321,
		.noreturn = false
	},
	[4322] = {
		.no = 4322,
		.name = "sys_timerfd_gettime32",
		.nargs = 2,
		.argt = argt_4322,
		.argsz = argsz_4322,
		.noreturn = false
	},
	[4323] = {
		.no = 4323,
		.name = "sys_timerfd_settime32",
		.nargs = 4,
		.argt = argt_4323,
		.argsz = argsz_4323,
		.noreturn = false
	},
	[4324] = {
		.no = 4324,
		.name = "sys_signalfd4",
		.nargs = 4,
		.argt = argt_4324,
		.argsz = argsz_4324,
		.noreturn = false
	},
	[4325] = {
		.no = 4325,
		.name = "sys_eventfd2",
		.nargs = 2,
		.argt = argt_4325,
		.argsz = argsz_4325,
		.noreturn = false
	},
	[4326] = {
		.no = 4326,
		.name = "sys_epoll_create1",
		.nargs = 1,
		.argt = argt_4326,
		.argsz = argsz_4326,
		.noreturn = false
	},
	[4327] = {
		.no = 4327,
		.name = "sys_dup3",
		.nargs = 3,
		.argt = argt_4327,
		.argsz = argsz_4327,
		.noreturn = false
	},
	[4328] = {
		.no = 4328,
		.name = "sys_pipe2",
		.nargs = 2,
		.argt = argt_4328,
		.argsz = argsz_4328,
		.noreturn = false
	},
	[4329] = {
		.no = 4329,
		.name = "sys_inotify_init1",
		.nargs = 1,
		.argt = argt_4329,
		.argsz = argsz_4329,
		.noreturn = false
	},
	[4330] = {
		.no = 4330,
		.name = "sys_preadv",
		.nargs = 5,
		.argt = argt_4330,
		.argsz = argsz_4330,
		.noreturn = false
	},
	[4331] = {
		.no = 4331,
		.name = "sys_pwritev",
		.nargs = 5,
		.argt = argt_4331,
		.argsz = argsz_4331,
		.noreturn = false
	},
	[4332] = {
		.no = 4332,
		.name = "sys_rt_tgsigqueueinfo",
		.nargs = 4,
		.argt = argt_4332,
		.argsz = argsz_4332,
		.noreturn = false
	},
	[4333] = {
		.no = 4333,
		.name = "sys_perf_event_open",
		.nargs = 5,
		.argt = argt_4333,
		.argsz = argsz_4333,
		.noreturn = false
	},
	[4334] = {
		.no = 4334,
		.name = "sys_accept4",
		.nargs = 4,
		.argt = argt_4334,
		.argsz = argsz_4334,
		.noreturn = false
	},
	[4335] = {
		.no = 4335,
		.name = "sys_recvmmsg_time32",
		.nargs = 5,
		.argt = argt_4335,
		.argsz = argsz_4335,
		.noreturn = false
	},
	[4336] = {
		.no = 4336,
		.name = "sys_fanotify_init",
		.nargs = 2,
		.argt = argt_4336,
		.argsz = argsz_4336,
		.noreturn = false
	},
	[4337] = {
		.no = 4337,
		.name = "sys_fanotify_mark",
		.nargs = 5,
		.argt = argt_4337,
		.argsz = argsz_4337,
		.noreturn = false
	},
	[4338] = {
		.no = 4338,
		.name = "sys_prlimit64",
		.nargs = 4,
		.argt = argt_4338,
		.argsz = argsz_4338,
		.noreturn = false
	},
	[4339] = {
		.no = 4339,
		.name = "sys_name_to_handle_at",
		.nargs = 5,
		.argt = argt_4339,
		.argsz = argsz_4339,
		.noreturn = false
	},
	[4340] = {
		.no = 4340,
		.name = "sys_open_by_handle_at",
		.nargs = 3,
		.argt = argt_4340,
		.argsz = argsz_4340,
		.noreturn = false
	},
	[4341] = {
		.no = 4341,
		.name = "sys_clock_adjtime32",
		.nargs = 2,
		.argt = argt_4341,
		.argsz = argsz_4341,
		.noreturn = false
	},
	[4342] = {
		.no = 4342,
		.name = "sys_syncfs",
		.nargs = 1,
		.argt = argt_4342,
		.argsz = argsz_4342,
		.noreturn = false
	},
	[4343] = {
		.no = 4343,
		.name = "sys_sendmmsg",
		.nargs = 4,
		.argt = argt_4343,
		.argsz = argsz_4343,
		.noreturn = false
	},
	[4344] = {
		.no = 4344,
		.name = "sys_setns",
		.nargs = 2,
		.argt = argt_4344,
		.argsz = argsz_4344,
		.noreturn = false
	},
	[4345] = {
		.no = 4345,
		.name = "sys_process_vm_readv",
		.nargs = 6,
		.argt = argt_4345,
		.argsz = argsz_4345,
		.noreturn = false
	},
	[4346] = {
		.no = 4346,
		.name = "sys_process_vm_writev",
		.nargs = 6,
		.argt = argt_4346,
		.argsz = argsz_4346,
		.noreturn = false
	},
	[4347] = {
		.no = 4347,
		.name = "sys_kcmp",
		.nargs = 5,
		.argt = argt_4347,
		.argsz = argsz_4347,
		.noreturn = false
	},
	[4348] = {
		.no = 4348,
		.name = "sys_finit_module",
		.nargs = 3,
		.argt = argt_4348,
		.argsz = argsz_4348,
		.noreturn = false
	},
	[4349] = {
		.no = 4349,
		.name = "sys_sched_setattr",
		.nargs = 3,
		.argt = argt_4349,
		.argsz = argsz_4349,
		.noreturn = false
	},
	[4350] = {
		.no = 4350,
		.name = "sys_sched_getattr",
		.nargs = 4,
		.argt = argt_4350,
		.argsz = argsz_4350,
		.noreturn = false
	},
	[4351] = {
		.no = 4351,
		.name = "sys_renameat2",
		.nargs = 5,
		.argt = argt_4351,
		.argsz = argsz_4351,
		.noreturn = false
	},
	[4352] = {
		.no = 4352,
		.name = "sys_seccomp",
		.nargs = 3,
		.argt = argt_4352,
		.argsz = argsz_4352,
		.noreturn = false
	},
	[4353] = {
		.no = 4353,
		.name = "sys_getrandom",
		.nargs = 3,
		.argt = argt_4353,
		.argsz = argsz_4353,
		.noreturn = false
	},
	[4354] = {
		.no = 4354,
		.name = "sys_memfd_create",
		.nargs = 2,
		.argt = argt_4354,
		.argsz = argsz_4354,
		.noreturn = false
	},
	[4355] = {
		.no = 4355,
		.name = "sys_bpf",
		.nargs = 3,
		.argt = argt_4355,
		.argsz = argsz_4355,
		.noreturn = false
	},
	[4356] = {
		.no = 4356,
		.name = "sys_execveat",
		.nargs = 5,
		.argt = argt_4356,
		.argsz = argsz_4356,
		.noreturn = false
	},
	[4357] = {
		.no = 4357,
		.name = "sys_userfaultfd",
		.nargs = 1,
		.argt = argt_4357,
		.argsz = argsz_4357,
		.noreturn = false
	},
	[4358] = {
		.no = 4358,
		.name = "sys_membarrier",
		.nargs = 2,
		.argt = argt_4358,
		.argsz = argsz_4358,
		.noreturn = false
	},
	[4359] = {
		.no = 4359,
		.name = "sys_mlock2",
		.nargs = 3,
		.argt = argt_4359,
		.argsz = argsz_4359,
		.noreturn = false
	},
	[4360] = {
		.no = 4360,
		.name = "sys_copy_file_range",
		.nargs = 6,
		.argt = argt_4360,
		.argsz = argsz_4360,
		.noreturn = false
	},
	[4361] = {
		.no = 4361,
		.name = "sys_preadv2",
		.nargs = 6,
		.argt = argt_4361,
		.argsz = argsz_4361,
		.noreturn = false
	},
	[4362] = {
		.no = 4362,
		.name = "sys_pwritev2",
		.nargs = 6,
		.argt = argt_4362,
		.argsz = argsz_4362,
		.noreturn = false
	},
	[4363] = {
		.no = 4363,
		.name = "sys_pkey_mprotect",
		.nargs = 4,
		.argt = argt_4363,
		.argsz = argsz_4363,
		.noreturn = false
	},
	[4364] = {
		.no = 4364,
		.name = "sys_pkey_alloc",
		.nargs = 2,
		.argt = argt_4364,
		.argsz = argsz_4364,
		.noreturn = false
	},
	[4365] = {
		.no = 4365,
		.name = "sys_pkey_free",
		.nargs = 1,
		.argt = argt_4365,
		.argsz = argsz_4365,
		.noreturn = false
	},
	[4366] = {
		.no = 4366,
		.name = "sys_statx",
		.nargs = 5,
		.argt = argt_4366,
		.argsz = argsz_4366,
		.noreturn = false
	},
	[4367] = {
		.no = 4367,
		.name = "sys_rseq",
		.nargs = 4,
		.argt = argt_4367,
		.argsz = argsz_4367,
		.noreturn = false
	},
	[4368] = {
		.no = 4368,
		.name = "sys_io_pgetevents_time32",
		.nargs = 6,
		.argt = argt_4368,
		.argsz = argsz_4368,
		.noreturn = false
	},
	[4393] = {
		.no = 4393,
		.name = "sys_semget",
		.nargs = 3,
		.argt = argt_4393,
		.argsz = argsz_4393,
		.noreturn = false
	},
	[4394] = {
		.no = 4394,
		.name = "sys_semctl",
		.nargs = 4,
		.argt = argt_4394,
		.argsz = argsz_4394,
		.noreturn = false
	},
	[4395] = {
		.no = 4395,
		.name = "sys_shmget",
		.nargs = 3,
		.argt = argt_4395,
		.argsz = argsz_4395,
		.noreturn = false
	},
	[4396] = {
		.no = 4396,
		.name = "sys_shmctl",
		.nargs = 3,
		.argt = argt_4396,
		.argsz = argsz_4396,
		.noreturn = false
	},
	[4397] = {
		.no = 4397,
		.name = "sys_shmat",
		.nargs = 3,
		.argt = argt_4397,
		.argsz = argsz_4397,
		.noreturn = false
	},
	[4398] = {
		.no = 4398,
		.name = "sys_shmdt",
		.nargs = 1,
		.argt = argt_4398,
		.argsz = argsz_4398,
		.noreturn = false
	},
	[4399] = {
		.no = 4399,
		.name = "sys_msgget",
		.nargs = 2,
		.argt = argt_4399,
		.argsz = argsz_4399,
		.noreturn = false
	},
	[4400] = {
		.no = 4400,
		.name = "sys_msgsnd",
		.nargs = 4,
		.argt = argt_4400,
		.argsz = argsz_4400,
		.noreturn = false
	},
	[4401] = {
		.no = 4401,
		.name = "sys_msgrcv",
		.nargs = 5,
		.argt = argt_4401,
		.argsz = argsz_4401,
		.noreturn = false
	},
	[4402] = {
		.no = 4402,
		.name = "sys_msgctl",
		.nargs = 3,
		.argt = argt_4402,
		.argsz = argsz_4402,
		.noreturn = false
	},
	[4403] = {
		.no = 4403,
		.name = "sys_clock_gettime",
		.nargs = 2,
		.argt = argt_4403,
		.argsz = argsz_4403,
		.noreturn = false
	},
	[4404] = {
		.no = 4404,
		.name = "sys_clock_settime",
		.nargs = 2,
		.argt = argt_4404,
		.argsz = argsz_4404,
		.noreturn = false
	},
	[4405] = {
		.no = 4405,
		.name = "sys_clock_adjtime",
		.nargs = 2,
		.argt = argt_4405,
		.argsz = argsz_4405,
		.noreturn = false
	},
	[4406] = {
		.no = 4406,
		.name = "sys_clock_getres",
		.nargs = 2,
		.argt = argt_4406,
		.argsz = argsz_4406,
		.noreturn = false
	},
	[4407] = {
		.no = 4407,
		.name = "sys_clock_nanosleep",
		.nargs = 4,
		.argt = argt_4407,
		.argsz = argsz_4407,
		.noreturn = false
	},
	[4408] = {
		.no = 4408,
		.name = "sys_timer_gettime",
		.nargs = 2,
		.argt = argt_4408,
		.argsz = argsz_4408,
		.noreturn = false
	},
	[4409] = {
		.no = 4409,
		.name = "sys_timer_settime",
		.nargs = 4,
		.argt = argt_4409,
		.argsz = argsz_4409,
		.noreturn = false
	},
	[4410] = {
		.no = 4410,
		.name = "sys_timerfd_gettime",
		.nargs = 2,
		.argt = argt_4410,
		.argsz = argsz_4410,
		.noreturn = false
	},
	[4411] = {
		.no = 4411,
		.name = "sys_timerfd_settime",
		.nargs = 4,
		.argt = argt_4411,
		.argsz = argsz_4411,
		.noreturn = false
	},
	[4412] = {
		.no = 4412,
		.name = "sys_utimensat",
		.nargs = 4,
		.argt = argt_4412,
		.argsz = argsz_4412,
		.noreturn = false
	},
	[4413] = {
		.no = 4413,
		.name = "sys_pselect6",
		.nargs = 6,
		.argt = argt_4413,
		.argsz = argsz_4413,
		.noreturn = false
	},
	[4414] = {
		.no = 4414,
		.name = "sys_ppoll",
		.nargs = 5,
		.argt = argt_4414,
		.argsz = argsz_4414,
		.noreturn = false
	},
	[4416] = {
		.no = 4416,
		.name = "sys_io_pgetevents",
		.nargs = 6,
		.argt = argt_4416,
		.argsz = argsz_4416,
		.noreturn = false
	},
	[4417] = {
		.no = 4417,
		.name = "sys_recvmmsg",
		.nargs = 5,
		.argt = argt_4417,
		.argsz = argsz_4417,
		.noreturn = false
	},
	[4418] = {
		.no = 4418,
		.name = "sys_mq_timedsend",
		.nargs = 5,
		.argt = argt_4418,
		.argsz = argsz_4418,
		.noreturn = false
	},
	[4419] = {
		.no = 4419,
		.name = "sys_mq_timedreceive",
		.nargs = 5,
		.argt = argt_4419,
		.argsz = argsz_4419,
		.noreturn = false
	},
	[4420] = {
		.no = 4420,
		.name = "sys_semtimedop",
		.nargs = 4,
		.argt = argt_4420,
		.argsz = argsz_4420,
		.noreturn = false
	},
	[4421] = {
		.no = 4421,
		.name = "sys_rt_sigtimedwait",
		.nargs = 4,
		.argt = argt_4421,
		.argsz = argsz_4421,
		.noreturn = false
	},
	[4422] = {
		.no = 4422,
		.name = "sys_futex",
		.nargs = 6,
		.argt = argt_4422,
		.argsz = argsz_4422,
		.noreturn = false
	},
	[4423] = {
		.no = 4423,
		.name = "sys_sched_rr_get_interval",
		.nargs = 2,
		.argt = argt_4423,
		.argsz = argsz_4423,
		.noreturn = false
	},
	[4424] = {
		.no = 4424,
		.name = "sys_pidfd_send_signal",
		.nargs = 4,
		.argt = argt_4424,
		.argsz = argsz_4424,
		.noreturn = false
	},
	[4425] = {
		.no = 4425,
		.name = "sys_io_uring_setup",
		.nargs = 2,
		.argt = argt_4425,
		.argsz = argsz_4425,
		.noreturn = false
	},
	[4426] = {
		.no = 4426,
		.name = "sys_io_uring_enter",
		.nargs = 6,
		.argt = argt_4426,
		.argsz = argsz_4426,
		.noreturn = false
	},
	[4427] = {
		.no = 4427,
		.name = "sys_io_uring_register",
		.nargs = 4,
		.argt = argt_4427,
		.argsz = argsz_4427,
		.noreturn = false
	},
	[4428] = {
		.no = 4428,
		.name = "sys_open_tree",
		.nargs = 3,
		.argt = argt_4428,
		.argsz = argsz_4428,
		.noreturn = false
	},
	[4429] = {
		.no = 4429,
		.name = "sys_move_mount",
		.nargs = 5,
		.argt = argt_4429,
		.argsz = argsz_4429,
		.noreturn = false
	},
	[4430] = {
		.no = 4430,
		.name = "sys_fsopen",
		.nargs = 2,
		.argt = argt_4430,
		.argsz = argsz_4430,
		.noreturn = false
	},
	[4431] = {
		.no = 4431,
		.name = "sys_fsconfig",
		.nargs = 5,
		.argt = argt_4431,
		.argsz = argsz_4431,
		.noreturn = false
	},
	[4432] = {
		.no = 4432,
		.name = "sys_fsmount",
		.nargs = 3,
		.argt = argt_4432,
		.argsz = argsz_4432,
		.noreturn = false
	},
	[4433] = {
		.no = 4433,
		.name = "sys_fspick",
		.nargs = 3,
		.argt = argt_4433,
		.argsz = argsz_4433,
		.noreturn = false
	},
	[4434] = {
		.no = 4434,
		.name = "sys_pidfd_open",
		.nargs = 2,
		.argt = argt_4434,
		.argsz = argsz_4434,
		.noreturn = false
	},
	[4437] = {
		.no = 4437,
		.name = "sys_openat2",
		.nargs = 4,
		.argt = argt_4437,
		.argsz = argsz_4437,
		.noreturn = false
	},
	[4438] = {
		.no = 4438,
		.name = "sys_pidfd_getfd",
		.nargs = 3,
		.argt = argt_4438,
		.argsz = argsz_4438,
		.noreturn = false
	},
	[4439] = {
		.no = 4439,
		.name = "sys_faccessat2",
		.nargs = 4,
		.argt = argt_4439,
		.argsz = argsz_4439,
		.noreturn = false
	},
	
};

syscall_meta_t __syscall_meta = {
	.max = MAX_SYSCALL_NO,
	.max_generic = MAX_SYSCALL_GENERIC_NO,
	.max_args = MAX_SYSCALL_ARGS
};

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=c: */