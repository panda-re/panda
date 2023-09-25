#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls2_info.h"
#include "hooks/hooks_int_fns.h"
#include "hw_proc_id/hw_proc_id_ext.h"

extern const syscall_info_t *syscall_info;
extern const syscall_meta_t *syscall_meta;

extern "C" {
#include "syscalls_ext_typedefs.h"
#include "syscall_ppp_extern_enter.h"
#include "syscall_ppp_extern_return.h"
}

/**
 * @brief Called when a system call invocation is identified.
 * Invokes all registered callbacks that should run for the call.
 *
 * Additionally, stores the context of the system call (number, asid,
 * arguments, return address) to prepare for handling the respective
 * system call return callbacks.
 */
void syscall_enter_switch_windows_7_x64(CPUState *cpu, target_ptr_t pc, int static_callno) {
#if defined(TARGET_X86_64)
	CPUArchState *env = (CPUArchState*)cpu->env_ptr;
	syscall_ctx_t ctx = {0};
	if (static_callno == -1) {
	  ctx.no = env->regs[R_EAX];
	} else {
	  ctx.no = static_callno;
	}
	ctx.asid = get_id(cpu);
	ctx.retaddr = calc_retaddr(cpu, pc);
	ctx.double_return = false;
	bool panda_noreturn;	// true if PANDA should not track the return of this system call
	const syscall_info_t *call = NULL;
	syscall_info_t zero = {0};
	if (syscall_meta != NULL && ctx.no <= syscall_meta->max_generic) {
	  // If the syscall_info object from dso_info_....c doesn't have an entry
	  // for this syscall, we want to leave it as a NULL pointer
	  if (memcmp(&syscall_info[ctx.no], &zero, sizeof(syscall_info_t)) != 0) {
		call = &syscall_info[ctx.no];
	  }
	}

	switch (ctx.no) {
	// 0 NTSTATUS NtMapUserPhysicalPagesScatter ['PVOID *VirtualAddresses', 'ULONG_PTR NumberOfPages', 'PULONG_PTR UserPfnArray']
	case 0: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtMapUserPhysicalPagesScatter_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtMapUserPhysicalPagesScatter_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 1 NTSTATUS NtWaitForSingleObject ['HANDLE Handle', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout']
	case 1: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWaitForSingleObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWaitForSingleObject_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 2 NTSTATUS NtCallbackReturn ['PVOID OutputBuffer', 'ULONG OutputLength', 'NTSTATUS Status']
	case 2: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCallbackReturn_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCallbackReturn_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 3 NTSTATUS NtReadFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length', 'PLARGE_INTEGER ByteOffset', 'PULONG Key']
	case 3: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReadFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReadFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
	}; break;
	// 4 NTSTATUS NtDeviceIoControlFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG IoControlCode', 'PVOID InputBuffer', 'ULONG InputBufferLength', 'PVOID OutputBuffer', 'ULONG OutputBufferLength']
	case 4: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		uint32_t arg9 = get_32(cpu, &ctx, 9);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDeviceIoControlFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtDeviceIoControlFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
	}; break;
	// 5 NTSTATUS NtWriteFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length', 'PLARGE_INTEGER ByteOffset', 'PULONG Key']
	case 5: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWriteFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWriteFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
	}; break;
	// 6 NTSTATUS NtRemoveIoCompletion ['HANDLE IoCompletionHandle', 'PVOID *KeyContext', 'PVOID *ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PLARGE_INTEGER Timeout']
	case 6: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRemoveIoCompletion_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRemoveIoCompletion_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 7 NTSTATUS NtReleaseSemaphore ['HANDLE SemaphoreHandle', 'LONG ReleaseCount', 'PLONG PreviousCount']
	case 7: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReleaseSemaphore_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReleaseSemaphore_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 8 NTSTATUS NtReplyWaitReceivePort ['HANDLE PortHandle', 'PVOID *PortContext', 'PPORT_MESSAGE ReplyMessage', 'PPORT_MESSAGE ReceiveMessage']
	case 8: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReplyWaitReceivePort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReplyWaitReceivePort_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 9 NTSTATUS NtReplyPort ['HANDLE PortHandle', 'PPORT_MESSAGE ReplyMessage']
	case 9: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReplyPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReplyPort_enter, cpu, pc, arg0, arg1);
	}; break;
	// 10 NTSTATUS NtSetInformationThread ['HANDLE ThreadHandle', 'THREADINFOCLASS ThreadInformationClass', 'PVOID ThreadInformation', 'ULONG ThreadInformationLength']
	case 10: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetInformationThread_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 11 NTSTATUS NtSetEvent ['HANDLE EventHandle', 'PLONG PreviousState']
	case 11: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetEvent_enter, cpu, pc, arg0, arg1);
	}; break;
	// 12 NTSTATUS NtClose ['HANDLE Handle']
	case 12: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtClose_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtClose_enter, cpu, pc, arg0);
	}; break;
	// 13 NTSTATUS NtQueryObject ['HANDLE Handle', 'OBJECT_INFORMATION_CLASS ObjectInformationClass', 'PVOID ObjectInformation', 'ULONG ObjectInformationLength', 'PULONG ReturnLength']
	case 13: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryObject_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 14 NTSTATUS NtQueryInformationFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID FileInformation', 'ULONG Length', 'FILE_INFORMATION_CLASS FileInformationClass']
	case 14: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInformationFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtQueryInformationFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 15 NTSTATUS NtOpenKey ['PHANDLE KeyHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 15: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenKey_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 16 NTSTATUS NtEnumerateValueKey ['HANDLE KeyHandle', 'ULONG Index', 'KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass', 'PVOID KeyValueInformation', 'ULONG Length', 'PULONG ResultLength']
	case 16: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtEnumerateValueKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtEnumerateValueKey_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 17 NTSTATUS NtFindAtom ['PWSTR AtomName', 'ULONG Length', 'PRTL_ATOM Atom']
	case 17: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtFindAtom_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtFindAtom_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 18 NTSTATUS NtQueryDefaultLocale ['BOOLEAN UserProfile', 'PLCID DefaultLocaleId']
	case 18: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryDefaultLocale_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryDefaultLocale_enter, cpu, pc, arg0, arg1);
	}; break;
	// 19 NTSTATUS NtQueryKey ['HANDLE KeyHandle', 'KEY_INFORMATION_CLASS KeyInformationClass', 'PVOID KeyInformation', 'ULONG Length', 'PULONG ResultLength']
	case 19: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryKey_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 20 NTSTATUS NtQueryValueKey ['HANDLE KeyHandle', 'PUNICODE_STRING ValueName', 'KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass', 'PVOID KeyValueInformation', 'ULONG Length', 'PULONG ResultLength']
	case 20: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryValueKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryValueKey_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 21 NTSTATUS NtAllocateVirtualMemory ['HANDLE ProcessHandle', 'PVOID *BaseAddress', 'ULONG_PTR ZeroBits', 'PSIZE_T RegionSize', 'ULONG AllocationType', 'ULONG Protect']
	case 21: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAllocateVirtualMemory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtAllocateVirtualMemory_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 22 NTSTATUS NtQueryInformationProcess ['HANDLE ProcessHandle', 'PROCESSINFOCLASS ProcessInformationClass', 'PVOID ProcessInformation', 'ULONG ProcessInformationLength', 'PULONG ReturnLength']
	case 22: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInformationProcess_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryInformationProcess_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 23 NTSTATUS NtWaitForMultipleObjects32 ['ULONG Count', 'LONG Handles[]', 'WAIT_TYPE WaitType', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout']
	case 23: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWaitForMultipleObjects32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWaitForMultipleObjects32_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 24 NTSTATUS NtWriteFileGather ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PFILE_SEGMENT_ELEMENT SegmentArray', 'ULONG Length', 'PLARGE_INTEGER ByteOffset', 'PULONG Key']
	case 24: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWriteFileGather_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWriteFileGather_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
	}; break;
	// 25 NTSTATUS NtSetInformationProcess ['HANDLE ProcessHandle', 'PROCESSINFOCLASS ProcessInformationClass', 'PVOID ProcessInformation', 'ULONG ProcessInformationLength']
	case 25: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationProcess_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetInformationProcess_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 26 NTSTATUS NtCreateKey ['PHANDLE KeyHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG TitleIndex', 'PUNICODE_STRING Class', 'ULONG CreateOptions', 'PULONG Disposition']
	case 26: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateKey_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 27 NTSTATUS NtFreeVirtualMemory ['HANDLE ProcessHandle', 'PVOID *BaseAddress', 'PSIZE_T RegionSize', 'ULONG FreeType']
	case 27: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtFreeVirtualMemory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtFreeVirtualMemory_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 28 NTSTATUS NtImpersonateClientOfPort ['HANDLE PortHandle', 'PPORT_MESSAGE Message']
	case 28: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtImpersonateClientOfPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtImpersonateClientOfPort_enter, cpu, pc, arg0, arg1);
	}; break;
	// 29 NTSTATUS NtReleaseMutant ['HANDLE MutantHandle', 'PLONG PreviousCount']
	case 29: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReleaseMutant_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReleaseMutant_enter, cpu, pc, arg0, arg1);
	}; break;
	// 30 NTSTATUS NtQueryInformationToken ['HANDLE TokenHandle', 'TOKEN_INFORMATION_CLASS TokenInformationClass', 'PVOID TokenInformation', 'ULONG TokenInformationLength', 'PULONG ReturnLength']
	case 30: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInformationToken_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryInformationToken_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 31 NTSTATUS NtRequestWaitReplyPort ['HANDLE PortHandle', 'PPORT_MESSAGE RequestMessage', 'PPORT_MESSAGE ReplyMessage']
	case 31: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRequestWaitReplyPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRequestWaitReplyPort_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 32 NTSTATUS NtQueryVirtualMemory ['HANDLE ProcessHandle', 'PVOID BaseAddress', 'MEMORY_INFORMATION_CLASS MemoryInformationClass', 'PVOID MemoryInformation', 'SIZE_T MemoryInformationLength', 'PSIZE_T ReturnLength']
	case 32: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryVirtualMemory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryVirtualMemory_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 33 NTSTATUS NtOpenThreadToken ['HANDLE ThreadHandle', 'ACCESS_MASK DesiredAccess', 'BOOLEAN OpenAsSelf', 'PHANDLE TokenHandle']
	case 33: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenThreadToken_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenThreadToken_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 34 NTSTATUS NtQueryInformationThread ['HANDLE ThreadHandle', 'THREADINFOCLASS ThreadInformationClass', 'PVOID ThreadInformation', 'ULONG ThreadInformationLength', 'PULONG ReturnLength']
	case 34: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInformationThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryInformationThread_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 35 NTSTATUS NtOpenProcess ['PHANDLE ProcessHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PCLIENT_ID ClientId']
	case 35: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenProcess_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenProcess_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 36 NTSTATUS NtSetInformationFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID FileInformation', 'ULONG Length', 'FILE_INFORMATION_CLASS FileInformationClass']
	case 36: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetInformationFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 37 NTSTATUS NtMapViewOfSection ['HANDLE SectionHandle', 'HANDLE ProcessHandle', 'PVOID *BaseAddress', 'ULONG_PTR ZeroBits', 'SIZE_T CommitSize', 'PLARGE_INTEGER SectionOffset', 'PSIZE_T ViewSize', 'SECTION_INHERIT InheritDisposition', 'ULONG AllocationType', 'WIN32_PROTECTION_MASK Win32Protect']
	case 37: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		uint32_t arg9 = get_32(cpu, &ctx, 9);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtMapViewOfSection_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtMapViewOfSection_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
	}; break;
	// 38 NTSTATUS NtAccessCheckAndAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'PUNICODE_STRING ObjectTypeName', 'PUNICODE_STRING ObjectName', 'PSECURITY_DESCRIPTOR SecurityDescriptor', 'ACCESS_MASK DesiredAccess', 'PGENERIC_MAPPING GenericMapping', 'BOOLEAN ObjectCreation', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus', 'PBOOLEAN GenerateOnClose']
	case 38: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		uint64_t arg10 = get_64(cpu, &ctx, 10);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAccessCheckAndAuditAlarm_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAccessCheckAndAuditAlarm_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
	}; break;
	// 39 NTSTATUS NtUnmapViewOfSection ['HANDLE ProcessHandle', 'PVOID BaseAddress']
	case 39: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtUnmapViewOfSection_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtUnmapViewOfSection_enter, cpu, pc, arg0, arg1);
	}; break;
	// 40 NTSTATUS NtReplyWaitReceivePortEx ['HANDLE PortHandle', 'PVOID *PortContext', 'PPORT_MESSAGE ReplyMessage', 'PPORT_MESSAGE ReceiveMessage', 'PLARGE_INTEGER Timeout']
	case 40: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReplyWaitReceivePortEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReplyWaitReceivePortEx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 41 NTSTATUS NtTerminateProcess ['HANDLE ProcessHandle', 'NTSTATUS ExitStatus']
	case 41: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtTerminateProcess_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtTerminateProcess_enter, cpu, pc, arg0, arg1);
	}; break;
	// 42 NTSTATUS NtSetEventBoostPriority ['HANDLE EventHandle']
	case 42: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetEventBoostPriority_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetEventBoostPriority_enter, cpu, pc, arg0);
	}; break;
	// 43 NTSTATUS NtReadFileScatter ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PFILE_SEGMENT_ELEMENT SegmentArray', 'ULONG Length', 'PLARGE_INTEGER ByteOffset', 'PULONG Key']
	case 43: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReadFileScatter_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReadFileScatter_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
	}; break;
	// 44 NTSTATUS NtOpenThreadTokenEx ['HANDLE ThreadHandle', 'ACCESS_MASK DesiredAccess', 'BOOLEAN OpenAsSelf', 'ULONG HandleAttributes', 'PHANDLE TokenHandle']
	case 44: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenThreadTokenEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenThreadTokenEx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 45 NTSTATUS NtOpenProcessTokenEx ['HANDLE ProcessHandle', 'ACCESS_MASK DesiredAccess', 'ULONG HandleAttributes', 'PHANDLE TokenHandle']
	case 45: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenProcessTokenEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenProcessTokenEx_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 46 NTSTATUS NtQueryPerformanceCounter ['PLARGE_INTEGER PerformanceCounter', 'PLARGE_INTEGER PerformanceFrequency']
	case 46: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryPerformanceCounter_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryPerformanceCounter_enter, cpu, pc, arg0, arg1);
	}; break;
	// 47 NTSTATUS NtEnumerateKey ['HANDLE KeyHandle', 'ULONG Index', 'KEY_INFORMATION_CLASS KeyInformationClass', 'PVOID KeyInformation', 'ULONG Length', 'PULONG ResultLength']
	case 47: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtEnumerateKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtEnumerateKey_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 48 NTSTATUS NtOpenFile ['PHANDLE FileHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG ShareAccess', 'ULONG OpenOptions']
	case 48: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtOpenFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 49 NTSTATUS NtDelayExecution ['BOOLEAN Alertable', 'PLARGE_INTEGER DelayInterval']
	case 49: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDelayExecution_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtDelayExecution_enter, cpu, pc, arg0, arg1);
	}; break;
	// 50 NTSTATUS NtQueryDirectoryFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID FileInformation', 'ULONG Length', 'FILE_INFORMATION_CLASS FileInformationClass', 'BOOLEAN ReturnSingleEntry', 'PUNICODE_STRING FileName', 'BOOLEAN RestartScan']
	case 50: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		uint32_t arg10 = get_32(cpu, &ctx, 10);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryDirectoryFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtQueryDirectoryFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
	}; break;
	// 51 NTSTATUS NtQuerySystemInformation ['SYSTEM_INFORMATION_CLASS SystemInformationClass', 'PVOID SystemInformation', 'ULONG SystemInformationLength', 'PULONG ReturnLength']
	case 51: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQuerySystemInformation_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQuerySystemInformation_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 52 NTSTATUS NtOpenSection ['PHANDLE SectionHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 52: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenSection_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenSection_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 53 NTSTATUS NtQueryTimer ['HANDLE TimerHandle', 'TIMER_INFORMATION_CLASS TimerInformationClass', 'PVOID TimerInformation', 'ULONG TimerInformationLength', 'PULONG ReturnLength']
	case 53: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryTimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryTimer_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 54 NTSTATUS NtFsControlFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG IoControlCode', 'PVOID InputBuffer', 'ULONG InputBufferLength', 'PVOID OutputBuffer', 'ULONG OutputBufferLength']
	case 54: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		uint32_t arg9 = get_32(cpu, &ctx, 9);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtFsControlFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtFsControlFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
	}; break;
	// 55 NTSTATUS NtWriteVirtualMemory ['HANDLE ProcessHandle', 'PVOID BaseAddress', 'PVOID Buffer', 'SIZE_T BufferSize', 'PSIZE_T NumberOfBytesWritten']
	case 55: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWriteVirtualMemory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWriteVirtualMemory_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 56 NTSTATUS NtCloseObjectAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'BOOLEAN GenerateOnClose']
	case 56: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCloseObjectAuditAlarm_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCloseObjectAuditAlarm_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 57 NTSTATUS NtDuplicateObject ['HANDLE SourceProcessHandle', 'HANDLE SourceHandle', 'HANDLE TargetProcessHandle', 'PHANDLE TargetHandle', 'ACCESS_MASK DesiredAccess', 'ULONG HandleAttributes', 'ULONG Options']
	case 57: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDuplicateObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtDuplicateObject_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 58 NTSTATUS NtQueryAttributesFile ['POBJECT_ATTRIBUTES ObjectAttributes', 'PFILE_BASIC_INFORMATION FileInformation']
	case 58: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryAttributesFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryAttributesFile_enter, cpu, pc, arg0, arg1);
	}; break;
	// 59 NTSTATUS NtClearEvent ['HANDLE EventHandle']
	case 59: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtClearEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtClearEvent_enter, cpu, pc, arg0);
	}; break;
	// 60 NTSTATUS NtReadVirtualMemory ['HANDLE ProcessHandle', 'PVOID BaseAddress', 'PVOID Buffer', 'SIZE_T BufferSize', 'PSIZE_T NumberOfBytesRead']
	case 60: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReadVirtualMemory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReadVirtualMemory_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 61 NTSTATUS NtOpenEvent ['PHANDLE EventHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 61: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenEvent_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 62 NTSTATUS NtAdjustPrivilegesToken ['HANDLE TokenHandle', 'BOOLEAN DisableAllPrivileges', 'PTOKEN_PRIVILEGES NewState', 'ULONG BufferLength', 'PTOKEN_PRIVILEGES PreviousState', 'PULONG ReturnLength']
	case 62: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAdjustPrivilegesToken_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAdjustPrivilegesToken_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 63 NTSTATUS NtDuplicateToken ['HANDLE ExistingTokenHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'BOOLEAN EffectiveOnly', 'TOKEN_TYPE TokenType', 'PHANDLE NewTokenHandle']
	case 63: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDuplicateToken_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtDuplicateToken_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 64 NTSTATUS NtContinue ['PCONTEXT ContextRecord', 'BOOLEAN TestAlert']
	case 64: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtContinue_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtContinue_enter, cpu, pc, arg0, arg1);
	}; break;
	// 65 NTSTATUS NtQueryDefaultUILanguage ['LANGID *DefaultUILanguageId']
	case 65: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryDefaultUILanguage_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryDefaultUILanguage_enter, cpu, pc, arg0);
	}; break;
	// 66 NTSTATUS NtQueueApcThread ['HANDLE ThreadHandle', 'PPS_APC_ROUTINE ApcRoutine', 'PVOID ApcArgument1', 'PVOID ApcArgument2', 'PVOID ApcArgument3']
	case 66: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueueApcThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueueApcThread_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 67 NTSTATUS NtYieldExecution ['']
	case 67: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtYieldExecution_enter, cpu, pc);
	}; break;
	// 68 NTSTATUS NtAddAtom ['PWSTR AtomName', 'ULONG Length', 'PRTL_ATOM Atom']
	case 68: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAddAtom_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAddAtom_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 69 NTSTATUS NtCreateEvent ['PHANDLE EventHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'EVENT_TYPE EventType', 'BOOLEAN InitialState']
	case 69: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreateEvent_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 70 NTSTATUS NtQueryVolumeInformationFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID FsInformation', 'ULONG Length', 'FS_INFORMATION_CLASS FsInformationClass']
	case 70: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryVolumeInformationFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtQueryVolumeInformationFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 71 NTSTATUS NtCreateSection ['PHANDLE SectionHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PLARGE_INTEGER MaximumSize', 'ULONG SectionPageProtection', 'ULONG AllocationAttributes', 'HANDLE FileHandle']
	case 71: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateSection_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateSection_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 72 NTSTATUS NtFlushBuffersFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock']
	case 72: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtFlushBuffersFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtFlushBuffersFile_enter, cpu, pc, arg0, arg1);
	}; break;
	// 73 NTSTATUS NtApphelpCacheControl ['APPHELPCOMMAND type', 'PVOID buf']
	case 73: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtApphelpCacheControl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtApphelpCacheControl_enter, cpu, pc, arg0, arg1);
	}; break;
	// 74 NTSTATUS NtCreateProcessEx ['PHANDLE ProcessHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'HANDLE ParentProcess', 'ULONG Flags', 'HANDLE SectionHandle', 'HANDLE DebugPort', 'HANDLE ExceptionPort', 'ULONG JobMemberLevel']
	case 74: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateProcessEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreateProcessEx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
	}; break;
	// 75 NTSTATUS NtCreateThread ['PHANDLE ThreadHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'HANDLE ProcessHandle', 'PCLIENT_ID ClientId', 'PCONTEXT ThreadContext', 'PINITIAL_TEB InitialTeb', 'BOOLEAN CreateSuspended']
	case 75: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreateThread_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	}; break;
	// 76 NTSTATUS NtIsProcessInJob ['HANDLE ProcessHandle', 'HANDLE JobHandle']
	case 76: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtIsProcessInJob_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtIsProcessInJob_enter, cpu, pc, arg0, arg1);
	}; break;
	// 77 NTSTATUS NtProtectVirtualMemory ['HANDLE ProcessHandle', 'PVOID *BaseAddress', 'PSIZE_T RegionSize', 'WIN32_PROTECTION_MASK NewProtectWin32', 'PULONG OldProtect']
	case 77: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtProtectVirtualMemory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtProtectVirtualMemory_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 78 NTSTATUS NtQuerySection ['HANDLE SectionHandle', 'SECTION_INFORMATION_CLASS SectionInformationClass', 'PVOID SectionInformation', 'SIZE_T SectionInformationLength', 'PSIZE_T ReturnLength']
	case 78: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQuerySection_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQuerySection_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 79 NTSTATUS NtResumeThread ['HANDLE ThreadHandle', 'PULONG PreviousSuspendCount']
	case 79: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtResumeThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtResumeThread_enter, cpu, pc, arg0, arg1);
	}; break;
	// 80 NTSTATUS NtTerminateThread ['HANDLE ThreadHandle', 'NTSTATUS ExitStatus']
	case 80: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtTerminateThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtTerminateThread_enter, cpu, pc, arg0, arg1);
	}; break;
	// 81 NTSTATUS NtReadRequestData ['HANDLE PortHandle', 'PPORT_MESSAGE Message', 'ULONG DataEntryIndex', 'PVOID Buffer', 'SIZE_T BufferSize', 'PSIZE_T NumberOfBytesRead']
	case 81: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReadRequestData_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReadRequestData_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 82 NTSTATUS NtCreateFile ['PHANDLE FileHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PIO_STATUS_BLOCK IoStatusBlock', 'PLARGE_INTEGER AllocationSize', 'ULONG FileAttributes', 'ULONG ShareAccess', 'ULONG CreateDisposition', 'ULONG CreateOptions', 'PVOID EaBuffer', 'ULONG EaLength']
	case 82: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		uint32_t arg10 = get_32(cpu, &ctx, 10);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreateFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
	}; break;
	// 83 NTSTATUS NtQueryEvent ['HANDLE EventHandle', 'EVENT_INFORMATION_CLASS EventInformationClass', 'PVOID EventInformation', 'ULONG EventInformationLength', 'PULONG ReturnLength']
	case 83: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryEvent_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 84 NTSTATUS NtWriteRequestData ['HANDLE PortHandle', 'PPORT_MESSAGE Message', 'ULONG DataEntryIndex', 'PVOID Buffer', 'SIZE_T BufferSize', 'PSIZE_T NumberOfBytesWritten']
	case 84: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWriteRequestData_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWriteRequestData_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 85 NTSTATUS NtOpenDirectoryObject ['PHANDLE DirectoryHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 85: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenDirectoryObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenDirectoryObject_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 86 NTSTATUS NtAccessCheckByTypeAndAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'PUNICODE_STRING ObjectTypeName', 'PUNICODE_STRING ObjectName', 'PSECURITY_DESCRIPTOR SecurityDescriptor', 'PSID PrincipalSelfSid', 'ACCESS_MASK DesiredAccess', 'AUDIT_EVENT_TYPE AuditType', 'ULONG Flags', 'POBJECT_TYPE_LIST ObjectTypeList', 'ULONG ObjectTypeListLength', 'PGENERIC_MAPPING GenericMapping', 'BOOLEAN ObjectCreation', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus', 'PBOOLEAN GenerateOnClose']
	case 86: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		uint32_t arg10 = get_32(cpu, &ctx, 10);
		uint64_t arg11 = get_64(cpu, &ctx, 11);
		uint32_t arg12 = get_32(cpu, &ctx, 12);
		uint64_t arg13 = get_64(cpu, &ctx, 13);
		uint64_t arg14 = get_64(cpu, &ctx, 14);
		uint64_t arg15 = get_64(cpu, &ctx, 15);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAccessCheckByTypeAndAuditAlarm_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint32_t));
			memcpy(ctx.args[11], &arg11, sizeof(uint64_t));
			memcpy(ctx.args[12], &arg12, sizeof(uint32_t));
			memcpy(ctx.args[13], &arg13, sizeof(uint64_t));
			memcpy(ctx.args[14], &arg14, sizeof(uint64_t));
			memcpy(ctx.args[15], &arg15, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAccessCheckByTypeAndAuditAlarm_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15);
	}; break;
	// 87 NTSTATUS NtQuerySystemTime ['PLARGE_INTEGER SystemTime']
	case 87: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQuerySystemTime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQuerySystemTime_enter, cpu, pc, arg0);
	}; break;
	// 88 NTSTATUS NtWaitForMultipleObjects ['ULONG Count', 'HANDLE Handles[]', 'WAIT_TYPE WaitType', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout']
	case 88: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWaitForMultipleObjects_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWaitForMultipleObjects_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 89 NTSTATUS NtSetInformationObject ['HANDLE Handle', 'OBJECT_INFORMATION_CLASS ObjectInformationClass', 'PVOID ObjectInformation', 'ULONG ObjectInformationLength']
	case 89: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetInformationObject_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 90 NTSTATUS NtCancelIoFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock']
	case 90: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCancelIoFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCancelIoFile_enter, cpu, pc, arg0, arg1);
	}; break;
	// 91 NTSTATUS NtTraceEvent ['HANDLE TraceHandle', 'ULONG Flags', 'ULONG FieldSize', 'PVOID Fields']
	case 91: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtTraceEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtTraceEvent_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 92 NTSTATUS NtPowerInformation ['POWER_INFORMATION_LEVEL InformationLevel', 'PVOID InputBuffer', 'ULONG InputBufferLength', 'PVOID OutputBuffer', 'ULONG OutputBufferLength']
	case 92: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtPowerInformation_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtPowerInformation_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 93 NTSTATUS NtSetValueKey ['HANDLE KeyHandle', 'PUNICODE_STRING ValueName', 'ULONG TitleIndex', 'ULONG Type', 'PVOID Data', 'ULONG DataSize']
	case 93: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetValueKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetValueKey_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 94 NTSTATUS NtCancelTimer ['HANDLE TimerHandle', 'PBOOLEAN CurrentState']
	case 94: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCancelTimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCancelTimer_enter, cpu, pc, arg0, arg1);
	}; break;
	// 95 NTSTATUS NtSetTimer ['HANDLE TimerHandle', 'PLARGE_INTEGER DueTime', 'PTIMER_APC_ROUTINE TimerApcRoutine', 'PVOID TimerContext', 'BOOLEAN WakeTimer', 'LONG Period', 'PBOOLEAN PreviousState']
	case 95: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		int32_t arg5 = get_s32(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetTimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(int32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetTimer_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 96 NTSTATUS NtAcceptConnectPort ['PHANDLE PortHandle', 'PVOID PortContext', 'PPORT_MESSAGE ConnectionRequest', 'BOOLEAN AcceptConnection', 'PPORT_VIEW ServerView', 'PREMOTE_PORT_VIEW ClientView']
	case 96: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAcceptConnectPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAcceptConnectPort_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 97 NTSTATUS NtAccessCheck ['PSECURITY_DESCRIPTOR SecurityDescriptor', 'HANDLE ClientToken', 'ACCESS_MASK DesiredAccess', 'PGENERIC_MAPPING GenericMapping', 'PPRIVILEGE_SET PrivilegeSet', 'PULONG PrivilegeSetLength', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus']
	case 97: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAccessCheck_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAccessCheck_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	}; break;
	// 98 NTSTATUS NtAccessCheckByType ['PSECURITY_DESCRIPTOR SecurityDescriptor', 'PSID PrincipalSelfSid', 'HANDLE ClientToken', 'ACCESS_MASK DesiredAccess', 'POBJECT_TYPE_LIST ObjectTypeList', 'ULONG ObjectTypeListLength', 'PGENERIC_MAPPING GenericMapping', 'PPRIVILEGE_SET PrivilegeSet', 'PULONG PrivilegeSetLength', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus']
	case 98: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		uint64_t arg10 = get_64(cpu, &ctx, 10);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAccessCheckByType_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAccessCheckByType_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
	}; break;
	// 99 NTSTATUS NtAccessCheckByTypeResultList ['PSECURITY_DESCRIPTOR SecurityDescriptor', 'PSID PrincipalSelfSid', 'HANDLE ClientToken', 'ACCESS_MASK DesiredAccess', 'POBJECT_TYPE_LIST ObjectTypeList', 'ULONG ObjectTypeListLength', 'PGENERIC_MAPPING GenericMapping', 'PPRIVILEGE_SET PrivilegeSet', 'PULONG PrivilegeSetLength', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus']
	case 99: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		uint64_t arg10 = get_64(cpu, &ctx, 10);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAccessCheckByTypeResultList_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAccessCheckByTypeResultList_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
	}; break;
	// 100 NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'PUNICODE_STRING ObjectTypeName', 'PUNICODE_STRING ObjectName', 'PSECURITY_DESCRIPTOR SecurityDescriptor', 'PSID PrincipalSelfSid', 'ACCESS_MASK DesiredAccess', 'AUDIT_EVENT_TYPE AuditType', 'ULONG Flags', 'POBJECT_TYPE_LIST ObjectTypeList', 'ULONG ObjectTypeListLength', 'PGENERIC_MAPPING GenericMapping', 'BOOLEAN ObjectCreation', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus', 'PBOOLEAN GenerateOnClose']
	case 100: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		uint32_t arg10 = get_32(cpu, &ctx, 10);
		uint64_t arg11 = get_64(cpu, &ctx, 11);
		uint32_t arg12 = get_32(cpu, &ctx, 12);
		uint64_t arg13 = get_64(cpu, &ctx, 13);
		uint64_t arg14 = get_64(cpu, &ctx, 14);
		uint64_t arg15 = get_64(cpu, &ctx, 15);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAccessCheckByTypeResultListAndAuditAlarm_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint32_t));
			memcpy(ctx.args[11], &arg11, sizeof(uint64_t));
			memcpy(ctx.args[12], &arg12, sizeof(uint32_t));
			memcpy(ctx.args[13], &arg13, sizeof(uint64_t));
			memcpy(ctx.args[14], &arg14, sizeof(uint64_t));
			memcpy(ctx.args[15], &arg15, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAccessCheckByTypeResultListAndAuditAlarm_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15);
	}; break;
	// 101 NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarmByHandle ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'HANDLE ClientToken', 'PUNICODE_STRING ObjectTypeName', 'PUNICODE_STRING ObjectName', 'PSECURITY_DESCRIPTOR SecurityDescriptor', 'PSID PrincipalSelfSid', 'ACCESS_MASK DesiredAccess', 'AUDIT_EVENT_TYPE AuditType', 'ULONG Flags', 'POBJECT_TYPE_LIST ObjectTypeList', 'ULONG ObjectTypeListLength', 'PGENERIC_MAPPING GenericMapping', 'BOOLEAN ObjectCreation', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus', 'PBOOLEAN GenerateOnClose']
	case 101: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		uint32_t arg9 = get_32(cpu, &ctx, 9);
		uint64_t arg10 = get_64(cpu, &ctx, 10);
		uint32_t arg11 = get_32(cpu, &ctx, 11);
		uint64_t arg12 = get_64(cpu, &ctx, 12);
		uint32_t arg13 = get_32(cpu, &ctx, 13);
		uint64_t arg14 = get_64(cpu, &ctx, 14);
		uint64_t arg15 = get_64(cpu, &ctx, 15);
		uint64_t arg16 = get_64(cpu, &ctx, 16);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAccessCheckByTypeResultListAndAuditAlarmByHandle_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint32_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint64_t));
			memcpy(ctx.args[11], &arg11, sizeof(uint32_t));
			memcpy(ctx.args[12], &arg12, sizeof(uint64_t));
			memcpy(ctx.args[13], &arg13, sizeof(uint32_t));
			memcpy(ctx.args[14], &arg14, sizeof(uint64_t));
			memcpy(ctx.args[15], &arg15, sizeof(uint64_t));
			memcpy(ctx.args[16], &arg16, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAccessCheckByTypeResultListAndAuditAlarmByHandle_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15, arg16);
	}; break;
	// 102 NTSTATUS NtAddBootEntry ['PBOOT_ENTRY BootEntry', 'PULONG Id']
	case 102: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAddBootEntry_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAddBootEntry_enter, cpu, pc, arg0, arg1);
	}; break;
	// 103 NTSTATUS NtAddDriverEntry ['PEFI_DRIVER_ENTRY DriverEntry', 'PULONG Id']
	case 103: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAddDriverEntry_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAddDriverEntry_enter, cpu, pc, arg0, arg1);
	}; break;
	// 104 NTSTATUS NtAdjustGroupsToken ['HANDLE TokenHandle', 'BOOLEAN ResetToDefault', 'PTOKEN_GROUPS NewState', 'ULONG BufferLength', 'PTOKEN_GROUPS PreviousState', 'PULONG ReturnLength']
	case 104: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAdjustGroupsToken_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAdjustGroupsToken_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 105 NTSTATUS NtAlertResumeThread ['HANDLE ThreadHandle', 'PULONG PreviousSuspendCount']
	case 105: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlertResumeThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlertResumeThread_enter, cpu, pc, arg0, arg1);
	}; break;
	// 106 NTSTATUS NtAlertThread ['HANDLE ThreadHandle']
	case 106: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlertThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlertThread_enter, cpu, pc, arg0);
	}; break;
	// 107 NTSTATUS NtAllocateLocallyUniqueId ['PLUID Luid']
	case 107: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAllocateLocallyUniqueId_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAllocateLocallyUniqueId_enter, cpu, pc, arg0);
	}; break;
	// 108 NTSTATUS NtAllocateReserveObject ['PHANDLE MemoryReserveHandle', 'POBJECT_ATTRIBUTES ObjectAttributes', 'MEMORY_RESERVE_TYPE Type']
	case 108: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAllocateReserveObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtAllocateReserveObject_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 109 NTSTATUS NtAllocateUserPhysicalPages ['HANDLE ProcessHandle', 'PULONG_PTR NumberOfPages', 'PULONG_PTR UserPfnArray']
	case 109: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAllocateUserPhysicalPages_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAllocateUserPhysicalPages_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 110 NTSTATUS NtAllocateUuids ['PULARGE_INTEGER Time', 'PULONG Range', 'PULONG Sequence', 'PCHAR Seed']
	case 110: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAllocateUuids_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAllocateUuids_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 111 NTSTATUS NtAlpcAcceptConnectPort ['PHANDLE PortHandle', 'HANDLE ConnectionPortHandle', 'ULONG Flags', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PALPC_PORT_ATTRIBUTES PortAttributes', 'PVOID PortContext', 'PPORT_MESSAGE ConnectionRequest', 'PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes', 'BOOLEAN AcceptConnection']
	case 111: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcAcceptConnectPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtAlpcAcceptConnectPort_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
	}; break;
	// 112 NTSTATUS NtAlpcCancelMessage ['HANDLE PortHandle', 'ULONG Flags', 'PALPC_CONTEXT_ATTR MessageContext']
	case 112: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcCancelMessage_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcCancelMessage_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 113 NTSTATUS NtAlpcConnectPort ['PHANDLE PortHandle', 'PUNICODE_STRING PortName', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PALPC_PORT_ATTRIBUTES PortAttributes', 'ULONG Flags', 'PSID RequiredServerSid', 'PPORT_MESSAGE ConnectionMessage', 'PULONG BufferLength', 'PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes', 'PALPC_MESSAGE_ATTRIBUTES InMessageAttributes', 'PLARGE_INTEGER Timeout']
	case 113: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		uint64_t arg10 = get_64(cpu, &ctx, 10);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcConnectPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcConnectPort_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
	}; break;
	// 114 NTSTATUS NtAlpcCreatePort ['PHANDLE PortHandle', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PALPC_PORT_ATTRIBUTES PortAttributes']
	case 114: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcCreatePort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcCreatePort_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 115 NTSTATUS NtAlpcCreatePortSection ['HANDLE PortHandle', 'ULONG Flags', 'HANDLE SectionHandle', 'SIZE_T SectionSize', 'PALPC_HANDLE AlpcSectionHandle', 'PSIZE_T ActualSectionSize']
	case 115: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcCreatePortSection_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcCreatePortSection_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 116 NTSTATUS NtAlpcCreateResourceReserve ['HANDLE PortHandle', 'ULONG Flags', 'SIZE_T MessageSize', 'PALPC_HANDLE ResourceId']
	case 116: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcCreateResourceReserve_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcCreateResourceReserve_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 117 NTSTATUS NtAlpcCreateSectionView ['HANDLE PortHandle', 'ULONG Flags', 'PALPC_DATA_VIEW_ATTR ViewAttributes']
	case 117: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcCreateSectionView_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcCreateSectionView_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 118 NTSTATUS NtAlpcCreateSecurityContext ['HANDLE PortHandle', 'ULONG Flags', 'PALPC_SECURITY_ATTR SecurityAttribute']
	case 118: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcCreateSecurityContext_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcCreateSecurityContext_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 119 NTSTATUS NtAlpcDeletePortSection ['HANDLE PortHandle', 'ULONG Flags', 'ALPC_HANDLE SectionHandle']
	case 119: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcDeletePortSection_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcDeletePortSection_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 120 NTSTATUS NtAlpcDeleteResourceReserve ['HANDLE PortHandle', 'ULONG Flags', 'ALPC_HANDLE ResourceId']
	case 120: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcDeleteResourceReserve_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcDeleteResourceReserve_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 121 NTSTATUS NtAlpcDeleteSectionView ['HANDLE PortHandle', 'ULONG Flags', 'PVOID ViewBase']
	case 121: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcDeleteSectionView_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcDeleteSectionView_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 122 NTSTATUS NtAlpcDeleteSecurityContext ['HANDLE PortHandle', 'ULONG Flags', 'ALPC_HANDLE ContextHandle']
	case 122: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcDeleteSecurityContext_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcDeleteSecurityContext_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 123 NTSTATUS NtAlpcDisconnectPort ['HANDLE PortHandle', 'ULONG Flags']
	case 123: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcDisconnectPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtAlpcDisconnectPort_enter, cpu, pc, arg0, arg1);
	}; break;
	// 124 NTSTATUS NtAlpcImpersonateClientOfPort ['HANDLE PortHandle', 'PPORT_MESSAGE PortMessage', 'PVOID Reserved']
	case 124: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcImpersonateClientOfPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcImpersonateClientOfPort_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 125 NTSTATUS NtAlpcOpenSenderProcess ['PHANDLE ProcessHandle', 'HANDLE PortHandle', 'PPORT_MESSAGE PortMessage', 'ULONG Flags', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 125: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcOpenSenderProcess_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcOpenSenderProcess_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 126 NTSTATUS NtAlpcOpenSenderThread ['PHANDLE ThreadHandle', 'HANDLE PortHandle', 'PPORT_MESSAGE PortMessage', 'ULONG Flags', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 126: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcOpenSenderThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcOpenSenderThread_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 127 NTSTATUS NtAlpcQueryInformation ['HANDLE PortHandle', 'ALPC_PORT_INFORMATION_CLASS PortInformationClass', 'PVOID PortInformation', 'ULONG Length', 'PULONG ReturnLength']
	case 127: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcQueryInformation_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcQueryInformation_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 128 NTSTATUS NtAlpcQueryInformationMessage ['HANDLE PortHandle', 'PPORT_MESSAGE PortMessage', 'ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass', 'PVOID MessageInformation', 'ULONG Length', 'PULONG ReturnLength']
	case 128: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcQueryInformationMessage_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcQueryInformationMessage_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 129 NTSTATUS NtAlpcRevokeSecurityContext ['HANDLE PortHandle', 'ULONG Flags', 'ALPC_HANDLE ContextHandle']
	case 129: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcRevokeSecurityContext_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcRevokeSecurityContext_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 130 NTSTATUS NtAlpcSendWaitReceivePort ['HANDLE PortHandle', 'ULONG Flags', 'PPORT_MESSAGE SendMessage', 'PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes', 'PPORT_MESSAGE ReceiveMessage', 'PULONG BufferLength', 'PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes', 'PLARGE_INTEGER Timeout']
	case 130: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcSendWaitReceivePort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAlpcSendWaitReceivePort_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	}; break;
	// 131 NTSTATUS NtAlpcSetInformation ['HANDLE PortHandle', 'ALPC_PORT_INFORMATION_CLASS PortInformationClass', 'PVOID PortInformation', 'ULONG Length']
	case 131: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAlpcSetInformation_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtAlpcSetInformation_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 132 NTSTATUS NtAreMappedFilesTheSame ['PVOID File1MappedAsAnImage', 'PVOID File2MappedAsFile']
	case 132: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAreMappedFilesTheSame_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAreMappedFilesTheSame_enter, cpu, pc, arg0, arg1);
	}; break;
	// 133 NTSTATUS NtAssignProcessToJobObject ['HANDLE JobHandle', 'HANDLE ProcessHandle']
	case 133: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtAssignProcessToJobObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtAssignProcessToJobObject_enter, cpu, pc, arg0, arg1);
	}; break;
	// 134 NTSTATUS NtCancelIoFileEx ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoRequestToCancel', 'PIO_STATUS_BLOCK IoStatusBlock']
	case 134: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCancelIoFileEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCancelIoFileEx_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 135 NTSTATUS NtCancelSynchronousIoFile ['HANDLE ThreadHandle', 'PIO_STATUS_BLOCK IoRequestToCancel', 'PIO_STATUS_BLOCK IoStatusBlock']
	case 135: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCancelSynchronousIoFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCancelSynchronousIoFile_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 136 NTSTATUS NtCommitComplete ['HANDLE EnlistmentHandle', 'PLARGE_INTEGER TmVirtualClock']
	case 136: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCommitComplete_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCommitComplete_enter, cpu, pc, arg0, arg1);
	}; break;
	// 137 NTSTATUS NtCommitEnlistment ['HANDLE EnlistmentHandle', 'PLARGE_INTEGER TmVirtualClock']
	case 137: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCommitEnlistment_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCommitEnlistment_enter, cpu, pc, arg0, arg1);
	}; break;
	// 138 NTSTATUS NtCommitTransaction ['HANDLE TransactionHandle', 'BOOLEAN Wait']
	case 138: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCommitTransaction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCommitTransaction_enter, cpu, pc, arg0, arg1);
	}; break;
	// 139 NTSTATUS NtCompactKeys ['ULONG Count', 'HANDLE KeyArray[]']
	case 139: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCompactKeys_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCompactKeys_enter, cpu, pc, arg0, arg1);
	}; break;
	// 140 NTSTATUS NtCompareTokens ['HANDLE FirstTokenHandle', 'HANDLE SecondTokenHandle', 'PBOOLEAN Equal']
	case 140: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCompareTokens_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCompareTokens_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 141 NTSTATUS NtCompleteConnectPort ['HANDLE PortHandle']
	case 141: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCompleteConnectPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCompleteConnectPort_enter, cpu, pc, arg0);
	}; break;
	// 142 NTSTATUS NtCompressKey ['HANDLE Key']
	case 142: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCompressKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCompressKey_enter, cpu, pc, arg0);
	}; break;
	// 143 NTSTATUS NtConnectPort ['PHANDLE PortHandle', 'PUNICODE_STRING PortName', 'PSECURITY_QUALITY_OF_SERVICE SecurityQos', 'PPORT_VIEW ClientView', 'PREMOTE_PORT_VIEW ServerView', 'PULONG MaxMessageLength', 'PVOID ConnectionInformation', 'PULONG ConnectionInformationLength']
	case 143: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtConnectPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtConnectPort_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	}; break;
	// 144 NTSTATUS NtCreateDebugObject ['PHANDLE DebugObjectHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG Flags']
	case 144: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateDebugObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreateDebugObject_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 145 NTSTATUS NtCreateDirectoryObject ['PHANDLE DirectoryHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 145: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateDirectoryObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateDirectoryObject_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 146 NTSTATUS NtCreateEnlistment ['PHANDLE EnlistmentHandle', 'ACCESS_MASK DesiredAccess', 'HANDLE ResourceManagerHandle', 'HANDLE TransactionHandle', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG CreateOptions', 'NOTIFICATION_MASK NotificationMask', 'PVOID EnlistmentKey']
	case 146: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateEnlistment_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateEnlistment_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	}; break;
	// 147 NTSTATUS NtCreateEventPair ['PHANDLE EventPairHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 147: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateEventPair_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateEventPair_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 148 NTSTATUS NtCreateIoCompletion ['PHANDLE IoCompletionHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG Count']
	case 148: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateIoCompletion_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreateIoCompletion_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 149 NTSTATUS NtCreateJobObject ['PHANDLE JobHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 149: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateJobObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateJobObject_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 150 NTSTATUS NtCreateJobSet ['ULONG NumJob', 'PJOB_SET_ARRAY UserJobSet', 'ULONG Flags']
	case 150: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateJobSet_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreateJobSet_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 151 NTSTATUS NtCreateKeyTransacted ['PHANDLE KeyHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG TitleIndex', 'PUNICODE_STRING Class', 'ULONG CreateOptions', 'HANDLE TransactionHandle', 'PULONG Disposition']
	case 151: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateKeyTransacted_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateKeyTransacted_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	}; break;
	// 152 NTSTATUS NtCreateKeyedEvent ['PHANDLE KeyedEventHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG Flags']
	case 152: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateKeyedEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreateKeyedEvent_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 153 NTSTATUS NtCreateMailslotFile ['PHANDLE FileHandle', 'ULONG DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG CreateOptions', 'ULONG MailslotQuota', 'ULONG MaximumMessageSize', 'PLARGE_INTEGER ReadTimeout']
	case 153: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateMailslotFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateMailslotFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	}; break;
	// 154 NTSTATUS NtCreateMutant ['PHANDLE MutantHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'BOOLEAN InitialOwner']
	case 154: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateMutant_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreateMutant_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 155 NTSTATUS NtCreateNamedPipeFile ['PHANDLE FileHandle', 'ULONG DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG ShareAccess', 'ULONG CreateDisposition', 'ULONG CreateOptions', 'ULONG NamedPipeType', 'ULONG ReadMode', 'ULONG CompletionMode', 'ULONG MaximumInstances', 'ULONG InboundQuota', 'ULONG OutboundQuota', 'PLARGE_INTEGER DefaultTimeout']
	case 155: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		uint32_t arg9 = get_32(cpu, &ctx, 9);
		uint32_t arg10 = get_32(cpu, &ctx, 10);
		uint32_t arg11 = get_32(cpu, &ctx, 11);
		uint32_t arg12 = get_32(cpu, &ctx, 12);
		uint64_t arg13 = get_64(cpu, &ctx, 13);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateNamedPipeFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint32_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint32_t));
			memcpy(ctx.args[11], &arg11, sizeof(uint32_t));
			memcpy(ctx.args[12], &arg12, sizeof(uint32_t));
			memcpy(ctx.args[13], &arg13, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateNamedPipeFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13);
	}; break;
	// 156 NTSTATUS NtCreatePagingFile ['PUNICODE_STRING PageFileName', 'PLARGE_INTEGER MinimumSize', 'PLARGE_INTEGER MaximumSize', 'ULONG Priority']
	case 156: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreatePagingFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreatePagingFile_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 157 NTSTATUS NtCreatePort ['PHANDLE PortHandle', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG MaxConnectionInfoLength', 'ULONG MaxMessageLength', 'ULONG MaxPoolUsage']
	case 157: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreatePort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreatePort_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 158 NTSTATUS NtCreatePrivateNamespace ['PHANDLE NamespaceHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PVOID BoundaryDescriptor']
	case 158: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreatePrivateNamespace_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreatePrivateNamespace_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 159 NTSTATUS NtCreateProcess ['PHANDLE ProcessHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'HANDLE ParentProcess', 'BOOLEAN InheritObjectTable', 'HANDLE SectionHandle', 'HANDLE DebugPort', 'HANDLE ExceptionPort']
	case 159: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateProcess_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateProcess_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	}; break;
	// 160 NTSTATUS NtCreateProfile ['PHANDLE ProfileHandle', 'HANDLE Process', 'PVOID RangeBase', 'SIZE_T RangeSize', 'ULONG BucketSize', 'PULONG Buffer', 'ULONG BufferSize', 'KPROFILE_SOURCE ProfileSource', 'KAFFINITY Affinity']
	case 160: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateProfile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateProfile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
	}; break;
	// 161 NTSTATUS NtCreateProfileEx ['PHANDLE ProfileHandle', 'HANDLE Process', 'PVOID ProfileBase', 'SIZE_T ProfileSize', 'ULONG BucketSize', 'PULONG Buffer', 'ULONG BufferSize', 'KPROFILE_SOURCE ProfileSource', 'ULONG GroupAffinityCount', 'PGROUP_AFFINITY GroupAffinity']
	case 161: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateProfileEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateProfileEx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
	}; break;
	// 162 NTSTATUS NtCreateResourceManager ['PHANDLE ResourceManagerHandle', 'ACCESS_MASK DesiredAccess', 'HANDLE TmHandle', 'LPGUID RmGuid', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG CreateOptions', 'PUNICODE_STRING Description']
	case 162: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateResourceManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateResourceManager_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 163 NTSTATUS NtCreateSemaphore ['PHANDLE SemaphoreHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'LONG InitialCount', 'LONG MaximumCount']
	case 163: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
		int32_t arg4 = get_s32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateSemaphore_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_NtCreateSemaphore_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 164 NTSTATUS NtCreateSymbolicLinkObject ['PHANDLE LinkHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PUNICODE_STRING LinkTarget']
	case 164: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateSymbolicLinkObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateSymbolicLinkObject_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 165 NTSTATUS NtCreateThreadEx ['PHANDLE ThreadHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'HANDLE ProcessHandle', 'PVOID StartRoutine', 'PVOID Argument', 'ULONG CreateFlags', 'ULONG_PTR ZeroBits', 'SIZE_T StackSize', 'SIZE_T MaximumStackSize', 'PPS_ATTRIBUTE_LIST AttributeList']
	case 165: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		uint64_t arg10 = get_64(cpu, &ctx, 10);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateThreadEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateThreadEx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
	}; break;
	// 166 NTSTATUS NtCreateTimer ['PHANDLE TimerHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'TIMER_TYPE TimerType']
	case 166: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateTimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreateTimer_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 167 NTSTATUS NtCreateToken ['PHANDLE TokenHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'TOKEN_TYPE TokenType', 'PLUID AuthenticationId', 'PLARGE_INTEGER ExpirationTime', 'PTOKEN_USER User', 'PTOKEN_GROUPS Groups', 'PTOKEN_PRIVILEGES Privileges', 'PTOKEN_OWNER Owner', 'PTOKEN_PRIMARY_GROUP PrimaryGroup', 'PTOKEN_DEFAULT_DACL DefaultDacl', 'PTOKEN_SOURCE TokenSource']
	case 167: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		uint64_t arg10 = get_64(cpu, &ctx, 10);
		uint64_t arg11 = get_64(cpu, &ctx, 11);
		uint64_t arg12 = get_64(cpu, &ctx, 12);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateToken_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint64_t));
			memcpy(ctx.args[11], &arg11, sizeof(uint64_t));
			memcpy(ctx.args[12], &arg12, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateToken_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12);
	}; break;
	// 168 NTSTATUS NtCreateTransaction ['PHANDLE TransactionHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'LPGUID Uow', 'HANDLE TmHandle', 'ULONG CreateOptions', 'ULONG IsolationLevel', 'ULONG IsolationFlags', 'PLARGE_INTEGER Timeout', 'PUNICODE_STRING Description']
	case 168: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateTransaction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateTransaction_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
	}; break;
	// 169 NTSTATUS NtCreateTransactionManager ['PHANDLE TmHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PUNICODE_STRING LogFileName', 'ULONG CreateOptions', 'ULONG CommitStrength']
	case 169: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateTransactionManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreateTransactionManager_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 170 NTSTATUS NtCreateUserProcess ['PHANDLE ProcessHandle', 'PHANDLE ThreadHandle', 'ACCESS_MASK ProcessDesiredAccess', 'ACCESS_MASK ThreadDesiredAccess', 'POBJECT_ATTRIBUTES ProcessObjectAttributes', 'POBJECT_ATTRIBUTES ThreadObjectAttributes', 'ULONG ProcessFlags', 'ULONG ThreadFlags', 'PRTL_USER_PROCESS_PARAMETERS ProcessParameters', 'PPROCESS_CREATE_INFO CreateInfo', 'PPROCESS_ATTRIBUTE_LIST AttributeList']
	case 170: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		uint64_t arg10 = get_64(cpu, &ctx, 10);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateUserProcess_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateUserProcess_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
	}; break;
	// 171 NTSTATUS NtCreateWaitablePort ['PHANDLE PortHandle', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG MaxConnectionInfoLength', 'ULONG MaxMessageLength', 'ULONG MaxPoolUsage']
	case 171: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateWaitablePort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtCreateWaitablePort_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 172 NTSTATUS NtCreateWorkerFactory ['PHANDLE WorkerFactoryHandleReturn', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'HANDLE CompletionPortHandle', 'HANDLE WorkerProcessHandle', 'PVOID StartRoutine', 'PVOID StartParameter', 'ULONG MaxThreadCount', 'SIZE_T StackReserve', 'SIZE_T StackCommit']
	case 172: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtCreateWorkerFactory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtCreateWorkerFactory_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
	}; break;
	// 173 NTSTATUS NtDebugActiveProcess ['HANDLE ProcessHandle', 'HANDLE DebugObjectHandle']
	case 173: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDebugActiveProcess_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtDebugActiveProcess_enter, cpu, pc, arg0, arg1);
	}; break;
	// 174 NTSTATUS NtDebugContinue ['HANDLE DebugObjectHandle', 'PCLIENT_ID ClientId', 'NTSTATUS ContinueStatus']
	case 174: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDebugContinue_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtDebugContinue_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 175 NTSTATUS NtDeleteAtom ['RTL_ATOM Atom']
	case 175: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDeleteAtom_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtDeleteAtom_enter, cpu, pc, arg0);
	}; break;
	// 176 NTSTATUS NtDeleteBootEntry ['ULONG Id']
	case 176: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDeleteBootEntry_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtDeleteBootEntry_enter, cpu, pc, arg0);
	}; break;
	// 177 NTSTATUS NtDeleteDriverEntry ['ULONG Id']
	case 177: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDeleteDriverEntry_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtDeleteDriverEntry_enter, cpu, pc, arg0);
	}; break;
	// 178 NTSTATUS NtDeleteFile ['POBJECT_ATTRIBUTES ObjectAttributes']
	case 178: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDeleteFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtDeleteFile_enter, cpu, pc, arg0);
	}; break;
	// 179 NTSTATUS NtDeleteKey ['HANDLE KeyHandle']
	case 179: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDeleteKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtDeleteKey_enter, cpu, pc, arg0);
	}; break;
	// 180 NTSTATUS NtDeleteObjectAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'BOOLEAN GenerateOnClose']
	case 180: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDeleteObjectAuditAlarm_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtDeleteObjectAuditAlarm_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 181 NTSTATUS NtDeletePrivateNamespace ['HANDLE NamespaceHandle']
	case 181: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDeletePrivateNamespace_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtDeletePrivateNamespace_enter, cpu, pc, arg0);
	}; break;
	// 182 NTSTATUS NtDeleteValueKey ['HANDLE KeyHandle', 'PUNICODE_STRING ValueName']
	case 182: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDeleteValueKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtDeleteValueKey_enter, cpu, pc, arg0, arg1);
	}; break;
	// 183 NTSTATUS NtDisableLastKnownGood ['']
	case 183: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtDisableLastKnownGood_enter, cpu, pc);
	}; break;
	// 184 NTSTATUS NtDisplayString ['PUNICODE_STRING String']
	case 184: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDisplayString_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtDisplayString_enter, cpu, pc, arg0);
	}; break;
	// 185 NTSTATUS NtDrawText ['PUNICODE_STRING Text']
	case 185: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtDrawText_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtDrawText_enter, cpu, pc, arg0);
	}; break;
	// 186 NTSTATUS NtEnableLastKnownGood ['']
	case 186: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtEnableLastKnownGood_enter, cpu, pc);
	}; break;
	// 187 NTSTATUS NtEnumerateBootEntries ['PVOID Buffer', 'PULONG BufferLength']
	case 187: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtEnumerateBootEntries_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtEnumerateBootEntries_enter, cpu, pc, arg0, arg1);
	}; break;
	// 188 NTSTATUS NtEnumerateDriverEntries ['PVOID Buffer', 'PULONG BufferLength']
	case 188: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtEnumerateDriverEntries_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtEnumerateDriverEntries_enter, cpu, pc, arg0, arg1);
	}; break;
	// 189 NTSTATUS NtEnumerateSystemEnvironmentValuesEx ['ULONG InformationClass', 'PVOID Buffer', 'PULONG BufferLength']
	case 189: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtEnumerateSystemEnvironmentValuesEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtEnumerateSystemEnvironmentValuesEx_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 190 NTSTATUS NtEnumerateTransactionObject ['HANDLE RootObjectHandle', 'KTMOBJECT_TYPE QueryType', 'PKTMOBJECT_CURSOR ObjectCursor', 'ULONG ObjectCursorLength', 'PULONG ReturnLength']
	case 190: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtEnumerateTransactionObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtEnumerateTransactionObject_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 191 NTSTATUS NtExtendSection ['HANDLE SectionHandle', 'PLARGE_INTEGER NewSectionSize']
	case 191: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtExtendSection_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtExtendSection_enter, cpu, pc, arg0, arg1);
	}; break;
	// 192 NTSTATUS NtFilterToken ['HANDLE ExistingTokenHandle', 'ULONG Flags', 'PTOKEN_GROUPS SidsToDisable', 'PTOKEN_PRIVILEGES PrivilegesToDelete', 'PTOKEN_GROUPS RestrictedSids', 'PHANDLE NewTokenHandle']
	case 192: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtFilterToken_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtFilterToken_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 193 NTSTATUS NtFlushInstallUILanguage ['LANGID InstallUILanguage', 'ULONG SetComittedFlag']
	case 193: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtFlushInstallUILanguage_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtFlushInstallUILanguage_enter, cpu, pc, arg0, arg1);
	}; break;
	// 194 NTSTATUS NtFlushInstructionCache ['HANDLE ProcessHandle', 'PVOID BaseAddress', 'SIZE_T Length']
	case 194: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtFlushInstructionCache_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtFlushInstructionCache_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 195 NTSTATUS NtFlushKey ['HANDLE KeyHandle']
	case 195: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtFlushKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtFlushKey_enter, cpu, pc, arg0);
	}; break;
	// 196 VOID NtFlushProcessWriteBuffers ['']
	case 196: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtFlushProcessWriteBuffers_enter, cpu, pc);
	}; break;
	// 197 NTSTATUS NtFlushVirtualMemory ['HANDLE ProcessHandle', 'PVOID *BaseAddress', 'PSIZE_T RegionSize', 'PIO_STATUS_BLOCK IoStatus']
	case 197: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtFlushVirtualMemory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtFlushVirtualMemory_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 198 NTSTATUS NtFlushWriteBuffer ['']
	case 198: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtFlushWriteBuffer_enter, cpu, pc);
	}; break;
	// 199 NTSTATUS NtFreeUserPhysicalPages ['HANDLE ProcessHandle', 'PULONG_PTR NumberOfPages', 'PULONG_PTR UserPfnArray']
	case 199: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtFreeUserPhysicalPages_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtFreeUserPhysicalPages_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 200 NTSTATUS NtFreezeRegistry ['ULONG TimeOutInSeconds']
	case 200: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtFreezeRegistry_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtFreezeRegistry_enter, cpu, pc, arg0);
	}; break;
	// 201 NTSTATUS NtFreezeTransactions ['PLARGE_INTEGER FreezeTimeout', 'PLARGE_INTEGER ThawTimeout']
	case 201: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtFreezeTransactions_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtFreezeTransactions_enter, cpu, pc, arg0, arg1);
	}; break;
	// 202 NTSTATUS NtGetContextThread ['HANDLE ThreadHandle', 'PCONTEXT ThreadContext']
	case 202: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtGetContextThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtGetContextThread_enter, cpu, pc, arg0, arg1);
	}; break;
	// 203 ULONG NtGetCurrentProcessorNumber ['']
	case 203: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtGetCurrentProcessorNumber_enter, cpu, pc);
	}; break;
	// 204 NTSTATUS NtGetDevicePowerState ['HANDLE Device', 'DEVICE_POWER_STATE *State']
	case 204: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtGetDevicePowerState_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtGetDevicePowerState_enter, cpu, pc, arg0, arg1);
	}; break;
	// 205 NTSTATUS NtGetMUIRegistryInfo ['ULONG Flags', 'PULONG DataSize', 'PVOID Data']
	case 205: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtGetMUIRegistryInfo_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtGetMUIRegistryInfo_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 206 NTSTATUS NtGetNextProcess ['HANDLE ProcessHandle', 'ACCESS_MASK DesiredAccess', 'ULONG HandleAttributes', 'ULONG Flags', 'PHANDLE NewProcessHandle']
	case 206: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtGetNextProcess_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtGetNextProcess_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 207 NTSTATUS NtGetNextThread ['HANDLE ProcessHandle', 'HANDLE ThreadHandle', 'ACCESS_MASK DesiredAccess', 'ULONG HandleAttributes', 'ULONG Flags', 'PHANDLE NewThreadHandle']
	case 207: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtGetNextThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtGetNextThread_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 208 NTSTATUS NtGetNlsSectionPtr ['ULONG SectionType', 'ULONG SectionData', 'PVOID ContextData', 'PVOID *SectionPointer', 'PULONG SectionSize']
	case 208: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtGetNlsSectionPtr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtGetNlsSectionPtr_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 209 NTSTATUS NtGetNotificationResourceManager ['HANDLE ResourceManagerHandle', 'PTRANSACTION_NOTIFICATION TransactionNotification', 'ULONG NotificationLength', 'PLARGE_INTEGER Timeout', 'PULONG ReturnLength', 'ULONG Asynchronous', 'ULONG_PTR AsynchronousContext']
	case 209: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtGetNotificationResourceManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtGetNotificationResourceManager_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 210 NTSTATUS NtGetPlugPlayEvent ['HANDLE EventHandle', 'PVOID Context', 'PPLUGPLAY_EVENT_BLOCK EventBlock', 'ULONG EventBufferSize']
	case 210: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtGetPlugPlayEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtGetPlugPlayEvent_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 211 NTSTATUS NtGetWriteWatch ['HANDLE ProcessHandle', 'ULONG Flags', 'PVOID BaseAddress', 'SIZE_T RegionSize', 'PVOID *UserAddressArray', 'PULONG_PTR EntriesInUserAddressArray', 'PULONG Granularity']
	case 211: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtGetWriteWatch_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtGetWriteWatch_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 212 NTSTATUS NtImpersonateAnonymousToken ['HANDLE ThreadHandle']
	case 212: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtImpersonateAnonymousToken_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtImpersonateAnonymousToken_enter, cpu, pc, arg0);
	}; break;
	// 213 NTSTATUS NtImpersonateThread ['HANDLE ServerThreadHandle', 'HANDLE ClientThreadHandle', 'PSECURITY_QUALITY_OF_SERVICE SecurityQos']
	case 213: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtImpersonateThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtImpersonateThread_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 214 NTSTATUS NtInitializeNlsFiles ['PVOID *BaseAddress', 'PLCID DefaultLocaleId', 'PLARGE_INTEGER DefaultCasingTableSize']
	case 214: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtInitializeNlsFiles_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtInitializeNlsFiles_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 215 NTSTATUS NtInitializeRegistry ['USHORT BootCondition']
	case 215: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtInitializeRegistry_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtInitializeRegistry_enter, cpu, pc, arg0);
	}; break;
	// 216 NTSTATUS NtInitiatePowerAction ['POWER_ACTION SystemAction', 'SYSTEM_POWER_STATE MinSystemState', 'ULONG Flags', 'BOOLEAN Asynchronous']
	case 216: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtInitiatePowerAction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtInitiatePowerAction_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 217 BOOLEAN NtIsSystemResumeAutomatic ['']
	case 217: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtIsSystemResumeAutomatic_enter, cpu, pc);
	}; break;
	// 218 NTSTATUS NtIsUILanguageComitted ['']
	case 218: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtIsUILanguageComitted_enter, cpu, pc);
	}; break;
	// 219 NTSTATUS NtListenPort ['HANDLE PortHandle', 'PPORT_MESSAGE ConnectionRequest']
	case 219: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtListenPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtListenPort_enter, cpu, pc, arg0, arg1);
	}; break;
	// 220 NTSTATUS NtLoadDriver ['PUNICODE_STRING DriverServiceName']
	case 220: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtLoadDriver_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtLoadDriver_enter, cpu, pc, arg0);
	}; break;
	// 221 NTSTATUS NtLoadKey ['POBJECT_ATTRIBUTES TargetKey', 'POBJECT_ATTRIBUTES SourceFile']
	case 221: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtLoadKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtLoadKey_enter, cpu, pc, arg0, arg1);
	}; break;
	// 222 NTSTATUS NtLoadKey2 ['POBJECT_ATTRIBUTES TargetKey', 'POBJECT_ATTRIBUTES SourceFile', 'ULONG Flags']
	case 222: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtLoadKey2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtLoadKey2_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 223 NTSTATUS NtLoadKeyEx ['POBJECT_ATTRIBUTES TargetKey', 'POBJECT_ATTRIBUTES SourceFile', 'ULONG Flags', 'HANDLE TrustClassKey']
	case 223: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtLoadKeyEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtLoadKeyEx_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 224 NTSTATUS NtLockFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PLARGE_INTEGER ByteOffset', 'PLARGE_INTEGER Length', 'ULONG Key', 'BOOLEAN FailImmediately', 'BOOLEAN ExclusiveLock']
	case 224: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		uint32_t arg9 = get_32(cpu, &ctx, 9);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtLockFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtLockFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
	}; break;
	// 225 NTSTATUS NtLockProductActivationKeys ['ULONG *pPrivateVer', 'ULONG *pSafeMode']
	case 225: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtLockProductActivationKeys_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtLockProductActivationKeys_enter, cpu, pc, arg0, arg1);
	}; break;
	// 226 NTSTATUS NtLockRegistryKey ['HANDLE KeyHandle']
	case 226: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtLockRegistryKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtLockRegistryKey_enter, cpu, pc, arg0);
	}; break;
	// 227 NTSTATUS NtLockVirtualMemory ['HANDLE ProcessHandle', 'PVOID *BaseAddress', 'PSIZE_T RegionSize', 'ULONG MapType']
	case 227: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtLockVirtualMemory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtLockVirtualMemory_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 228 NTSTATUS NtMakePermanentObject ['HANDLE Handle']
	case 228: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtMakePermanentObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtMakePermanentObject_enter, cpu, pc, arg0);
	}; break;
	// 229 NTSTATUS NtMakeTemporaryObject ['HANDLE Handle']
	case 229: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtMakeTemporaryObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtMakeTemporaryObject_enter, cpu, pc, arg0);
	}; break;
	// 230 NTSTATUS NtMapCMFModule ['ULONG What', 'ULONG Index', 'PULONG CacheIndexOut', 'PULONG CacheFlagsOut', 'PULONG ViewSizeOut', 'PVOID *BaseAddress']
	case 230: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtMapCMFModule_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtMapCMFModule_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 231 NTSTATUS NtMapUserPhysicalPages ['PVOID VirtualAddress', 'ULONG_PTR NumberOfPages', 'PULONG_PTR UserPfnArray']
	case 231: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtMapUserPhysicalPages_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtMapUserPhysicalPages_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 232 NTSTATUS NtModifyBootEntry ['PBOOT_ENTRY BootEntry']
	case 232: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtModifyBootEntry_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtModifyBootEntry_enter, cpu, pc, arg0);
	}; break;
	// 233 NTSTATUS NtModifyDriverEntry ['PEFI_DRIVER_ENTRY DriverEntry']
	case 233: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtModifyDriverEntry_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtModifyDriverEntry_enter, cpu, pc, arg0);
	}; break;
	// 234 NTSTATUS NtNotifyChangeDirectoryFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length', 'ULONG CompletionFilter', 'BOOLEAN WatchTree']
	case 234: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtNotifyChangeDirectoryFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtNotifyChangeDirectoryFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
	}; break;
	// 235 NTSTATUS NtNotifyChangeKey ['HANDLE KeyHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG CompletionFilter', 'BOOLEAN WatchTree', 'PVOID Buffer', 'ULONG BufferSize', 'BOOLEAN Asynchronous']
	case 235: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		uint32_t arg9 = get_32(cpu, &ctx, 9);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtNotifyChangeKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtNotifyChangeKey_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
	}; break;
	// 236 NTSTATUS NtNotifyChangeMultipleKeys ['HANDLE MasterKeyHandle', 'ULONG Count', 'OBJECT_ATTRIBUTES SlaveObjects[]', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG CompletionFilter', 'BOOLEAN WatchTree', 'PVOID Buffer', 'ULONG BufferSize', 'BOOLEAN Asynchronous']
	case 236: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		uint64_t arg9 = get_64(cpu, &ctx, 9);
		uint32_t arg10 = get_32(cpu, &ctx, 10);
		uint32_t arg11 = get_32(cpu, &ctx, 11);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtNotifyChangeMultipleKeys_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint64_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint32_t));
			memcpy(ctx.args[11], &arg11, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtNotifyChangeMultipleKeys_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11);
	}; break;
	// 237 NTSTATUS NtNotifyChangeSession ['HANDLE Session', 'ULONG IoStateSequence', 'PVOID Reserved', 'ULONG Action', 'IO_SESSION_STATE IoState', 'IO_SESSION_STATE IoState2', 'PVOID Buffer', 'ULONG BufferSize']
	case 237: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtNotifyChangeSession_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtNotifyChangeSession_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	}; break;
	// 238 NTSTATUS NtOpenEnlistment ['PHANDLE EnlistmentHandle', 'ACCESS_MASK DesiredAccess', 'HANDLE ResourceManagerHandle', 'LPGUID EnlistmentGuid', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 238: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenEnlistment_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenEnlistment_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 239 NTSTATUS NtOpenEventPair ['PHANDLE EventPairHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 239: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenEventPair_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenEventPair_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 240 NTSTATUS NtOpenIoCompletion ['PHANDLE IoCompletionHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 240: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenIoCompletion_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenIoCompletion_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 241 NTSTATUS NtOpenJobObject ['PHANDLE JobHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 241: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenJobObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenJobObject_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 242 NTSTATUS NtOpenKeyEx ['PHANDLE KeyHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG OpenOptions']
	case 242: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenKeyEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtOpenKeyEx_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 243 NTSTATUS NtOpenKeyTransacted ['PHANDLE KeyHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'HANDLE TransactionHandle']
	case 243: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenKeyTransacted_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenKeyTransacted_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 244 NTSTATUS NtOpenKeyTransactedEx ['PHANDLE KeyHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG OpenOptions', 'HANDLE TransactionHandle']
	case 244: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenKeyTransactedEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenKeyTransactedEx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 245 NTSTATUS NtOpenKeyedEvent ['PHANDLE KeyedEventHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 245: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenKeyedEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenKeyedEvent_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 246 NTSTATUS NtOpenMutant ['PHANDLE MutantHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 246: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenMutant_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenMutant_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 247 NTSTATUS NtOpenObjectAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'PUNICODE_STRING ObjectTypeName', 'PUNICODE_STRING ObjectName', 'PSECURITY_DESCRIPTOR SecurityDescriptor', 'HANDLE ClientToken', 'ACCESS_MASK DesiredAccess', 'ACCESS_MASK GrantedAccess', 'PPRIVILEGE_SET Privileges', 'BOOLEAN ObjectCreation', 'BOOLEAN AccessGranted', 'PBOOLEAN GenerateOnClose']
	case 247: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint32_t arg7 = get_32(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		uint32_t arg9 = get_32(cpu, &ctx, 9);
		uint32_t arg10 = get_32(cpu, &ctx, 10);
		uint64_t arg11 = get_64(cpu, &ctx, 11);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenObjectAuditAlarm_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint32_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
			memcpy(ctx.args[9], &arg9, sizeof(uint32_t));
			memcpy(ctx.args[10], &arg10, sizeof(uint32_t));
			memcpy(ctx.args[11], &arg11, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenObjectAuditAlarm_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11);
	}; break;
	// 248 NTSTATUS NtOpenPrivateNamespace ['PHANDLE NamespaceHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PVOID BoundaryDescriptor']
	case 248: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenPrivateNamespace_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenPrivateNamespace_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 249 NTSTATUS NtOpenProcessToken ['HANDLE ProcessHandle', 'ACCESS_MASK DesiredAccess', 'PHANDLE TokenHandle']
	case 249: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenProcessToken_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenProcessToken_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 250 NTSTATUS NtOpenResourceManager ['PHANDLE ResourceManagerHandle', 'ACCESS_MASK DesiredAccess', 'HANDLE TmHandle', 'LPGUID ResourceManagerGuid', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 250: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenResourceManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenResourceManager_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 251 NTSTATUS NtOpenSemaphore ['PHANDLE SemaphoreHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 251: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenSemaphore_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenSemaphore_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 252 NTSTATUS NtOpenSession ['PHANDLE SessionHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 252: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenSession_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenSession_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 253 NTSTATUS NtOpenSymbolicLinkObject ['PHANDLE LinkHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 253: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenSymbolicLinkObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenSymbolicLinkObject_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 254 NTSTATUS NtOpenThread ['PHANDLE ThreadHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PCLIENT_ID ClientId']
	case 254: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenThread_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 255 NTSTATUS NtOpenTimer ['PHANDLE TimerHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
	case 255: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenTimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenTimer_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 256 NTSTATUS NtOpenTransaction ['PHANDLE TransactionHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'LPGUID Uow', 'HANDLE TmHandle']
	case 256: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenTransaction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtOpenTransaction_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 257 NTSTATUS NtOpenTransactionManager ['PHANDLE TmHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PUNICODE_STRING LogFileName', 'LPGUID TmIdentity', 'ULONG OpenOptions']
	case 257: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtOpenTransactionManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtOpenTransactionManager_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 258 NTSTATUS NtPlugPlayControl ['PLUGPLAY_CONTROL_CLASS PnPControlClass', 'PVOID PnPControlData', 'ULONG PnPControlDataLength']
	case 258: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtPlugPlayControl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtPlugPlayControl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 259 NTSTATUS NtPrePrepareComplete ['HANDLE EnlistmentHandle', 'PLARGE_INTEGER TmVirtualClock']
	case 259: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtPrePrepareComplete_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtPrePrepareComplete_enter, cpu, pc, arg0, arg1);
	}; break;
	// 260 NTSTATUS NtPrePrepareEnlistment ['HANDLE EnlistmentHandle', 'PLARGE_INTEGER TmVirtualClock']
	case 260: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtPrePrepareEnlistment_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtPrePrepareEnlistment_enter, cpu, pc, arg0, arg1);
	}; break;
	// 261 NTSTATUS NtPrepareComplete ['HANDLE EnlistmentHandle', 'PLARGE_INTEGER TmVirtualClock']
	case 261: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtPrepareComplete_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtPrepareComplete_enter, cpu, pc, arg0, arg1);
	}; break;
	// 262 NTSTATUS NtPrepareEnlistment ['HANDLE EnlistmentHandle', 'PLARGE_INTEGER TmVirtualClock']
	case 262: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtPrepareEnlistment_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtPrepareEnlistment_enter, cpu, pc, arg0, arg1);
	}; break;
	// 263 NTSTATUS NtPrivilegeCheck ['HANDLE ClientToken', 'PPRIVILEGE_SET RequiredPrivileges', 'PBOOLEAN Result']
	case 263: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtPrivilegeCheck_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtPrivilegeCheck_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 264 NTSTATUS NtPrivilegeObjectAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'HANDLE ClientToken', 'ACCESS_MASK DesiredAccess', 'PPRIVILEGE_SET Privileges', 'BOOLEAN AccessGranted']
	case 264: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtPrivilegeObjectAuditAlarm_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtPrivilegeObjectAuditAlarm_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 265 NTSTATUS NtPrivilegedServiceAuditAlarm ['PUNICODE_STRING SubsystemName', 'PUNICODE_STRING ServiceName', 'HANDLE ClientToken', 'PPRIVILEGE_SET Privileges', 'BOOLEAN AccessGranted']
	case 265: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtPrivilegedServiceAuditAlarm_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtPrivilegedServiceAuditAlarm_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 266 NTSTATUS NtPropagationComplete ['HANDLE ResourceManagerHandle', 'ULONG RequestCookie', 'ULONG BufferLength', 'PVOID Buffer']
	case 266: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtPropagationComplete_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtPropagationComplete_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 267 NTSTATUS NtPropagationFailed ['HANDLE ResourceManagerHandle', 'ULONG RequestCookie', 'NTSTATUS PropStatus']
	case 267: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtPropagationFailed_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtPropagationFailed_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 268 NTSTATUS NtPulseEvent ['HANDLE EventHandle', 'PLONG PreviousState']
	case 268: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtPulseEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtPulseEvent_enter, cpu, pc, arg0, arg1);
	}; break;
	// 269 NTSTATUS NtQueryBootEntryOrder ['PULONG Ids', 'PULONG Count']
	case 269: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryBootEntryOrder_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryBootEntryOrder_enter, cpu, pc, arg0, arg1);
	}; break;
	// 270 NTSTATUS NtQueryBootOptions ['PBOOT_OPTIONS BootOptions', 'PULONG BootOptionsLength']
	case 270: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryBootOptions_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryBootOptions_enter, cpu, pc, arg0, arg1);
	}; break;
	// 271 NTSTATUS NtQueryDebugFilterState ['ULONG ComponentId', 'ULONG Level']
	case 271: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryDebugFilterState_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtQueryDebugFilterState_enter, cpu, pc, arg0, arg1);
	}; break;
	// 272 NTSTATUS NtQueryDirectoryObject ['HANDLE DirectoryHandle', 'PVOID Buffer', 'ULONG Length', 'BOOLEAN ReturnSingleEntry', 'BOOLEAN RestartScan', 'PULONG Context', 'PULONG ReturnLength']
	case 272: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryDirectoryObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryDirectoryObject_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 273 NTSTATUS NtQueryDriverEntryOrder ['PULONG Ids', 'PULONG Count']
	case 273: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryDriverEntryOrder_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryDriverEntryOrder_enter, cpu, pc, arg0, arg1);
	}; break;
	// 274 NTSTATUS NtQueryEaFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length', 'BOOLEAN ReturnSingleEntry', 'PVOID EaList', 'ULONG EaListLength', 'PULONG EaIndex', 'BOOLEAN RestartScan']
	case 274: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryEaFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtQueryEaFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
	}; break;
	// 275 NTSTATUS NtQueryFullAttributesFile ['POBJECT_ATTRIBUTES ObjectAttributes', 'PFILE_NETWORK_OPEN_INFORMATION FileInformation']
	case 275: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryFullAttributesFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryFullAttributesFile_enter, cpu, pc, arg0, arg1);
	}; break;
	// 276 NTSTATUS NtQueryInformationAtom ['RTL_ATOM Atom', 'ATOM_INFORMATION_CLASS InformationClass', 'PVOID AtomInformation', 'ULONG AtomInformationLength', 'PULONG ReturnLength']
	case 276: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInformationAtom_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryInformationAtom_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 277 NTSTATUS NtQueryInformationEnlistment ['HANDLE EnlistmentHandle', 'ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass', 'PVOID EnlistmentInformation', 'ULONG EnlistmentInformationLength', 'PULONG ReturnLength']
	case 277: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInformationEnlistment_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryInformationEnlistment_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 278 NTSTATUS NtQueryInformationJobObject ['HANDLE JobHandle', 'JOBOBJECTINFOCLASS JobObjectInformationClass', 'PVOID JobObjectInformation', 'ULONG JobObjectInformationLength', 'PULONG ReturnLength']
	case 278: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInformationJobObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryInformationJobObject_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 279 NTSTATUS NtQueryInformationPort ['HANDLE PortHandle', 'PORT_INFORMATION_CLASS PortInformationClass', 'PVOID PortInformation', 'ULONG Length', 'PULONG ReturnLength']
	case 279: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInformationPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryInformationPort_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 280 NTSTATUS NtQueryInformationResourceManager ['HANDLE ResourceManagerHandle', 'RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass', 'PVOID ResourceManagerInformation', 'ULONG ResourceManagerInformationLength', 'PULONG ReturnLength']
	case 280: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInformationResourceManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryInformationResourceManager_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 281 NTSTATUS NtQueryInformationTransaction ['HANDLE TransactionHandle', 'TRANSACTION_INFORMATION_CLASS TransactionInformationClass', 'PVOID TransactionInformation', 'ULONG TransactionInformationLength', 'PULONG ReturnLength']
	case 281: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInformationTransaction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryInformationTransaction_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 282 NTSTATUS NtQueryInformationTransactionManager ['HANDLE TransactionManagerHandle', 'TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass', 'PVOID TransactionManagerInformation', 'ULONG TransactionManagerInformationLength', 'PULONG ReturnLength']
	case 282: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInformationTransactionManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryInformationTransactionManager_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 283 NTSTATUS NtQueryInformationWorkerFactory ['HANDLE WorkerFactoryHandle', 'WORKERFACTORYINFOCLASS WorkerFactoryInformationClass', 'PVOID WorkerFactoryInformation', 'ULONG WorkerFactoryInformationLength', 'PULONG ReturnLength']
	case 283: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInformationWorkerFactory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryInformationWorkerFactory_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 284 NTSTATUS NtQueryInstallUILanguage ['LANGID *InstallUILanguageId']
	case 284: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryInstallUILanguage_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryInstallUILanguage_enter, cpu, pc, arg0);
	}; break;
	// 285 NTSTATUS NtQueryIntervalProfile ['KPROFILE_SOURCE ProfileSource', 'PULONG Interval']
	case 285: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryIntervalProfile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryIntervalProfile_enter, cpu, pc, arg0, arg1);
	}; break;
	// 286 NTSTATUS NtQueryIoCompletion ['HANDLE IoCompletionHandle', 'IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass', 'PVOID IoCompletionInformation', 'ULONG IoCompletionInformationLength', 'PULONG ReturnLength']
	case 286: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryIoCompletion_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryIoCompletion_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 287 NTSTATUS NtQueryLicenseValue ['PUNICODE_STRING Name', 'PULONG Type', 'PVOID Buffer', 'ULONG Length', 'PULONG ReturnedLength']
	case 287: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryLicenseValue_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryLicenseValue_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 288 NTSTATUS NtQueryMultipleValueKey ['HANDLE KeyHandle', 'PKEY_VALUE_ENTRY ValueEntries', 'ULONG EntryCount', 'PVOID ValueBuffer', 'PULONG BufferLength', 'PULONG RequiredBufferLength']
	case 288: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryMultipleValueKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryMultipleValueKey_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 289 NTSTATUS NtQueryMutant ['HANDLE MutantHandle', 'MUTANT_INFORMATION_CLASS MutantInformationClass', 'PVOID MutantInformation', 'ULONG MutantInformationLength', 'PULONG ReturnLength']
	case 289: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryMutant_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryMutant_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 290 NTSTATUS NtQueryOpenSubKeys ['POBJECT_ATTRIBUTES TargetKey', 'PULONG HandleCount']
	case 290: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryOpenSubKeys_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryOpenSubKeys_enter, cpu, pc, arg0, arg1);
	}; break;
	// 291 NTSTATUS NtQueryOpenSubKeysEx ['POBJECT_ATTRIBUTES TargetKey', 'ULONG BufferLength', 'PVOID Buffer', 'PULONG RequiredSize']
	case 291: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryOpenSubKeysEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryOpenSubKeysEx_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 292 NTSTATUS NtQueryPortInformationProcess ['']
	case 292: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtQueryPortInformationProcess_enter, cpu, pc);
	}; break;
	// 293 NTSTATUS NtQueryQuotaInformationFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length', 'BOOLEAN ReturnSingleEntry', 'PVOID SidList', 'ULONG SidListLength', 'PULONG StartSid', 'BOOLEAN RestartScan']
	case 293: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint32_t arg6 = get_32(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint32_t arg8 = get_32(cpu, &ctx, 8);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryQuotaInformationFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint32_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtQueryQuotaInformationFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
	}; break;
	// 294 NTSTATUS NtQuerySecurityAttributesToken ['HANDLE TokenHandle', 'PUNICODE_STRING Attributes', 'ULONG NumberOfAttributes', 'PVOID Buffer', 'ULONG Length', 'PULONG ReturnLength']
	case 294: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQuerySecurityAttributesToken_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQuerySecurityAttributesToken_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 295 NTSTATUS NtQuerySecurityObject ['HANDLE Handle', 'SECURITY_INFORMATION SecurityInformation', 'PSECURITY_DESCRIPTOR SecurityDescriptor', 'ULONG Length', 'PULONG LengthNeeded']
	case 295: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQuerySecurityObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQuerySecurityObject_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 296 NTSTATUS NtQuerySemaphore ['HANDLE SemaphoreHandle', 'SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass', 'PVOID SemaphoreInformation', 'ULONG SemaphoreInformationLength', 'PULONG ReturnLength']
	case 296: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQuerySemaphore_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQuerySemaphore_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 297 NTSTATUS NtQuerySymbolicLinkObject ['HANDLE LinkHandle', 'PUNICODE_STRING LinkTarget', 'PULONG ReturnedLength']
	case 297: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQuerySymbolicLinkObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQuerySymbolicLinkObject_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 298 NTSTATUS NtQuerySystemEnvironmentValue ['PUNICODE_STRING VariableName', 'PWSTR VariableValue', 'USHORT ValueLength', 'PUSHORT ReturnLength']
	case 298: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQuerySystemEnvironmentValue_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQuerySystemEnvironmentValue_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 299 NTSTATUS NtQuerySystemEnvironmentValueEx ['PUNICODE_STRING VariableName', 'LPGUID VendorGuid', 'PVOID Value', 'PULONG ValueLength', 'PULONG Attributes']
	case 299: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQuerySystemEnvironmentValueEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQuerySystemEnvironmentValueEx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 300 NTSTATUS NtQuerySystemInformationEx ['SYSTEM_INFORMATION_CLASS SystemInformationClass', 'PVOID QueryInformation', 'ULONG QueryInformationLength', 'PVOID SystemInformation', 'ULONG SystemInformationLength', 'PULONG ReturnLength']
	case 300: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQuerySystemInformationEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQuerySystemInformationEx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 301 NTSTATUS NtQueryTimerResolution ['PULONG MaximumTime', 'PULONG MinimumTime', 'PULONG CurrentTime']
	case 301: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueryTimerResolution_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueryTimerResolution_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 302 NTSTATUS NtQueueApcThreadEx ['HANDLE ThreadHandle', 'HANDLE UserApcReserveHandle', 'PPS_APC_ROUTINE ApcRoutine', 'PVOID ApcArgument1', 'PVOID ApcArgument2', 'PVOID ApcArgument3']
	case 302: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtQueueApcThreadEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtQueueApcThreadEx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 303 NTSTATUS NtRaiseException ['PEXCEPTION_RECORD ExceptionRecord', 'PCONTEXT ContextRecord', 'BOOLEAN FirstChance']
	case 303: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRaiseException_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtRaiseException_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 304 NTSTATUS NtRaiseHardError ['NTSTATUS ErrorStatus', 'ULONG NumberOfParameters', 'ULONG UnicodeStringParameterMask', 'PULONG_PTR Parameters', 'ULONG ValidResponseOptions', 'PULONG Response']
	case 304: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRaiseHardError_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRaiseHardError_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 305 NTSTATUS NtReadOnlyEnlistment ['HANDLE EnlistmentHandle', 'PLARGE_INTEGER TmVirtualClock']
	case 305: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReadOnlyEnlistment_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReadOnlyEnlistment_enter, cpu, pc, arg0, arg1);
	}; break;
	// 306 NTSTATUS NtRecoverEnlistment ['HANDLE EnlistmentHandle', 'PVOID EnlistmentKey']
	case 306: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRecoverEnlistment_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRecoverEnlistment_enter, cpu, pc, arg0, arg1);
	}; break;
	// 307 NTSTATUS NtRecoverResourceManager ['HANDLE ResourceManagerHandle']
	case 307: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRecoverResourceManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRecoverResourceManager_enter, cpu, pc, arg0);
	}; break;
	// 308 NTSTATUS NtRecoverTransactionManager ['HANDLE TransactionManagerHandle']
	case 308: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRecoverTransactionManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRecoverTransactionManager_enter, cpu, pc, arg0);
	}; break;
	// 309 NTSTATUS NtRegisterProtocolAddressInformation ['HANDLE ResourceManager', 'PCRM_PROTOCOL_ID ProtocolId', 'ULONG ProtocolInformationSize', 'PVOID ProtocolInformation', 'ULONG CreateOptions']
	case 309: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRegisterProtocolAddressInformation_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtRegisterProtocolAddressInformation_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 310 NTSTATUS NtRegisterThreadTerminatePort ['HANDLE PortHandle']
	case 310: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRegisterThreadTerminatePort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRegisterThreadTerminatePort_enter, cpu, pc, arg0);
	}; break;
	// 311 NTSTATUS NtReleaseKeyedEvent ['HANDLE KeyedEventHandle', 'PVOID KeyValue', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout']
	case 311: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReleaseKeyedEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReleaseKeyedEvent_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 312 NTSTATUS NtReleaseWorkerFactoryWorker ['HANDLE WorkerFactoryHandle']
	case 312: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReleaseWorkerFactoryWorker_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReleaseWorkerFactoryWorker_enter, cpu, pc, arg0);
	}; break;
	// 313 NTSTATUS NtRemoveIoCompletionEx ['HANDLE IoCompletionHandle', 'PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation', 'ULONG Count', 'PULONG NumEntriesRemoved', 'PLARGE_INTEGER Timeout', 'BOOLEAN Alertable']
	case 313: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRemoveIoCompletionEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtRemoveIoCompletionEx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 314 NTSTATUS NtRemoveProcessDebug ['HANDLE ProcessHandle', 'HANDLE DebugObjectHandle']
	case 314: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRemoveProcessDebug_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRemoveProcessDebug_enter, cpu, pc, arg0, arg1);
	}; break;
	// 315 NTSTATUS NtRenameKey ['HANDLE KeyHandle', 'PUNICODE_STRING NewName']
	case 315: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRenameKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRenameKey_enter, cpu, pc, arg0, arg1);
	}; break;
	// 316 NTSTATUS NtRenameTransactionManager ['PUNICODE_STRING LogFileName', 'LPGUID ExistingTransactionManagerGuid']
	case 316: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRenameTransactionManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRenameTransactionManager_enter, cpu, pc, arg0, arg1);
	}; break;
	// 317 NTSTATUS NtReplaceKey ['POBJECT_ATTRIBUTES NewFile', 'HANDLE TargetHandle', 'POBJECT_ATTRIBUTES OldFile']
	case 317: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReplaceKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReplaceKey_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 318 NTSTATUS NtReplacePartitionUnit ['PUNICODE_STRING TargetInstancePath', 'PUNICODE_STRING SpareInstancePath', 'ULONG Flags']
	case 318: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReplacePartitionUnit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtReplacePartitionUnit_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 319 NTSTATUS NtReplyWaitReplyPort ['HANDLE PortHandle', 'PPORT_MESSAGE ReplyMessage']
	case 319: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtReplyWaitReplyPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtReplyWaitReplyPort_enter, cpu, pc, arg0, arg1);
	}; break;
	// 320 NTSTATUS NtRequestPort ['HANDLE PortHandle', 'PPORT_MESSAGE RequestMessage']
	case 320: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRequestPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRequestPort_enter, cpu, pc, arg0, arg1);
	}; break;
	// 321 NTSTATUS NtResetEvent ['HANDLE EventHandle', 'PLONG PreviousState']
	case 321: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtResetEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtResetEvent_enter, cpu, pc, arg0, arg1);
	}; break;
	// 322 NTSTATUS NtResetWriteWatch ['HANDLE ProcessHandle', 'PVOID BaseAddress', 'SIZE_T RegionSize']
	case 322: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtResetWriteWatch_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtResetWriteWatch_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 323 NTSTATUS NtRestoreKey ['HANDLE KeyHandle', 'HANDLE FileHandle', 'ULONG Flags']
	case 323: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRestoreKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtRestoreKey_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 324 NTSTATUS NtResumeProcess ['HANDLE ProcessHandle']
	case 324: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtResumeProcess_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtResumeProcess_enter, cpu, pc, arg0);
	}; break;
	// 325 NTSTATUS NtRollbackComplete ['HANDLE EnlistmentHandle', 'PLARGE_INTEGER TmVirtualClock']
	case 325: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRollbackComplete_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRollbackComplete_enter, cpu, pc, arg0, arg1);
	}; break;
	// 326 NTSTATUS NtRollbackEnlistment ['HANDLE EnlistmentHandle', 'PLARGE_INTEGER TmVirtualClock']
	case 326: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRollbackEnlistment_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRollbackEnlistment_enter, cpu, pc, arg0, arg1);
	}; break;
	// 327 NTSTATUS NtRollbackTransaction ['HANDLE TransactionHandle', 'BOOLEAN Wait']
	case 327: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRollbackTransaction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtRollbackTransaction_enter, cpu, pc, arg0, arg1);
	}; break;
	// 328 NTSTATUS NtRollforwardTransactionManager ['HANDLE TransactionManagerHandle', 'PLARGE_INTEGER TmVirtualClock']
	case 328: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtRollforwardTransactionManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtRollforwardTransactionManager_enter, cpu, pc, arg0, arg1);
	}; break;
	// 329 NTSTATUS NtSaveKey ['HANDLE KeyHandle', 'HANDLE FileHandle']
	case 329: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSaveKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSaveKey_enter, cpu, pc, arg0, arg1);
	}; break;
	// 330 NTSTATUS NtSaveKeyEx ['HANDLE KeyHandle', 'HANDLE FileHandle', 'ULONG Format']
	case 330: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSaveKeyEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSaveKeyEx_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 331 NTSTATUS NtSaveMergedKeys ['HANDLE HighPrecedenceKeyHandle', 'HANDLE LowPrecedenceKeyHandle', 'HANDLE FileHandle']
	case 331: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSaveMergedKeys_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSaveMergedKeys_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 332 NTSTATUS NtSecureConnectPort ['PHANDLE PortHandle', 'PUNICODE_STRING PortName', 'PSECURITY_QUALITY_OF_SERVICE SecurityQos', 'PPORT_VIEW ClientView', 'PSID RequiredServerSid', 'PREMOTE_PORT_VIEW ServerView', 'PULONG MaxMessageLength', 'PVOID ConnectionInformation', 'PULONG ConnectionInformationLength']
	case 332: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		uint64_t arg6 = get_64(cpu, &ctx, 6);
		uint64_t arg7 = get_64(cpu, &ctx, 7);
		uint64_t arg8 = get_64(cpu, &ctx, 8);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSecureConnectPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
			memcpy(ctx.args[7], &arg7, sizeof(uint64_t));
			memcpy(ctx.args[8], &arg8, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSecureConnectPort_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
	}; break;
	// 333 NTSTATUS NtSerializeBoot ['']
	case 333: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtSerializeBoot_enter, cpu, pc);
	}; break;
	// 334 NTSTATUS NtSetBootEntryOrder ['PULONG Ids', 'ULONG Count']
	case 334: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetBootEntryOrder_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetBootEntryOrder_enter, cpu, pc, arg0, arg1);
	}; break;
	// 335 NTSTATUS NtSetBootOptions ['PBOOT_OPTIONS BootOptions', 'ULONG FieldsToChange']
	case 335: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetBootOptions_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetBootOptions_enter, cpu, pc, arg0, arg1);
	}; break;
	// 336 NTSTATUS NtSetContextThread ['HANDLE ThreadHandle', 'PCONTEXT ThreadContext']
	case 336: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetContextThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetContextThread_enter, cpu, pc, arg0, arg1);
	}; break;
	// 337 NTSTATUS NtSetDebugFilterState ['ULONG ComponentId', 'ULONG Level', 'BOOLEAN State']
	case 337: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetDebugFilterState_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetDebugFilterState_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 338 NTSTATUS NtSetDefaultHardErrorPort ['HANDLE DefaultHardErrorPort']
	case 338: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetDefaultHardErrorPort_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetDefaultHardErrorPort_enter, cpu, pc, arg0);
	}; break;
	// 339 NTSTATUS NtSetDefaultLocale ['BOOLEAN UserProfile', 'LCID DefaultLocaleId']
	case 339: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetDefaultLocale_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetDefaultLocale_enter, cpu, pc, arg0, arg1);
	}; break;
	// 340 NTSTATUS NtSetDefaultUILanguage ['LANGID DefaultUILanguageId']
	case 340: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetDefaultUILanguage_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetDefaultUILanguage_enter, cpu, pc, arg0);
	}; break;
	// 341 NTSTATUS NtSetDriverEntryOrder ['PULONG Ids', 'ULONG Count']
	case 341: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetDriverEntryOrder_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetDriverEntryOrder_enter, cpu, pc, arg0, arg1);
	}; break;
	// 342 NTSTATUS NtSetEaFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length']
	case 342: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetEaFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetEaFile_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 343 NTSTATUS NtSetHighEventPair ['HANDLE EventPairHandle']
	case 343: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetHighEventPair_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetHighEventPair_enter, cpu, pc, arg0);
	}; break;
	// 344 NTSTATUS NtSetHighWaitLowEventPair ['HANDLE EventPairHandle']
	case 344: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetHighWaitLowEventPair_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetHighWaitLowEventPair_enter, cpu, pc, arg0);
	}; break;
	// 345 NTSTATUS NtSetInformationDebugObject ['HANDLE DebugObjectHandle', 'DEBUGOBJECTINFOCLASS DebugObjectInformationClass', 'PVOID DebugInformation', 'ULONG DebugInformationLength', 'PULONG ReturnLength']
	case 345: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationDebugObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetInformationDebugObject_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 346 NTSTATUS NtSetInformationEnlistment ['HANDLE EnlistmentHandle', 'ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass', 'PVOID EnlistmentInformation', 'ULONG EnlistmentInformationLength']
	case 346: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationEnlistment_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetInformationEnlistment_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 347 NTSTATUS NtSetInformationJobObject ['HANDLE JobHandle', 'JOBOBJECTINFOCLASS JobObjectInformationClass', 'PVOID JobObjectInformation', 'ULONG JobObjectInformationLength']
	case 347: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationJobObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetInformationJobObject_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 348 NTSTATUS NtSetInformationKey ['HANDLE KeyHandle', 'KEY_SET_INFORMATION_CLASS KeySetInformationClass', 'PVOID KeySetInformation', 'ULONG KeySetInformationLength']
	case 348: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetInformationKey_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 349 NTSTATUS NtSetInformationResourceManager ['HANDLE ResourceManagerHandle', 'RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass', 'PVOID ResourceManagerInformation', 'ULONG ResourceManagerInformationLength']
	case 349: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationResourceManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetInformationResourceManager_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 350 NTSTATUS NtSetInformationToken ['HANDLE TokenHandle', 'TOKEN_INFORMATION_CLASS TokenInformationClass', 'PVOID TokenInformation', 'ULONG TokenInformationLength']
	case 350: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationToken_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetInformationToken_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 351 NTSTATUS NtSetInformationTransaction ['HANDLE TransactionHandle', 'TRANSACTION_INFORMATION_CLASS TransactionInformationClass', 'PVOID TransactionInformation', 'ULONG TransactionInformationLength']
	case 351: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationTransaction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetInformationTransaction_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 352 NTSTATUS NtSetInformationTransactionManager ['HANDLE TmHandle', 'TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass', 'PVOID TransactionManagerInformation', 'ULONG TransactionManagerInformationLength']
	case 352: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationTransactionManager_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetInformationTransactionManager_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 353 NTSTATUS NtSetInformationWorkerFactory ['HANDLE WorkerFactoryHandle', 'WORKERFACTORYINFOCLASS WorkerFactoryInformationClass', 'PVOID WorkerFactoryInformation', 'ULONG WorkerFactoryInformationLength']
	case 353: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetInformationWorkerFactory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetInformationWorkerFactory_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 354 NTSTATUS NtSetIntervalProfile ['ULONG Interval', 'KPROFILE_SOURCE Source']
	case 354: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetIntervalProfile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetIntervalProfile_enter, cpu, pc, arg0, arg1);
	}; break;
	// 355 NTSTATUS NtSetIoCompletion ['HANDLE IoCompletionHandle', 'PVOID KeyContext', 'PVOID ApcContext', 'NTSTATUS IoStatus', 'ULONG_PTR IoStatusInformation']
	case 355: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint64_t arg4 = get_64(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetIoCompletion_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetIoCompletion_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 356 NTSTATUS NtSetIoCompletionEx ['HANDLE IoCompletionHandle', 'HANDLE IoCompletionReserveHandle', 'PVOID KeyContext', 'PVOID ApcContext', 'NTSTATUS IoStatus', 'ULONG_PTR IoStatusInformation']
	case 356: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetIoCompletionEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetIoCompletionEx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 357 NTSTATUS NtSetLdtEntries ['ULONG Selector0', 'ULONG Entry0Low', 'ULONG Entry0Hi', 'ULONG Selector1', 'ULONG Entry1Low', 'ULONG Entry1Hi']
	case 357: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetLdtEntries_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetLdtEntries_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 358 NTSTATUS NtSetLowEventPair ['HANDLE EventPairHandle']
	case 358: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetLowEventPair_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetLowEventPair_enter, cpu, pc, arg0);
	}; break;
	// 359 NTSTATUS NtSetLowWaitHighEventPair ['HANDLE EventPairHandle']
	case 359: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetLowWaitHighEventPair_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetLowWaitHighEventPair_enter, cpu, pc, arg0);
	}; break;
	// 360 NTSTATUS NtSetQuotaInformationFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length']
	case 360: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetQuotaInformationFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetQuotaInformationFile_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 361 NTSTATUS NtSetSecurityObject ['HANDLE Handle', 'SECURITY_INFORMATION SecurityInformation', 'PSECURITY_DESCRIPTOR SecurityDescriptor']
	case 361: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetSecurityObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetSecurityObject_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 362 NTSTATUS NtSetSystemEnvironmentValue ['PUNICODE_STRING VariableName', 'PUNICODE_STRING VariableValue']
	case 362: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetSystemEnvironmentValue_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetSystemEnvironmentValue_enter, cpu, pc, arg0, arg1);
	}; break;
	// 363 NTSTATUS NtSetSystemEnvironmentValueEx ['PUNICODE_STRING VariableName', 'LPGUID VendorGuid', 'PVOID Value', 'ULONG ValueLength', 'ULONG Attributes']
	case 363: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetSystemEnvironmentValueEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetSystemEnvironmentValueEx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 364 NTSTATUS NtSetSystemInformation ['SYSTEM_INFORMATION_CLASS SystemInformationClass', 'PVOID SystemInformation', 'ULONG SystemInformationLength']
	case 364: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetSystemInformation_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetSystemInformation_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 365 NTSTATUS NtSetSystemPowerState ['POWER_ACTION SystemAction', 'SYSTEM_POWER_STATE MinSystemState', 'ULONG Flags']
	case 365: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetSystemPowerState_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetSystemPowerState_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 366 NTSTATUS NtSetSystemTime ['PLARGE_INTEGER SystemTime', 'PLARGE_INTEGER PreviousTime']
	case 366: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetSystemTime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetSystemTime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 367 NTSTATUS NtSetThreadExecutionState ['EXECUTION_STATE esFlags', 'PEXECUTION_STATE PreviousFlags']
	case 367: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetThreadExecutionState_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetThreadExecutionState_enter, cpu, pc, arg0, arg1);
	}; break;
	// 368 NTSTATUS NtSetTimerEx ['HANDLE TimerHandle', 'TIMER_SET_INFORMATION_CLASS TimerSetInformationClass', 'PVOID TimerSetInformation', 'ULONG TimerSetInformationLength']
	case 368: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetTimerEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetTimerEx_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 369 NTSTATUS NtSetTimerResolution ['ULONG DesiredTime', 'BOOLEAN SetResolution', 'PULONG ActualTime']
	case 369: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetTimerResolution_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetTimerResolution_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 370 NTSTATUS NtSetUuidSeed ['PCHAR Seed']
	case 370: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetUuidSeed_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSetUuidSeed_enter, cpu, pc, arg0);
	}; break;
	// 371 NTSTATUS NtSetVolumeInformationFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID FsInformation', 'ULONG Length', 'FS_INFORMATION_CLASS FsInformationClass']
	case 371: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSetVolumeInformationFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtSetVolumeInformationFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 372 NTSTATUS NtShutdownSystem ['SHUTDOWN_ACTION Action']
	case 372: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtShutdownSystem_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtShutdownSystem_enter, cpu, pc, arg0);
	}; break;
	// 373 NTSTATUS NtShutdownWorkerFactory ['HANDLE WorkerFactoryHandle', 'LONG *PendingWorkerCount']
	case 373: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtShutdownWorkerFactory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtShutdownWorkerFactory_enter, cpu, pc, arg0, arg1);
	}; break;
	// 374 NTSTATUS NtSignalAndWaitForSingleObject ['HANDLE SignalHandle', 'HANDLE WaitHandle', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout']
	case 374: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSignalAndWaitForSingleObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSignalAndWaitForSingleObject_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 375 NTSTATUS NtSinglePhaseReject ['HANDLE EnlistmentHandle', 'PLARGE_INTEGER TmVirtualClock']
	case 375: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSinglePhaseReject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSinglePhaseReject_enter, cpu, pc, arg0, arg1);
	}; break;
	// 376 NTSTATUS NtStartProfile ['HANDLE ProfileHandle']
	case 376: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtStartProfile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtStartProfile_enter, cpu, pc, arg0);
	}; break;
	// 377 NTSTATUS NtStopProfile ['HANDLE ProfileHandle']
	case 377: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtStopProfile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtStopProfile_enter, cpu, pc, arg0);
	}; break;
	// 378 NTSTATUS NtSuspendProcess ['HANDLE ProcessHandle']
	case 378: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSuspendProcess_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSuspendProcess_enter, cpu, pc, arg0);
	}; break;
	// 379 NTSTATUS NtSuspendThread ['HANDLE ThreadHandle', 'PULONG PreviousSuspendCount']
	case 379: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSuspendThread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSuspendThread_enter, cpu, pc, arg0, arg1);
	}; break;
	// 380 NTSTATUS NtSystemDebugControl ['SYSDBG_COMMAND Command', 'PVOID InputBuffer', 'ULONG InputBufferLength', 'PVOID OutputBuffer', 'ULONG OutputBufferLength', 'PULONG ReturnLength']
	case 380: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtSystemDebugControl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtSystemDebugControl_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 381 NTSTATUS NtTerminateJobObject ['HANDLE JobHandle', 'NTSTATUS ExitStatus']
	case 381: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtTerminateJobObject_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtTerminateJobObject_enter, cpu, pc, arg0, arg1);
	}; break;
	// 382 NTSTATUS NtTestAlert ['']
	case 382: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtTestAlert_enter, cpu, pc);
	}; break;
	// 383 NTSTATUS NtThawRegistry ['']
	case 383: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtThawRegistry_enter, cpu, pc);
	}; break;
	// 384 NTSTATUS NtThawTransactions ['']
	case 384: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_NtThawTransactions_enter, cpu, pc);
	}; break;
	// 385 NTSTATUS NtTraceControl ['ULONG FunctionCode', 'PVOID InBuffer', 'ULONG InBufferLen', 'PVOID OutBuffer', 'ULONG OutBufferLen', 'PULONG ReturnLength']
	case 385: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint64_t arg5 = get_64(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtTraceControl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtTraceControl_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 386 NTSTATUS NtTranslateFilePath ['PFILE_PATH InputFilePath', 'ULONG OutputType', 'PFILE_PATH OutputFilePath', 'PULONG OutputFilePathLength']
	case 386: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtTranslateFilePath_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtTranslateFilePath_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 387 NTSTATUS NtUmsThreadYield ['PVOID SchedulerParam']
	case 387: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtUmsThreadYield_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtUmsThreadYield_enter, cpu, pc, arg0);
	}; break;
	// 388 NTSTATUS NtUnloadDriver ['PUNICODE_STRING DriverServiceName']
	case 388: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtUnloadDriver_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtUnloadDriver_enter, cpu, pc, arg0);
	}; break;
	// 389 NTSTATUS NtUnloadKey ['POBJECT_ATTRIBUTES TargetKey']
	case 389: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtUnloadKey_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtUnloadKey_enter, cpu, pc, arg0);
	}; break;
	// 390 NTSTATUS NtUnloadKey2 ['POBJECT_ATTRIBUTES TargetKey', 'ULONG Flags']
	case 390: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtUnloadKey2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtUnloadKey2_enter, cpu, pc, arg0, arg1);
	}; break;
	// 391 NTSTATUS NtUnloadKeyEx ['POBJECT_ATTRIBUTES TargetKey', 'HANDLE Event']
	case 391: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtUnloadKeyEx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtUnloadKeyEx_enter, cpu, pc, arg0, arg1);
	}; break;
	// 392 NTSTATUS NtUnlockFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PLARGE_INTEGER ByteOffset', 'PLARGE_INTEGER Length', 'ULONG Key']
	case 392: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtUnlockFile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtUnlockFile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 393 NTSTATUS NtUnlockVirtualMemory ['HANDLE ProcessHandle', 'PVOID *BaseAddress', 'PSIZE_T RegionSize', 'ULONG MapType']
	case 393: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtUnlockVirtualMemory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_NtUnlockVirtualMemory_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 394 NTSTATUS NtVdmControl ['VDMSERVICECLASS Service', 'PVOID ServiceData']
	case 394: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtVdmControl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtVdmControl_enter, cpu, pc, arg0, arg1);
	}; break;
	// 395 NTSTATUS NtWaitForDebugEvent ['HANDLE DebugObjectHandle', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout', 'PDBGUI_WAIT_STATE_CHANGE WaitStateChange']
	case 395: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = get_64(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWaitForDebugEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWaitForDebugEvent_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 396 NTSTATUS NtWaitForKeyedEvent ['HANDLE KeyedEventHandle', 'PVOID KeyValue', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout']
	case 396: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = get_64(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWaitForKeyedEvent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWaitForKeyedEvent_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 397 NTSTATUS NtWaitForWorkViaWorkerFactory ['HANDLE WorkerFactoryHandle', 'PFILE_IO_COMPLETION_INFORMATION MiniPacket']
	case 397: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		uint64_t arg1 = get_64(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWaitForWorkViaWorkerFactory_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWaitForWorkViaWorkerFactory_enter, cpu, pc, arg0, arg1);
	}; break;
	// 398 NTSTATUS NtWaitHighEventPair ['HANDLE EventPairHandle']
	case 398: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWaitHighEventPair_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWaitHighEventPair_enter, cpu, pc, arg0);
	}; break;
	// 399 NTSTATUS NtWaitLowEventPair ['HANDLE EventPairHandle']
	case 399: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWaitLowEventPair_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWaitLowEventPair_enter, cpu, pc, arg0);
	}; break;
	// 400 NTSTATUS NtWorkerFactoryWorkerReady ['HANDLE WorkerFactoryHandle']
	case 400: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_NtWorkerFactoryWorkerReady_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_NtWorkerFactoryWorkerReady_enter, cpu, pc, arg0);
	}; break;
	default:
		panda_noreturn = false;
		PPP_RUN_CB(on_unknown_sys_enter, cpu, pc, ctx.no);
	} // switch (ctx.no)

	PPP_RUN_CB(on_all_sys_enter, cpu, pc, ctx.no);
	PPP_RUN_CB(on_all_sys_enter2, cpu, pc, call, &ctx);
	if (!panda_noreturn) {
		struct hook h;
		h.addr = ctx.retaddr;
		h.asid = ctx.asid;
		h.cb.before_tcg_codegen = hook_syscall_return;
		h.type = PANDA_CB_BEFORE_TCG_CODEGEN;
		h.enabled = true;
		h.km = MODE_ANY; //you'd expect this to be user only
		hooks_add_hook(&h);

		running_syscalls[std::make_pair(ctx.retaddr, ctx.asid)] = ctx;
	}
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */