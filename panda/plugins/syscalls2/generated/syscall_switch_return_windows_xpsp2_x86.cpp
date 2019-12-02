#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls2_info.h"

extern const syscall_info_t *syscall_info;
extern const syscall_meta_t *syscall_meta;

extern "C" {
#include "syscalls_ext_typedefs.h"
#include "syscall_ppp_extern_return.h"
}

void syscall_return_switch_windows_xpsp2_x86(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx) {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
	const syscall_info_t *call = (syscall_meta == NULL || ctx->no > syscall_meta->max_generic) ? NULL : &syscall_info[ctx->no];
	switch (ctx->no) {
		// 0 NTSTATUS NtAcceptConnectPort ['PHANDLE PortHandle', 'PVOID PortContext', 'PPORT_MESSAGE ConnectionRequest', 'BOOLEAN AcceptConnection', 'PPORT_VIEW ServerView', 'PREMOTE_PORT_VIEW ClientView']
		case 0: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtAcceptConnectPort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAcceptConnectPort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 1 NTSTATUS NtAccessCheck ['PSECURITY_DESCRIPTOR SecurityDescriptor', 'HANDLE ClientToken', 'ACCESS_MASK DesiredAccess', 'PGENERIC_MAPPING GenericMapping', 'PPRIVILEGE_SET PrivilegeSet', 'PULONG PrivilegeSetLength', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus']
		case 1: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtAccessCheck_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheck_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 2 NTSTATUS NtAccessCheckAndAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'PUNICODE_STRING ObjectTypeName', 'PUNICODE_STRING ObjectName', 'PSECURITY_DESCRIPTOR SecurityDescriptor', 'ACCESS_MASK DesiredAccess', 'PGENERIC_MAPPING GenericMapping', 'BOOLEAN ObjectCreation', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus', 'PBOOLEAN GenerateOnClose']
		case 2: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			uint32_t arg10;
			if (PPP_CHECK_CB(on_NtAccessCheckAndAuditAlarm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
				memcpy(&arg10, ctx->args[10], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheckAndAuditAlarm_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 3 NTSTATUS NtAccessCheckByType ['PSECURITY_DESCRIPTOR SecurityDescriptor', 'PSID PrincipalSelfSid', 'HANDLE ClientToken', 'ACCESS_MASK DesiredAccess', 'POBJECT_TYPE_LIST ObjectTypeList', 'ULONG ObjectTypeListLength', 'PGENERIC_MAPPING GenericMapping', 'PPRIVILEGE_SET PrivilegeSet', 'PULONG PrivilegeSetLength', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus']
		case 3: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			uint32_t arg10;
			if (PPP_CHECK_CB(on_NtAccessCheckByType_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
				memcpy(&arg10, ctx->args[10], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheckByType_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 4 NTSTATUS NtAccessCheckByTypeAndAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'PUNICODE_STRING ObjectTypeName', 'PUNICODE_STRING ObjectName', 'PSECURITY_DESCRIPTOR SecurityDescriptor', 'PSID PrincipalSelfSid', 'ACCESS_MASK DesiredAccess', 'AUDIT_EVENT_TYPE AuditType', 'ULONG Flags', 'POBJECT_TYPE_LIST ObjectTypeList', 'ULONG ObjectTypeListLength', 'PGENERIC_MAPPING GenericMapping', 'BOOLEAN ObjectCreation', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus', 'PBOOLEAN GenerateOnClose']
		case 4: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			uint32_t arg10;
			uint32_t arg11;
			uint32_t arg12;
			uint32_t arg13;
			uint32_t arg14;
			uint32_t arg15;
			if (PPP_CHECK_CB(on_NtAccessCheckByTypeAndAuditAlarm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
				memcpy(&arg10, ctx->args[10], sizeof(uint32_t));
				memcpy(&arg11, ctx->args[11], sizeof(uint32_t));
				memcpy(&arg12, ctx->args[12], sizeof(uint32_t));
				memcpy(&arg13, ctx->args[13], sizeof(uint32_t));
				memcpy(&arg14, ctx->args[14], sizeof(uint32_t));
				memcpy(&arg15, ctx->args[15], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheckByTypeAndAuditAlarm_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15) ;
		}; break;
		// 5 NTSTATUS NtAccessCheckByTypeResultList ['PSECURITY_DESCRIPTOR SecurityDescriptor', 'PSID PrincipalSelfSid', 'HANDLE ClientToken', 'ACCESS_MASK DesiredAccess', 'POBJECT_TYPE_LIST ObjectTypeList', 'ULONG ObjectTypeListLength', 'PGENERIC_MAPPING GenericMapping', 'PPRIVILEGE_SET PrivilegeSet', 'PULONG PrivilegeSetLength', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus']
		case 5: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			uint32_t arg10;
			if (PPP_CHECK_CB(on_NtAccessCheckByTypeResultList_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
				memcpy(&arg10, ctx->args[10], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheckByTypeResultList_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 6 NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'PUNICODE_STRING ObjectTypeName', 'PUNICODE_STRING ObjectName', 'PSECURITY_DESCRIPTOR SecurityDescriptor', 'PSID PrincipalSelfSid', 'ACCESS_MASK DesiredAccess', 'AUDIT_EVENT_TYPE AuditType', 'ULONG Flags', 'POBJECT_TYPE_LIST ObjectTypeList', 'ULONG ObjectTypeListLength', 'PGENERIC_MAPPING GenericMapping', 'BOOLEAN ObjectCreation', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus', 'PBOOLEAN GenerateOnClose']
		case 6: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			uint32_t arg10;
			uint32_t arg11;
			uint32_t arg12;
			uint32_t arg13;
			uint32_t arg14;
			uint32_t arg15;
			if (PPP_CHECK_CB(on_NtAccessCheckByTypeResultListAndAuditAlarm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
				memcpy(&arg10, ctx->args[10], sizeof(uint32_t));
				memcpy(&arg11, ctx->args[11], sizeof(uint32_t));
				memcpy(&arg12, ctx->args[12], sizeof(uint32_t));
				memcpy(&arg13, ctx->args[13], sizeof(uint32_t));
				memcpy(&arg14, ctx->args[14], sizeof(uint32_t));
				memcpy(&arg15, ctx->args[15], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheckByTypeResultListAndAuditAlarm_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15) ;
		}; break;
		// 7 NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarmByHandle ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'HANDLE ClientToken', 'PUNICODE_STRING ObjectTypeName', 'PUNICODE_STRING ObjectName', 'PSECURITY_DESCRIPTOR SecurityDescriptor', 'PSID PrincipalSelfSid', 'ACCESS_MASK DesiredAccess', 'AUDIT_EVENT_TYPE AuditType', 'ULONG Flags', 'POBJECT_TYPE_LIST ObjectTypeList', 'ULONG ObjectTypeListLength', 'PGENERIC_MAPPING GenericMapping', 'BOOLEAN ObjectCreation', 'PACCESS_MASK GrantedAccess', 'PNTSTATUS AccessStatus', 'PBOOLEAN GenerateOnClose']
		case 7: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			uint32_t arg10;
			uint32_t arg11;
			uint32_t arg12;
			uint32_t arg13;
			uint32_t arg14;
			uint32_t arg15;
			uint32_t arg16;
			if (PPP_CHECK_CB(on_NtAccessCheckByTypeResultListAndAuditAlarmByHandle_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
				memcpy(&arg10, ctx->args[10], sizeof(uint32_t));
				memcpy(&arg11, ctx->args[11], sizeof(uint32_t));
				memcpy(&arg12, ctx->args[12], sizeof(uint32_t));
				memcpy(&arg13, ctx->args[13], sizeof(uint32_t));
				memcpy(&arg14, ctx->args[14], sizeof(uint32_t));
				memcpy(&arg15, ctx->args[15], sizeof(uint32_t));
				memcpy(&arg16, ctx->args[16], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheckByTypeResultListAndAuditAlarmByHandle_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15, arg16) ;
		}; break;
		// 8 NTSTATUS NtAddAtom ['PWSTR AtomName', 'ULONG Length', 'PRTL_ATOM Atom']
		case 8: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAddAtom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAddAtom_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 9 NTSTATUS NtAddBootEntry ['PBOOT_ENTRY BootEntry', 'PULONG Id']
		case 9: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAddBootEntry_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAddBootEntry_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 10 NTSTATUS NtAdjustGroupsToken ['HANDLE TokenHandle', 'BOOLEAN ResetToDefault', 'PTOKEN_GROUPS NewState', 'ULONG BufferLength', 'PTOKEN_GROUPS PreviousState', 'PULONG ReturnLength']
		case 10: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtAdjustGroupsToken_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAdjustGroupsToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 11 NTSTATUS NtAdjustPrivilegesToken ['HANDLE TokenHandle', 'BOOLEAN DisableAllPrivileges', 'PTOKEN_PRIVILEGES NewState', 'ULONG BufferLength', 'PTOKEN_PRIVILEGES PreviousState', 'PULONG ReturnLength']
		case 11: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtAdjustPrivilegesToken_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAdjustPrivilegesToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 12 NTSTATUS NtAlertResumeThread ['HANDLE ThreadHandle', 'PULONG PreviousSuspendCount']
		case 12: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAlertResumeThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlertResumeThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 13 NTSTATUS NtAlertThread ['HANDLE ThreadHandle']
		case 13: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtAlertThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlertThread_return, cpu, pc, arg0) ;
		}; break;
		// 14 NTSTATUS NtAllocateLocallyUniqueId ['PLUID Luid']
		case 14: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtAllocateLocallyUniqueId_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAllocateLocallyUniqueId_return, cpu, pc, arg0) ;
		}; break;
		// 15 NTSTATUS NtAllocateUserPhysicalPages ['HANDLE ProcessHandle', 'PULONG_PTR NumberOfPages', 'PULONG_PTR UserPfnArray']
		case 15: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAllocateUserPhysicalPages_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAllocateUserPhysicalPages_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 16 NTSTATUS NtAllocateUuids ['PULARGE_INTEGER Time', 'PULONG Range', 'PULONG Sequence', 'PCHAR Seed']
		case 16: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtAllocateUuids_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAllocateUuids_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 17 NTSTATUS NtAllocateVirtualMemory ['HANDLE ProcessHandle', 'PVOID *BaseAddress', 'ULONG_PTR ZeroBits', 'PSIZE_T RegionSize', 'ULONG AllocationType', 'ULONG Protect']
		case 17: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtAllocateVirtualMemory_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAllocateVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 18 NTSTATUS NtAreMappedFilesTheSame ['PVOID File1MappedAsAnImage', 'PVOID File2MappedAsFile']
		case 18: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAreMappedFilesTheSame_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAreMappedFilesTheSame_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 19 NTSTATUS NtAssignProcessToJobObject ['HANDLE JobHandle', 'HANDLE ProcessHandle']
		case 19: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAssignProcessToJobObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAssignProcessToJobObject_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 20 NTSTATUS NtCallbackReturn ['PVOID OutputBuffer', 'ULONG OutputLength', 'NTSTATUS Status']
		case 20: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCallbackReturn_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCallbackReturn_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 22 NTSTATUS NtCancelIoFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock']
		case 22: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtCancelIoFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCancelIoFile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 23 NTSTATUS NtCancelTimer ['HANDLE TimerHandle', 'PBOOLEAN CurrentState']
		case 23: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtCancelTimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCancelTimer_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 24 NTSTATUS NtClearEvent ['HANDLE EventHandle']
		case 24: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtClearEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtClearEvent_return, cpu, pc, arg0) ;
		}; break;
		// 25 NTSTATUS NtClose ['HANDLE Handle']
		case 25: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtClose_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtClose_return, cpu, pc, arg0) ;
		}; break;
		// 26 NTSTATUS NtCloseObjectAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'BOOLEAN GenerateOnClose']
		case 26: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCloseObjectAuditAlarm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCloseObjectAuditAlarm_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 27 NTSTATUS NtCompactKeys ['ULONG Count', 'HANDLE KeyArray[]']
		case 27: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtCompactKeys_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCompactKeys_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 28 NTSTATUS NtCompareTokens ['HANDLE FirstTokenHandle', 'HANDLE SecondTokenHandle', 'PBOOLEAN Equal']
		case 28: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCompareTokens_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCompareTokens_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 29 NTSTATUS NtCompleteConnectPort ['HANDLE PortHandle']
		case 29: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtCompleteConnectPort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCompleteConnectPort_return, cpu, pc, arg0) ;
		}; break;
		// 30 NTSTATUS NtCompressKey ['HANDLE Key']
		case 30: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtCompressKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCompressKey_return, cpu, pc, arg0) ;
		}; break;
		// 31 NTSTATUS NtConnectPort ['PHANDLE PortHandle', 'PUNICODE_STRING PortName', 'PSECURITY_QUALITY_OF_SERVICE SecurityQos', 'PPORT_VIEW ClientView', 'PREMOTE_PORT_VIEW ServerView', 'PULONG MaxMessageLength', 'PVOID ConnectionInformation', 'PULONG ConnectionInformationLength']
		case 31: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtConnectPort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtConnectPort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 32 NTSTATUS NtContinue ['PCONTEXT ContextRecord', 'BOOLEAN TestAlert']
		case 32: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtContinue_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtContinue_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 33 NTSTATUS NtCreateDebugObject ['PHANDLE DebugObjectHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG Flags']
		case 33: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreateDebugObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateDebugObject_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 34 NTSTATUS NtCreateDirectoryObject ['PHANDLE DirectoryHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 34: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCreateDirectoryObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateDirectoryObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 35 NTSTATUS NtCreateEvent ['PHANDLE EventHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'EVENT_TYPE EventType', 'BOOLEAN InitialState']
		case 35: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtCreateEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateEvent_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 36 NTSTATUS NtCreateEventPair ['PHANDLE EventPairHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 36: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCreateEventPair_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateEventPair_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 37 NTSTATUS NtCreateFile ['PHANDLE FileHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PIO_STATUS_BLOCK IoStatusBlock', 'PLARGE_INTEGER AllocationSize', 'ULONG FileAttributes', 'ULONG ShareAccess', 'ULONG CreateDisposition', 'ULONG CreateOptions', 'PVOID EaBuffer', 'ULONG EaLength']
		case 37: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			uint32_t arg10;
			if (PPP_CHECK_CB(on_NtCreateFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
				memcpy(&arg10, ctx->args[10], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 38 NTSTATUS NtCreateIoCompletion ['PHANDLE IoCompletionHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG Count']
		case 38: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreateIoCompletion_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateIoCompletion_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 39 NTSTATUS NtCreateJobObject ['PHANDLE JobHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 39: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCreateJobObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateJobObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 40 NTSTATUS NtCreateJobSet ['ULONG NumJob', 'PJOB_SET_ARRAY UserJobSet', 'ULONG Flags']
		case 40: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCreateJobSet_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateJobSet_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 41 NTSTATUS NtCreateKey ['PHANDLE KeyHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG TitleIndex', 'PUNICODE_STRING Class', 'ULONG CreateOptions', 'PULONG Disposition']
		case 41: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtCreateKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 42 NTSTATUS NtCreateMailslotFile ['PHANDLE FileHandle', 'ULONG DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG CreateOptions', 'ULONG MailslotQuota', 'ULONG MaximumMessageSize', 'PLARGE_INTEGER ReadTimeout']
		case 42: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtCreateMailslotFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateMailslotFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 43 NTSTATUS NtCreateMutant ['PHANDLE MutantHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'BOOLEAN InitialOwner']
		case 43: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreateMutant_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateMutant_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 44 NTSTATUS NtCreateNamedPipeFile ['PHANDLE FileHandle', 'ULONG DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG ShareAccess', 'ULONG CreateDisposition', 'ULONG CreateOptions', 'ULONG NamedPipeType', 'ULONG ReadMode', 'ULONG CompletionMode', 'ULONG MaximumInstances', 'ULONG InboundQuota', 'ULONG OutboundQuota', 'PLARGE_INTEGER DefaultTimeout']
		case 44: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			uint32_t arg10;
			uint32_t arg11;
			uint32_t arg12;
			uint32_t arg13;
			if (PPP_CHECK_CB(on_NtCreateNamedPipeFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
				memcpy(&arg10, ctx->args[10], sizeof(uint32_t));
				memcpy(&arg11, ctx->args[11], sizeof(uint32_t));
				memcpy(&arg12, ctx->args[12], sizeof(uint32_t));
				memcpy(&arg13, ctx->args[13], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateNamedPipeFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13) ;
		}; break;
		// 45 NTSTATUS NtCreatePagingFile ['PUNICODE_STRING PageFileName', 'PLARGE_INTEGER MinimumSize', 'PLARGE_INTEGER MaximumSize', 'ULONG Priority']
		case 45: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreatePagingFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreatePagingFile_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 46 NTSTATUS NtCreatePort ['PHANDLE PortHandle', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG MaxConnectionInfoLength', 'ULONG MaxMessageLength', 'ULONG MaxPoolUsage']
		case 46: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtCreatePort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreatePort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 47 NTSTATUS NtCreateProcess ['PHANDLE ProcessHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'HANDLE ParentProcess', 'BOOLEAN InheritObjectTable', 'HANDLE SectionHandle', 'HANDLE DebugPort', 'HANDLE ExceptionPort']
		case 47: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtCreateProcess_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateProcess_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 48 NTSTATUS NtCreateProcessEx ['PHANDLE ProcessHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'HANDLE ParentProcess', 'ULONG Flags', 'HANDLE SectionHandle', 'HANDLE DebugPort', 'HANDLE ExceptionPort', 'ULONG JobMemberLevel']
		case 48: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtCreateProcessEx_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateProcessEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 49 NTSTATUS NtCreateProfile ['PHANDLE ProfileHandle', 'HANDLE Process', 'PVOID RangeBase', 'SIZE_T RangeSize', 'ULONG BucketSize', 'PULONG Buffer', 'ULONG BufferSize', 'KPROFILE_SOURCE ProfileSource', 'KAFFINITY Affinity']
		case 49: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtCreateProfile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateProfile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 50 NTSTATUS NtCreateSection ['PHANDLE SectionHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PLARGE_INTEGER MaximumSize', 'ULONG SectionPageProtection', 'ULONG AllocationAttributes', 'HANDLE FileHandle']
		case 50: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtCreateSection_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateSection_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 51 NTSTATUS NtCreateSemaphore ['PHANDLE SemaphoreHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'LONG InitialCount', 'LONG MaximumCount']
		case 51: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			int32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_NtCreateSemaphore_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_NtCreateSemaphore_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 52 NTSTATUS NtCreateSymbolicLinkObject ['PHANDLE LinkHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PUNICODE_STRING LinkTarget']
		case 52: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreateSymbolicLinkObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateSymbolicLinkObject_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 53 NTSTATUS NtCreateThread ['PHANDLE ThreadHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'HANDLE ProcessHandle', 'PCLIENT_ID ClientId', 'PCONTEXT ThreadContext', 'PINITIAL_TEB InitialTeb', 'BOOLEAN CreateSuspended']
		case 53: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtCreateThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateThread_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 54 NTSTATUS NtCreateTimer ['PHANDLE TimerHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'TIMER_TYPE TimerType']
		case 54: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreateTimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateTimer_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 55 NTSTATUS NtCreateToken ['PHANDLE TokenHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'TOKEN_TYPE TokenType', 'PLUID AuthenticationId', 'PLARGE_INTEGER ExpirationTime', 'PTOKEN_USER User', 'PTOKEN_GROUPS Groups', 'PTOKEN_PRIVILEGES Privileges', 'PTOKEN_OWNER Owner', 'PTOKEN_PRIMARY_GROUP PrimaryGroup', 'PTOKEN_DEFAULT_DACL DefaultDacl', 'PTOKEN_SOURCE TokenSource']
		case 55: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			uint32_t arg10;
			uint32_t arg11;
			uint32_t arg12;
			if (PPP_CHECK_CB(on_NtCreateToken_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
				memcpy(&arg10, ctx->args[10], sizeof(uint32_t));
				memcpy(&arg11, ctx->args[11], sizeof(uint32_t));
				memcpy(&arg12, ctx->args[12], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12) ;
		}; break;
		// 56 NTSTATUS NtCreateWaitablePort ['PHANDLE PortHandle', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG MaxConnectionInfoLength', 'ULONG MaxMessageLength', 'ULONG MaxPoolUsage']
		case 56: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtCreateWaitablePort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateWaitablePort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 57 NTSTATUS NtDebugActiveProcess ['HANDLE ProcessHandle', 'HANDLE DebugObjectHandle']
		case 57: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtDebugActiveProcess_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDebugActiveProcess_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 58 NTSTATUS NtDebugContinue ['HANDLE DebugObjectHandle', 'PCLIENT_ID ClientId', 'NTSTATUS ContinueStatus']
		case 58: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtDebugContinue_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDebugContinue_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 59 NTSTATUS NtDelayExecution ['BOOLEAN Alertable', 'PLARGE_INTEGER DelayInterval']
		case 59: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtDelayExecution_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDelayExecution_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 60 NTSTATUS NtDeleteAtom ['RTL_ATOM Atom']
		case 60: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeleteAtom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteAtom_return, cpu, pc, arg0) ;
		}; break;
		// 61 NTSTATUS NtDeleteBootEntry ['ULONG Id']
		case 61: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeleteBootEntry_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteBootEntry_return, cpu, pc, arg0) ;
		}; break;
		// 62 NTSTATUS NtDeleteFile ['POBJECT_ATTRIBUTES ObjectAttributes']
		case 62: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeleteFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteFile_return, cpu, pc, arg0) ;
		}; break;
		// 63 NTSTATUS NtDeleteKey ['HANDLE KeyHandle']
		case 63: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeleteKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteKey_return, cpu, pc, arg0) ;
		}; break;
		// 64 NTSTATUS NtDeleteObjectAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'BOOLEAN GenerateOnClose']
		case 64: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtDeleteObjectAuditAlarm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteObjectAuditAlarm_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 65 NTSTATUS NtDeleteValueKey ['HANDLE KeyHandle', 'PUNICODE_STRING ValueName']
		case 65: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtDeleteValueKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteValueKey_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 66 NTSTATUS NtDeviceIoControlFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG IoControlCode', 'PVOID InputBuffer', 'ULONG InputBufferLength', 'PVOID OutputBuffer', 'ULONG OutputBufferLength']
		case 66: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			if (PPP_CHECK_CB(on_NtDeviceIoControlFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeviceIoControlFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 67 NTSTATUS NtDisplayString ['PUNICODE_STRING String']
		case 67: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDisplayString_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDisplayString_return, cpu, pc, arg0) ;
		}; break;
		// 68 NTSTATUS NtDuplicateObject ['HANDLE SourceProcessHandle', 'HANDLE SourceHandle', 'HANDLE TargetProcessHandle', 'PHANDLE TargetHandle', 'ACCESS_MASK DesiredAccess', 'ULONG HandleAttributes', 'ULONG Options']
		case 68: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtDuplicateObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDuplicateObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 69 NTSTATUS NtDuplicateToken ['HANDLE ExistingTokenHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'BOOLEAN EffectiveOnly', 'TOKEN_TYPE TokenType', 'PHANDLE NewTokenHandle']
		case 69: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtDuplicateToken_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDuplicateToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 70 NTSTATUS NtEnumerateBootEntries ['PVOID Buffer', 'PULONG BufferLength']
		case 70: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtEnumerateBootEntries_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtEnumerateBootEntries_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 71 NTSTATUS NtEnumerateKey ['HANDLE KeyHandle', 'ULONG Index', 'KEY_INFORMATION_CLASS KeyInformationClass', 'PVOID KeyInformation', 'ULONG Length', 'PULONG ResultLength']
		case 71: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtEnumerateKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtEnumerateKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 72 NTSTATUS NtEnumerateSystemEnvironmentValuesEx ['ULONG InformationClass', 'PVOID Buffer', 'PULONG BufferLength']
		case 72: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtEnumerateSystemEnvironmentValuesEx_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtEnumerateSystemEnvironmentValuesEx_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 73 NTSTATUS NtEnumerateValueKey ['HANDLE KeyHandle', 'ULONG Index', 'KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass', 'PVOID KeyValueInformation', 'ULONG Length', 'PULONG ResultLength']
		case 73: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtEnumerateValueKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtEnumerateValueKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 74 NTSTATUS NtExtendSection ['HANDLE SectionHandle', 'PLARGE_INTEGER NewSectionSize']
		case 74: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtExtendSection_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtExtendSection_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 75 NTSTATUS NtFilterToken ['HANDLE ExistingTokenHandle', 'ULONG Flags', 'PTOKEN_GROUPS SidsToDisable', 'PTOKEN_PRIVILEGES PrivilegesToDelete', 'PTOKEN_GROUPS RestrictedSids', 'PHANDLE NewTokenHandle']
		case 75: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtFilterToken_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFilterToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 76 NTSTATUS NtFindAtom ['PWSTR AtomName', 'ULONG Length', 'PRTL_ATOM Atom']
		case 76: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtFindAtom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFindAtom_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 77 NTSTATUS NtFlushBuffersFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock']
		case 77: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtFlushBuffersFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFlushBuffersFile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 78 NTSTATUS NtFlushInstructionCache ['HANDLE ProcessHandle', 'PVOID BaseAddress', 'SIZE_T Length']
		case 78: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtFlushInstructionCache_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFlushInstructionCache_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 79 NTSTATUS NtFlushKey ['HANDLE KeyHandle']
		case 79: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtFlushKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFlushKey_return, cpu, pc, arg0) ;
		}; break;
		// 80 NTSTATUS NtFlushVirtualMemory ['HANDLE ProcessHandle', 'PVOID *BaseAddress', 'PSIZE_T RegionSize', 'PIO_STATUS_BLOCK IoStatus']
		case 80: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtFlushVirtualMemory_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFlushVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 81 NTSTATUS NtFlushWriteBuffer ['']
		case 81: {
			if (PPP_CHECK_CB(on_NtFlushWriteBuffer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_NtFlushWriteBuffer_return, cpu, pc) ;
		}; break;
		// 82 NTSTATUS NtFreeUserPhysicalPages ['HANDLE ProcessHandle', 'PULONG_PTR NumberOfPages', 'PULONG_PTR UserPfnArray']
		case 82: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtFreeUserPhysicalPages_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFreeUserPhysicalPages_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 83 NTSTATUS NtFreeVirtualMemory ['HANDLE ProcessHandle', 'PVOID *BaseAddress', 'PSIZE_T RegionSize', 'ULONG FreeType']
		case 83: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtFreeVirtualMemory_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFreeVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 84 NTSTATUS NtFsControlFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG IoControlCode', 'PVOID InputBuffer', 'ULONG InputBufferLength', 'PVOID OutputBuffer', 'ULONG OutputBufferLength']
		case 84: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			if (PPP_CHECK_CB(on_NtFsControlFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFsControlFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 85 NTSTATUS NtGetContextThread ['HANDLE ThreadHandle', 'PCONTEXT ThreadContext']
		case 85: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtGetContextThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetContextThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 86 NTSTATUS NtGetDevicePowerState ['HANDLE Device', 'DEVICE_POWER_STATE *State']
		case 86: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtGetDevicePowerState_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetDevicePowerState_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 87 NTSTATUS NtGetPlugPlayEvent ['HANDLE EventHandle', 'PVOID Context', 'PPLUGPLAY_EVENT_BLOCK EventBlock', 'ULONG EventBufferSize']
		case 87: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtGetPlugPlayEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetPlugPlayEvent_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 88 NTSTATUS NtGetWriteWatch ['HANDLE ProcessHandle', 'ULONG Flags', 'PVOID BaseAddress', 'SIZE_T RegionSize', 'PVOID *UserAddressArray', 'PULONG_PTR EntriesInUserAddressArray', 'PULONG Granularity']
		case 88: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtGetWriteWatch_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetWriteWatch_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 89 NTSTATUS NtImpersonateAnonymousToken ['HANDLE ThreadHandle']
		case 89: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtImpersonateAnonymousToken_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtImpersonateAnonymousToken_return, cpu, pc, arg0) ;
		}; break;
		// 90 NTSTATUS NtImpersonateClientOfPort ['HANDLE PortHandle', 'PPORT_MESSAGE Message']
		case 90: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtImpersonateClientOfPort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtImpersonateClientOfPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 91 NTSTATUS NtImpersonateThread ['HANDLE ServerThreadHandle', 'HANDLE ClientThreadHandle', 'PSECURITY_QUALITY_OF_SERVICE SecurityQos']
		case 91: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtImpersonateThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtImpersonateThread_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 92 NTSTATUS NtInitializeRegistry ['USHORT BootCondition']
		case 92: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtInitializeRegistry_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtInitializeRegistry_return, cpu, pc, arg0) ;
		}; break;
		// 93 NTSTATUS NtInitiatePowerAction ['POWER_ACTION SystemAction', 'SYSTEM_POWER_STATE MinSystemState', 'ULONG Flags', 'BOOLEAN Asynchronous']
		case 93: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtInitiatePowerAction_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtInitiatePowerAction_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 94 NTSTATUS NtIsProcessInJob ['HANDLE ProcessHandle', 'HANDLE JobHandle']
		case 94: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtIsProcessInJob_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtIsProcessInJob_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 95 BOOLEAN NtIsSystemResumeAutomatic ['']
		case 95: {
			if (PPP_CHECK_CB(on_NtIsSystemResumeAutomatic_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_NtIsSystemResumeAutomatic_return, cpu, pc) ;
		}; break;
		// 96 NTSTATUS NtListenPort ['HANDLE PortHandle', 'PPORT_MESSAGE ConnectionRequest']
		case 96: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtListenPort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtListenPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 97 NTSTATUS NtLoadDriver ['PUNICODE_STRING DriverServiceName']
		case 97: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtLoadDriver_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLoadDriver_return, cpu, pc, arg0) ;
		}; break;
		// 98 NTSTATUS NtLoadKey ['POBJECT_ATTRIBUTES TargetKey', 'POBJECT_ATTRIBUTES SourceFile']
		case 98: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtLoadKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLoadKey_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 99 NTSTATUS NtLoadKey2 ['POBJECT_ATTRIBUTES TargetKey', 'POBJECT_ATTRIBUTES SourceFile', 'ULONG Flags']
		case 99: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtLoadKey2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLoadKey2_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 100 NTSTATUS NtLockFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PLARGE_INTEGER ByteOffset', 'PLARGE_INTEGER Length', 'ULONG Key', 'BOOLEAN FailImmediately', 'BOOLEAN ExclusiveLock']
		case 100: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			if (PPP_CHECK_CB(on_NtLockFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLockFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 101 NTSTATUS NtLockProductActivationKeys ['ULONG *pPrivateVer', 'ULONG *pSafeMode']
		case 101: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtLockProductActivationKeys_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLockProductActivationKeys_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 102 NTSTATUS NtLockRegistryKey ['HANDLE KeyHandle']
		case 102: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtLockRegistryKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLockRegistryKey_return, cpu, pc, arg0) ;
		}; break;
		// 103 NTSTATUS NtLockVirtualMemory ['HANDLE ProcessHandle', 'PVOID *BaseAddress', 'PSIZE_T RegionSize', 'ULONG MapType']
		case 103: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtLockVirtualMemory_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLockVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 104 NTSTATUS NtMakePermanentObject ['HANDLE Handle']
		case 104: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtMakePermanentObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtMakePermanentObject_return, cpu, pc, arg0) ;
		}; break;
		// 105 NTSTATUS NtMakeTemporaryObject ['HANDLE Handle']
		case 105: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtMakeTemporaryObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtMakeTemporaryObject_return, cpu, pc, arg0) ;
		}; break;
		// 106 NTSTATUS NtMapUserPhysicalPages ['PVOID VirtualAddress', 'ULONG_PTR NumberOfPages', 'PULONG_PTR UserPfnArray']
		case 106: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtMapUserPhysicalPages_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtMapUserPhysicalPages_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 107 NTSTATUS NtMapUserPhysicalPagesScatter ['PVOID *VirtualAddresses', 'ULONG_PTR NumberOfPages', 'PULONG_PTR UserPfnArray']
		case 107: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtMapUserPhysicalPagesScatter_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtMapUserPhysicalPagesScatter_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 108 NTSTATUS NtMapViewOfSection ['HANDLE SectionHandle', 'HANDLE ProcessHandle', 'PVOID *BaseAddress', 'ULONG_PTR ZeroBits', 'SIZE_T CommitSize', 'PLARGE_INTEGER SectionOffset', 'PSIZE_T ViewSize', 'SECTION_INHERIT InheritDisposition', 'ULONG AllocationType', 'WIN32_PROTECTION_MASK Win32Protect']
		case 108: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			if (PPP_CHECK_CB(on_NtMapViewOfSection_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtMapViewOfSection_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 109 NTSTATUS NtModifyBootEntry ['PBOOT_ENTRY BootEntry']
		case 109: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtModifyBootEntry_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtModifyBootEntry_return, cpu, pc, arg0) ;
		}; break;
		// 110 NTSTATUS NtNotifyChangeDirectoryFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length', 'ULONG CompletionFilter', 'BOOLEAN WatchTree']
		case 110: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtNotifyChangeDirectoryFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtNotifyChangeDirectoryFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 111 NTSTATUS NtNotifyChangeKey ['HANDLE KeyHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG CompletionFilter', 'BOOLEAN WatchTree', 'PVOID Buffer', 'ULONG BufferSize', 'BOOLEAN Asynchronous']
		case 111: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			if (PPP_CHECK_CB(on_NtNotifyChangeKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtNotifyChangeKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 112 NTSTATUS NtNotifyChangeMultipleKeys ['HANDLE MasterKeyHandle', 'ULONG Count', 'OBJECT_ATTRIBUTES SlaveObjects[]', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG CompletionFilter', 'BOOLEAN WatchTree', 'PVOID Buffer', 'ULONG BufferSize', 'BOOLEAN Asynchronous']
		case 112: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			uint32_t arg10;
			uint32_t arg11;
			if (PPP_CHECK_CB(on_NtNotifyChangeMultipleKeys_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
				memcpy(&arg10, ctx->args[10], sizeof(uint32_t));
				memcpy(&arg11, ctx->args[11], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtNotifyChangeMultipleKeys_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11) ;
		}; break;
		// 113 NTSTATUS NtOpenDirectoryObject ['PHANDLE DirectoryHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 113: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenDirectoryObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenDirectoryObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 114 NTSTATUS NtOpenEvent ['PHANDLE EventHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 114: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenEvent_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 115 NTSTATUS NtOpenEventPair ['PHANDLE EventPairHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 115: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenEventPair_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenEventPair_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 116 NTSTATUS NtOpenFile ['PHANDLE FileHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PIO_STATUS_BLOCK IoStatusBlock', 'ULONG ShareAccess', 'ULONG OpenOptions']
		case 116: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtOpenFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 117 NTSTATUS NtOpenIoCompletion ['PHANDLE IoCompletionHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 117: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenIoCompletion_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenIoCompletion_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 118 NTSTATUS NtOpenJobObject ['PHANDLE JobHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 118: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenJobObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenJobObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 119 NTSTATUS NtOpenKey ['PHANDLE KeyHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 119: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenKey_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 120 NTSTATUS NtOpenMutant ['PHANDLE MutantHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 120: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenMutant_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenMutant_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 121 NTSTATUS NtOpenObjectAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'PUNICODE_STRING ObjectTypeName', 'PUNICODE_STRING ObjectName', 'PSECURITY_DESCRIPTOR SecurityDescriptor', 'HANDLE ClientToken', 'ACCESS_MASK DesiredAccess', 'ACCESS_MASK GrantedAccess', 'PPRIVILEGE_SET Privileges', 'BOOLEAN ObjectCreation', 'BOOLEAN AccessGranted', 'PBOOLEAN GenerateOnClose']
		case 121: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			uint32_t arg10;
			uint32_t arg11;
			if (PPP_CHECK_CB(on_NtOpenObjectAuditAlarm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
				memcpy(&arg10, ctx->args[10], sizeof(uint32_t));
				memcpy(&arg11, ctx->args[11], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenObjectAuditAlarm_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11) ;
		}; break;
		// 122 NTSTATUS NtOpenProcess ['PHANDLE ProcessHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PCLIENT_ID ClientId']
		case 122: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtOpenProcess_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenProcess_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 123 NTSTATUS NtOpenProcessToken ['HANDLE ProcessHandle', 'ACCESS_MASK DesiredAccess', 'PHANDLE TokenHandle']
		case 123: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenProcessToken_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenProcessToken_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 124 NTSTATUS NtOpenProcessTokenEx ['HANDLE ProcessHandle', 'ACCESS_MASK DesiredAccess', 'ULONG HandleAttributes', 'PHANDLE TokenHandle']
		case 124: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtOpenProcessTokenEx_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenProcessTokenEx_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 125 NTSTATUS NtOpenSection ['PHANDLE SectionHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 125: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenSection_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenSection_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 126 NTSTATUS NtOpenSemaphore ['PHANDLE SemaphoreHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 126: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenSemaphore_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenSemaphore_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 127 NTSTATUS NtOpenSymbolicLinkObject ['PHANDLE LinkHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 127: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenSymbolicLinkObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenSymbolicLinkObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 128 NTSTATUS NtOpenThread ['PHANDLE ThreadHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'PCLIENT_ID ClientId']
		case 128: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtOpenThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenThread_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 129 NTSTATUS NtOpenThreadToken ['HANDLE ThreadHandle', 'ACCESS_MASK DesiredAccess', 'BOOLEAN OpenAsSelf', 'PHANDLE TokenHandle']
		case 129: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtOpenThreadToken_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenThreadToken_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 130 NTSTATUS NtOpenThreadTokenEx ['HANDLE ThreadHandle', 'ACCESS_MASK DesiredAccess', 'BOOLEAN OpenAsSelf', 'ULONG HandleAttributes', 'PHANDLE TokenHandle']
		case 130: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtOpenThreadTokenEx_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenThreadTokenEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 131 NTSTATUS NtOpenTimer ['PHANDLE TimerHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 131: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenTimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenTimer_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 132 NTSTATUS NtPlugPlayControl ['PLUGPLAY_CONTROL_CLASS PnPControlClass', 'PVOID PnPControlData', 'ULONG PnPControlDataLength']
		case 132: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtPlugPlayControl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPlugPlayControl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 133 NTSTATUS NtPowerInformation ['POWER_INFORMATION_LEVEL InformationLevel', 'PVOID InputBuffer', 'ULONG InputBufferLength', 'PVOID OutputBuffer', 'ULONG OutputBufferLength']
		case 133: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtPowerInformation_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPowerInformation_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 134 NTSTATUS NtPrivilegeCheck ['HANDLE ClientToken', 'PPRIVILEGE_SET RequiredPrivileges', 'PBOOLEAN Result']
		case 134: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtPrivilegeCheck_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPrivilegeCheck_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 135 NTSTATUS NtPrivilegeObjectAuditAlarm ['PUNICODE_STRING SubsystemName', 'PVOID HandleId', 'HANDLE ClientToken', 'ACCESS_MASK DesiredAccess', 'PPRIVILEGE_SET Privileges', 'BOOLEAN AccessGranted']
		case 135: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtPrivilegeObjectAuditAlarm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPrivilegeObjectAuditAlarm_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 136 NTSTATUS NtPrivilegedServiceAuditAlarm ['PUNICODE_STRING SubsystemName', 'PUNICODE_STRING ServiceName', 'HANDLE ClientToken', 'PPRIVILEGE_SET Privileges', 'BOOLEAN AccessGranted']
		case 136: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtPrivilegedServiceAuditAlarm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPrivilegedServiceAuditAlarm_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 137 NTSTATUS NtProtectVirtualMemory ['HANDLE ProcessHandle', 'PVOID *BaseAddress', 'PSIZE_T RegionSize', 'WIN32_PROTECTION_MASK NewProtectWin32', 'PULONG OldProtect']
		case 137: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtProtectVirtualMemory_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtProtectVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 138 NTSTATUS NtPulseEvent ['HANDLE EventHandle', 'PLONG PreviousState']
		case 138: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtPulseEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPulseEvent_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 139 NTSTATUS NtQueryAttributesFile ['POBJECT_ATTRIBUTES ObjectAttributes', 'PFILE_BASIC_INFORMATION FileInformation']
		case 139: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryAttributesFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryAttributesFile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 140 NTSTATUS NtQueryBootEntryOrder ['PULONG Ids', 'PULONG Count']
		case 140: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryBootEntryOrder_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryBootEntryOrder_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 141 NTSTATUS NtQueryBootOptions ['PBOOT_OPTIONS BootOptions', 'PULONG BootOptionsLength']
		case 141: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryBootOptions_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryBootOptions_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 142 NTSTATUS NtQueryDebugFilterState ['ULONG ComponentId', 'ULONG Level']
		case 142: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryDebugFilterState_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDebugFilterState_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 143 NTSTATUS NtQueryDefaultLocale ['BOOLEAN UserProfile', 'PLCID DefaultLocaleId']
		case 143: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryDefaultLocale_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDefaultLocale_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 144 NTSTATUS NtQueryDefaultUILanguage ['LANGID *DefaultUILanguageId']
		case 144: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtQueryDefaultUILanguage_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDefaultUILanguage_return, cpu, pc, arg0) ;
		}; break;
		// 145 NTSTATUS NtQueryDirectoryFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID FileInformation', 'ULONG Length', 'FILE_INFORMATION_CLASS FileInformationClass', 'BOOLEAN ReturnSingleEntry', 'PUNICODE_STRING FileName', 'BOOLEAN RestartScan']
		case 145: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			uint32_t arg9;
			uint32_t arg10;
			if (PPP_CHECK_CB(on_NtQueryDirectoryFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
				memcpy(&arg9, ctx->args[9], sizeof(uint32_t));
				memcpy(&arg10, ctx->args[10], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDirectoryFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 146 NTSTATUS NtQueryDirectoryObject ['HANDLE DirectoryHandle', 'PVOID Buffer', 'ULONG Length', 'BOOLEAN ReturnSingleEntry', 'BOOLEAN RestartScan', 'PULONG Context', 'PULONG ReturnLength']
		case 146: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtQueryDirectoryObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDirectoryObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 147 NTSTATUS NtQueryEaFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length', 'BOOLEAN ReturnSingleEntry', 'PVOID EaList', 'ULONG EaListLength', 'PULONG EaIndex', 'BOOLEAN RestartScan']
		case 147: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtQueryEaFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryEaFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 148 NTSTATUS NtQueryEvent ['HANDLE EventHandle', 'EVENT_INFORMATION_CLASS EventInformationClass', 'PVOID EventInformation', 'ULONG EventInformationLength', 'PULONG ReturnLength']
		case 148: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryEvent_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 149 NTSTATUS NtQueryFullAttributesFile ['POBJECT_ATTRIBUTES ObjectAttributes', 'PFILE_NETWORK_OPEN_INFORMATION FileInformation']
		case 149: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryFullAttributesFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryFullAttributesFile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 150 NTSTATUS NtQueryInformationAtom ['RTL_ATOM Atom', 'ATOM_INFORMATION_CLASS InformationClass', 'PVOID AtomInformation', 'ULONG AtomInformationLength', 'PULONG ReturnLength']
		case 150: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationAtom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationAtom_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 151 NTSTATUS NtQueryInformationFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID FileInformation', 'ULONG Length', 'FILE_INFORMATION_CLASS FileInformationClass']
		case 151: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 152 NTSTATUS NtQueryInformationJobObject ['HANDLE JobHandle', 'JOBOBJECTINFOCLASS JobObjectInformationClass', 'PVOID JobObjectInformation', 'ULONG JobObjectInformationLength', 'PULONG ReturnLength']
		case 152: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationJobObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationJobObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 153 NTSTATUS NtQueryInformationPort ['HANDLE PortHandle', 'PORT_INFORMATION_CLASS PortInformationClass', 'PVOID PortInformation', 'ULONG Length', 'PULONG ReturnLength']
		case 153: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationPort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationPort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 154 NTSTATUS NtQueryInformationProcess ['HANDLE ProcessHandle', 'PROCESSINFOCLASS ProcessInformationClass', 'PVOID ProcessInformation', 'ULONG ProcessInformationLength', 'PULONG ReturnLength']
		case 154: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationProcess_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationProcess_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 155 NTSTATUS NtQueryInformationThread ['HANDLE ThreadHandle', 'THREADINFOCLASS ThreadInformationClass', 'PVOID ThreadInformation', 'ULONG ThreadInformationLength', 'PULONG ReturnLength']
		case 155: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationThread_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 156 NTSTATUS NtQueryInformationToken ['HANDLE TokenHandle', 'TOKEN_INFORMATION_CLASS TokenInformationClass', 'PVOID TokenInformation', 'ULONG TokenInformationLength', 'PULONG ReturnLength']
		case 156: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationToken_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 157 NTSTATUS NtQueryInstallUILanguage ['LANGID *InstallUILanguageId']
		case 157: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtQueryInstallUILanguage_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInstallUILanguage_return, cpu, pc, arg0) ;
		}; break;
		// 158 NTSTATUS NtQueryIntervalProfile ['KPROFILE_SOURCE ProfileSource', 'PULONG Interval']
		case 158: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryIntervalProfile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryIntervalProfile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 159 NTSTATUS NtQueryIoCompletion ['HANDLE IoCompletionHandle', 'IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass', 'PVOID IoCompletionInformation', 'ULONG IoCompletionInformationLength', 'PULONG ReturnLength']
		case 159: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryIoCompletion_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryIoCompletion_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 160 NTSTATUS NtQueryKey ['HANDLE KeyHandle', 'KEY_INFORMATION_CLASS KeyInformationClass', 'PVOID KeyInformation', 'ULONG Length', 'PULONG ResultLength']
		case 160: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 161 NTSTATUS NtQueryMultipleValueKey ['HANDLE KeyHandle', 'PKEY_VALUE_ENTRY ValueEntries', 'ULONG EntryCount', 'PVOID ValueBuffer', 'PULONG BufferLength', 'PULONG RequiredBufferLength']
		case 161: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtQueryMultipleValueKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryMultipleValueKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 162 NTSTATUS NtQueryMutant ['HANDLE MutantHandle', 'MUTANT_INFORMATION_CLASS MutantInformationClass', 'PVOID MutantInformation', 'ULONG MutantInformationLength', 'PULONG ReturnLength']
		case 162: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryMutant_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryMutant_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 163 NTSTATUS NtQueryObject ['HANDLE Handle', 'OBJECT_INFORMATION_CLASS ObjectInformationClass', 'PVOID ObjectInformation', 'ULONG ObjectInformationLength', 'PULONG ReturnLength']
		case 163: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 164 NTSTATUS NtQueryOpenSubKeys ['POBJECT_ATTRIBUTES TargetKey', 'PULONG HandleCount']
		case 164: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryOpenSubKeys_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryOpenSubKeys_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 165 NTSTATUS NtQueryPerformanceCounter ['PLARGE_INTEGER PerformanceCounter', 'PLARGE_INTEGER PerformanceFrequency']
		case 165: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryPerformanceCounter_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryPerformanceCounter_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 166 NTSTATUS NtQueryQuotaInformationFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length', 'BOOLEAN ReturnSingleEntry', 'PVOID SidList', 'ULONG SidListLength', 'PULONG StartSid', 'BOOLEAN RestartScan']
		case 166: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtQueryQuotaInformationFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryQuotaInformationFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 167 NTSTATUS NtQuerySection ['HANDLE SectionHandle', 'SECTION_INFORMATION_CLASS SectionInformationClass', 'PVOID SectionInformation', 'SIZE_T SectionInformationLength', 'PSIZE_T ReturnLength']
		case 167: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQuerySection_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySection_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 168 NTSTATUS NtQuerySecurityObject ['HANDLE Handle', 'SECURITY_INFORMATION SecurityInformation', 'PSECURITY_DESCRIPTOR SecurityDescriptor', 'ULONG Length', 'PULONG LengthNeeded']
		case 168: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQuerySecurityObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySecurityObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 169 NTSTATUS NtQuerySemaphore ['HANDLE SemaphoreHandle', 'SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass', 'PVOID SemaphoreInformation', 'ULONG SemaphoreInformationLength', 'PULONG ReturnLength']
		case 169: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQuerySemaphore_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySemaphore_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 170 NTSTATUS NtQuerySymbolicLinkObject ['HANDLE LinkHandle', 'PUNICODE_STRING LinkTarget', 'PULONG ReturnedLength']
		case 170: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtQuerySymbolicLinkObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySymbolicLinkObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 171 NTSTATUS NtQuerySystemEnvironmentValue ['PUNICODE_STRING VariableName', 'PWSTR VariableValue', 'USHORT ValueLength', 'PUSHORT ReturnLength']
		case 171: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtQuerySystemEnvironmentValue_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySystemEnvironmentValue_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 172 NTSTATUS NtQuerySystemEnvironmentValueEx ['PUNICODE_STRING VariableName', 'LPGUID VendorGuid', 'PVOID Value', 'PULONG ValueLength', 'PULONG Attributes']
		case 172: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQuerySystemEnvironmentValueEx_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySystemEnvironmentValueEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 173 NTSTATUS NtQuerySystemInformation ['SYSTEM_INFORMATION_CLASS SystemInformationClass', 'PVOID SystemInformation', 'ULONG SystemInformationLength', 'PULONG ReturnLength']
		case 173: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtQuerySystemInformation_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySystemInformation_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 174 NTSTATUS NtQuerySystemTime ['PLARGE_INTEGER SystemTime']
		case 174: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtQuerySystemTime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySystemTime_return, cpu, pc, arg0) ;
		}; break;
		// 175 NTSTATUS NtQueryTimer ['HANDLE TimerHandle', 'TIMER_INFORMATION_CLASS TimerInformationClass', 'PVOID TimerInformation', 'ULONG TimerInformationLength', 'PULONG ReturnLength']
		case 175: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryTimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryTimer_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 176 NTSTATUS NtQueryTimerResolution ['PULONG MaximumTime', 'PULONG MinimumTime', 'PULONG CurrentTime']
		case 176: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtQueryTimerResolution_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryTimerResolution_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 177 NTSTATUS NtQueryValueKey ['HANDLE KeyHandle', 'PUNICODE_STRING ValueName', 'KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass', 'PVOID KeyValueInformation', 'ULONG Length', 'PULONG ResultLength']
		case 177: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtQueryValueKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryValueKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 178 NTSTATUS NtQueryVirtualMemory ['HANDLE ProcessHandle', 'PVOID BaseAddress', 'MEMORY_INFORMATION_CLASS MemoryInformationClass', 'PVOID MemoryInformation', 'SIZE_T MemoryInformationLength', 'PSIZE_T ReturnLength']
		case 178: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtQueryVirtualMemory_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 179 NTSTATUS NtQueryVolumeInformationFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID FsInformation', 'ULONG Length', 'FS_INFORMATION_CLASS FsInformationClass']
		case 179: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryVolumeInformationFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryVolumeInformationFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 180 NTSTATUS NtQueueApcThread ['HANDLE ThreadHandle', 'PPS_APC_ROUTINE ApcRoutine', 'PVOID ApcArgument1', 'PVOID ApcArgument2', 'PVOID ApcArgument3']
		case 180: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueueApcThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueueApcThread_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 181 NTSTATUS NtRaiseException ['PEXCEPTION_RECORD ExceptionRecord', 'PCONTEXT ContextRecord', 'BOOLEAN FirstChance']
		case 181: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtRaiseException_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRaiseException_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 182 NTSTATUS NtRaiseHardError ['NTSTATUS ErrorStatus', 'ULONG NumberOfParameters', 'ULONG UnicodeStringParameterMask', 'PULONG_PTR Parameters', 'ULONG ValidResponseOptions', 'PULONG Response']
		case 182: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtRaiseHardError_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRaiseHardError_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 183 NTSTATUS NtReadFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length', 'PLARGE_INTEGER ByteOffset', 'PULONG Key']
		case 183: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtReadFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReadFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 184 NTSTATUS NtReadFileScatter ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PFILE_SEGMENT_ELEMENT SegmentArray', 'ULONG Length', 'PLARGE_INTEGER ByteOffset', 'PULONG Key']
		case 184: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtReadFileScatter_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReadFileScatter_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 185 NTSTATUS NtReadRequestData ['HANDLE PortHandle', 'PPORT_MESSAGE Message', 'ULONG DataEntryIndex', 'PVOID Buffer', 'SIZE_T BufferSize', 'PSIZE_T NumberOfBytesRead']
		case 185: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtReadRequestData_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReadRequestData_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 186 NTSTATUS NtReadVirtualMemory ['HANDLE ProcessHandle', 'PVOID BaseAddress', 'PVOID Buffer', 'SIZE_T BufferSize', 'PSIZE_T NumberOfBytesRead']
		case 186: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtReadVirtualMemory_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReadVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 187 NTSTATUS NtRegisterThreadTerminatePort ['HANDLE PortHandle']
		case 187: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtRegisterThreadTerminatePort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRegisterThreadTerminatePort_return, cpu, pc, arg0) ;
		}; break;
		// 188 NTSTATUS NtReleaseMutant ['HANDLE MutantHandle', 'PLONG PreviousCount']
		case 188: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtReleaseMutant_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReleaseMutant_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 189 NTSTATUS NtReleaseSemaphore ['HANDLE SemaphoreHandle', 'LONG ReleaseCount', 'PLONG PreviousCount']
		case 189: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtReleaseSemaphore_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReleaseSemaphore_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 190 NTSTATUS NtRemoveIoCompletion ['HANDLE IoCompletionHandle', 'PVOID *KeyContext', 'PVOID *ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PLARGE_INTEGER Timeout']
		case 190: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtRemoveIoCompletion_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRemoveIoCompletion_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 191 NTSTATUS NtRemoveProcessDebug ['HANDLE ProcessHandle', 'HANDLE DebugObjectHandle']
		case 191: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRemoveProcessDebug_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRemoveProcessDebug_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 192 NTSTATUS NtRenameKey ['HANDLE KeyHandle', 'PUNICODE_STRING NewName']
		case 192: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRenameKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRenameKey_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 193 NTSTATUS NtReplaceKey ['POBJECT_ATTRIBUTES NewFile', 'HANDLE TargetHandle', 'POBJECT_ATTRIBUTES OldFile']
		case 193: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtReplaceKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplaceKey_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 194 NTSTATUS NtReplyPort ['HANDLE PortHandle', 'PPORT_MESSAGE ReplyMessage']
		case 194: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtReplyPort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplyPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 195 NTSTATUS NtReplyWaitReceivePort ['HANDLE PortHandle', 'PVOID *PortContext', 'PPORT_MESSAGE ReplyMessage', 'PPORT_MESSAGE ReceiveMessage']
		case 195: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtReplyWaitReceivePort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplyWaitReceivePort_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 196 NTSTATUS NtReplyWaitReceivePortEx ['HANDLE PortHandle', 'PVOID *PortContext', 'PPORT_MESSAGE ReplyMessage', 'PPORT_MESSAGE ReceiveMessage', 'PLARGE_INTEGER Timeout']
		case 196: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtReplyWaitReceivePortEx_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplyWaitReceivePortEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 197 NTSTATUS NtReplyWaitReplyPort ['HANDLE PortHandle', 'PPORT_MESSAGE ReplyMessage']
		case 197: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtReplyWaitReplyPort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplyWaitReplyPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 199 NTSTATUS NtRequestPort ['HANDLE PortHandle', 'PPORT_MESSAGE RequestMessage']
		case 199: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRequestPort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRequestPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 200 NTSTATUS NtRequestWaitReplyPort ['HANDLE PortHandle', 'PPORT_MESSAGE RequestMessage', 'PPORT_MESSAGE ReplyMessage']
		case 200: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtRequestWaitReplyPort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRequestWaitReplyPort_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 202 NTSTATUS NtResetEvent ['HANDLE EventHandle', 'PLONG PreviousState']
		case 202: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtResetEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtResetEvent_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 203 NTSTATUS NtResetWriteWatch ['HANDLE ProcessHandle', 'PVOID BaseAddress', 'SIZE_T RegionSize']
		case 203: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtResetWriteWatch_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtResetWriteWatch_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 204 NTSTATUS NtRestoreKey ['HANDLE KeyHandle', 'HANDLE FileHandle', 'ULONG Flags']
		case 204: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtRestoreKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRestoreKey_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 205 NTSTATUS NtResumeProcess ['HANDLE ProcessHandle']
		case 205: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtResumeProcess_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtResumeProcess_return, cpu, pc, arg0) ;
		}; break;
		// 206 NTSTATUS NtResumeThread ['HANDLE ThreadHandle', 'PULONG PreviousSuspendCount']
		case 206: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtResumeThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtResumeThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 207 NTSTATUS NtSaveKey ['HANDLE KeyHandle', 'HANDLE FileHandle']
		case 207: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSaveKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSaveKey_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 208 NTSTATUS NtSaveKeyEx ['HANDLE KeyHandle', 'HANDLE FileHandle', 'ULONG Format']
		case 208: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSaveKeyEx_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSaveKeyEx_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 209 NTSTATUS NtSaveMergedKeys ['HANDLE HighPrecedenceKeyHandle', 'HANDLE LowPrecedenceKeyHandle', 'HANDLE FileHandle']
		case 209: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSaveMergedKeys_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSaveMergedKeys_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 210 NTSTATUS NtSecureConnectPort ['PHANDLE PortHandle', 'PUNICODE_STRING PortName', 'PSECURITY_QUALITY_OF_SERVICE SecurityQos', 'PPORT_VIEW ClientView', 'PSID RequiredServerSid', 'PREMOTE_PORT_VIEW ServerView', 'PULONG MaxMessageLength', 'PVOID ConnectionInformation', 'PULONG ConnectionInformationLength']
		case 210: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtSecureConnectPort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSecureConnectPort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 211 NTSTATUS NtSetBootEntryOrder ['PULONG Ids', 'ULONG Count']
		case 211: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetBootEntryOrder_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetBootEntryOrder_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 212 NTSTATUS NtSetBootOptions ['PBOOT_OPTIONS BootOptions', 'ULONG FieldsToChange']
		case 212: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetBootOptions_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetBootOptions_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 213 NTSTATUS NtSetContextThread ['HANDLE ThreadHandle', 'PCONTEXT ThreadContext']
		case 213: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetContextThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetContextThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 214 NTSTATUS NtSetDebugFilterState ['ULONG ComponentId', 'ULONG Level', 'BOOLEAN State']
		case 214: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSetDebugFilterState_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetDebugFilterState_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 215 NTSTATUS NtSetDefaultHardErrorPort ['HANDLE DefaultHardErrorPort']
		case 215: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetDefaultHardErrorPort_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetDefaultHardErrorPort_return, cpu, pc, arg0) ;
		}; break;
		// 216 NTSTATUS NtSetDefaultLocale ['BOOLEAN UserProfile', 'LCID DefaultLocaleId']
		case 216: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetDefaultLocale_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetDefaultLocale_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 217 NTSTATUS NtSetDefaultUILanguage ['LANGID DefaultUILanguageId']
		case 217: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetDefaultUILanguage_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetDefaultUILanguage_return, cpu, pc, arg0) ;
		}; break;
		// 218 NTSTATUS NtSetEaFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length']
		case 218: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetEaFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetEaFile_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 219 NTSTATUS NtSetEvent ['HANDLE EventHandle', 'PLONG PreviousState']
		case 219: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetEvent_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 220 NTSTATUS NtSetEventBoostPriority ['HANDLE EventHandle']
		case 220: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetEventBoostPriority_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetEventBoostPriority_return, cpu, pc, arg0) ;
		}; break;
		// 221 NTSTATUS NtSetHighEventPair ['HANDLE EventPairHandle']
		case 221: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetHighEventPair_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetHighEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 222 NTSTATUS NtSetHighWaitLowEventPair ['HANDLE EventPairHandle']
		case 222: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetHighWaitLowEventPair_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetHighWaitLowEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 223 NTSTATUS NtSetInformationDebugObject ['HANDLE DebugObjectHandle', 'DEBUGOBJECTINFOCLASS DebugObjectInformationClass', 'PVOID DebugInformation', 'ULONG DebugInformationLength', 'PULONG ReturnLength']
		case 223: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtSetInformationDebugObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationDebugObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 224 NTSTATUS NtSetInformationFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID FileInformation', 'ULONG Length', 'FILE_INFORMATION_CLASS FileInformationClass']
		case 224: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtSetInformationFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 225 NTSTATUS NtSetInformationJobObject ['HANDLE JobHandle', 'JOBOBJECTINFOCLASS JobObjectInformationClass', 'PVOID JobObjectInformation', 'ULONG JobObjectInformationLength']
		case 225: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationJobObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationJobObject_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 226 NTSTATUS NtSetInformationKey ['HANDLE KeyHandle', 'KEY_SET_INFORMATION_CLASS KeySetInformationClass', 'PVOID KeySetInformation', 'ULONG KeySetInformationLength']
		case 226: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationKey_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 227 NTSTATUS NtSetInformationObject ['HANDLE Handle', 'OBJECT_INFORMATION_CLASS ObjectInformationClass', 'PVOID ObjectInformation', 'ULONG ObjectInformationLength']
		case 227: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationObject_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 228 NTSTATUS NtSetInformationProcess ['HANDLE ProcessHandle', 'PROCESSINFOCLASS ProcessInformationClass', 'PVOID ProcessInformation', 'ULONG ProcessInformationLength']
		case 228: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationProcess_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationProcess_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 229 NTSTATUS NtSetInformationThread ['HANDLE ThreadHandle', 'THREADINFOCLASS ThreadInformationClass', 'PVOID ThreadInformation', 'ULONG ThreadInformationLength']
		case 229: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationThread_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 230 NTSTATUS NtSetInformationToken ['HANDLE TokenHandle', 'TOKEN_INFORMATION_CLASS TokenInformationClass', 'PVOID TokenInformation', 'ULONG TokenInformationLength']
		case 230: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationToken_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationToken_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 231 NTSTATUS NtSetIntervalProfile ['ULONG Interval', 'KPROFILE_SOURCE Source']
		case 231: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetIntervalProfile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetIntervalProfile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 232 NTSTATUS NtSetIoCompletion ['HANDLE IoCompletionHandle', 'PVOID KeyContext', 'PVOID ApcContext', 'NTSTATUS IoStatus', 'ULONG_PTR IoStatusInformation']
		case 232: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtSetIoCompletion_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetIoCompletion_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 233 NTSTATUS NtSetLdtEntries ['ULONG Selector0', 'ULONG Entry0Low', 'ULONG Entry0Hi', 'ULONG Selector1', 'ULONG Entry1Low', 'ULONG Entry1Hi']
		case 233: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtSetLdtEntries_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetLdtEntries_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 234 NTSTATUS NtSetLowEventPair ['HANDLE EventPairHandle']
		case 234: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetLowEventPair_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetLowEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 235 NTSTATUS NtSetLowWaitHighEventPair ['HANDLE EventPairHandle']
		case 235: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetLowWaitHighEventPair_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetLowWaitHighEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 236 NTSTATUS NtSetQuotaInformationFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length']
		case 236: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetQuotaInformationFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetQuotaInformationFile_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 237 NTSTATUS NtSetSecurityObject ['HANDLE Handle', 'SECURITY_INFORMATION SecurityInformation', 'PSECURITY_DESCRIPTOR SecurityDescriptor']
		case 237: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSetSecurityObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSecurityObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 238 NTSTATUS NtSetSystemEnvironmentValue ['PUNICODE_STRING VariableName', 'PUNICODE_STRING VariableValue']
		case 238: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetSystemEnvironmentValue_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSystemEnvironmentValue_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 239 NTSTATUS NtSetSystemEnvironmentValueEx ['PUNICODE_STRING VariableName', 'LPGUID VendorGuid', 'PVOID Value', 'ULONG ValueLength', 'ULONG Attributes']
		case 239: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtSetSystemEnvironmentValueEx_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSystemEnvironmentValueEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 240 NTSTATUS NtSetSystemInformation ['SYSTEM_INFORMATION_CLASS SystemInformationClass', 'PVOID SystemInformation', 'ULONG SystemInformationLength']
		case 240: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSetSystemInformation_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSystemInformation_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 241 NTSTATUS NtSetSystemPowerState ['POWER_ACTION SystemAction', 'SYSTEM_POWER_STATE MinSystemState', 'ULONG Flags']
		case 241: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSetSystemPowerState_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSystemPowerState_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 242 NTSTATUS NtSetSystemTime ['PLARGE_INTEGER SystemTime', 'PLARGE_INTEGER PreviousTime']
		case 242: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetSystemTime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSystemTime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 243 NTSTATUS NtSetThreadExecutionState ['EXECUTION_STATE esFlags', 'PEXECUTION_STATE PreviousFlags']
		case 243: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetThreadExecutionState_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetThreadExecutionState_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 244 NTSTATUS NtSetTimer ['HANDLE TimerHandle', 'PLARGE_INTEGER DueTime', 'PTIMER_APC_ROUTINE TimerApcRoutine', 'PVOID TimerContext', 'BOOLEAN WakeTimer', 'LONG Period', 'PBOOLEAN PreviousState']
		case 244: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			int32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtSetTimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(int32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetTimer_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 245 NTSTATUS NtSetTimerResolution ['ULONG DesiredTime', 'BOOLEAN SetResolution', 'PULONG ActualTime']
		case 245: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSetTimerResolution_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetTimerResolution_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 246 NTSTATUS NtSetUuidSeed ['PCHAR Seed']
		case 246: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetUuidSeed_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetUuidSeed_return, cpu, pc, arg0) ;
		}; break;
		// 247 NTSTATUS NtSetValueKey ['HANDLE KeyHandle', 'PUNICODE_STRING ValueName', 'ULONG TitleIndex', 'ULONG Type', 'PVOID Data', 'ULONG DataSize']
		case 247: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtSetValueKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetValueKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 248 NTSTATUS NtSetVolumeInformationFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID FsInformation', 'ULONG Length', 'FS_INFORMATION_CLASS FsInformationClass']
		case 248: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtSetVolumeInformationFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetVolumeInformationFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 249 NTSTATUS NtShutdownSystem ['SHUTDOWN_ACTION Action']
		case 249: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtShutdownSystem_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtShutdownSystem_return, cpu, pc, arg0) ;
		}; break;
		// 250 NTSTATUS NtSignalAndWaitForSingleObject ['HANDLE SignalHandle', 'HANDLE WaitHandle', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout']
		case 250: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSignalAndWaitForSingleObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSignalAndWaitForSingleObject_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 251 NTSTATUS NtStartProfile ['HANDLE ProfileHandle']
		case 251: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtStartProfile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtStartProfile_return, cpu, pc, arg0) ;
		}; break;
		// 252 NTSTATUS NtStopProfile ['HANDLE ProfileHandle']
		case 252: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtStopProfile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtStopProfile_return, cpu, pc, arg0) ;
		}; break;
		// 253 NTSTATUS NtSuspendProcess ['HANDLE ProcessHandle']
		case 253: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSuspendProcess_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSuspendProcess_return, cpu, pc, arg0) ;
		}; break;
		// 254 NTSTATUS NtSuspendThread ['HANDLE ThreadHandle', 'PULONG PreviousSuspendCount']
		case 254: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSuspendThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSuspendThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 255 NTSTATUS NtSystemDebugControl ['SYSDBG_COMMAND Command', 'PVOID InputBuffer', 'ULONG InputBufferLength', 'PVOID OutputBuffer', 'ULONG OutputBufferLength', 'PULONG ReturnLength']
		case 255: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtSystemDebugControl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSystemDebugControl_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 256 NTSTATUS NtTerminateJobObject ['HANDLE JobHandle', 'NTSTATUS ExitStatus']
		case 256: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtTerminateJobObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTerminateJobObject_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 257 NTSTATUS NtTerminateProcess ['HANDLE ProcessHandle', 'NTSTATUS ExitStatus']
		case 257: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtTerminateProcess_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTerminateProcess_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 258 NTSTATUS NtTerminateThread ['HANDLE ThreadHandle', 'NTSTATUS ExitStatus']
		case 258: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtTerminateThread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTerminateThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 259 NTSTATUS NtTestAlert ['']
		case 259: {
			if (PPP_CHECK_CB(on_NtTestAlert_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_NtTestAlert_return, cpu, pc) ;
		}; break;
		// 260 NTSTATUS NtTraceEvent ['HANDLE TraceHandle', 'ULONG Flags', 'ULONG FieldSize', 'PVOID Fields']
		case 260: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtTraceEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTraceEvent_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 261 NTSTATUS NtTranslateFilePath ['PFILE_PATH InputFilePath', 'ULONG OutputType', 'PFILE_PATH OutputFilePath', 'PULONG OutputFilePathLength']
		case 261: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtTranslateFilePath_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTranslateFilePath_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 262 NTSTATUS NtUnloadDriver ['PUNICODE_STRING DriverServiceName']
		case 262: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtUnloadDriver_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnloadDriver_return, cpu, pc, arg0) ;
		}; break;
		// 263 NTSTATUS NtUnloadKey ['POBJECT_ATTRIBUTES TargetKey']
		case 263: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtUnloadKey_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnloadKey_return, cpu, pc, arg0) ;
		}; break;
		// 264 NTSTATUS NtUnloadKeyEx ['POBJECT_ATTRIBUTES TargetKey', 'HANDLE Event']
		case 264: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtUnloadKeyEx_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnloadKeyEx_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 265 NTSTATUS NtUnlockFile ['HANDLE FileHandle', 'PIO_STATUS_BLOCK IoStatusBlock', 'PLARGE_INTEGER ByteOffset', 'PLARGE_INTEGER Length', 'ULONG Key']
		case 265: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtUnlockFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnlockFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 266 NTSTATUS NtUnlockVirtualMemory ['HANDLE ProcessHandle', 'PVOID *BaseAddress', 'PSIZE_T RegionSize', 'ULONG MapType']
		case 266: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtUnlockVirtualMemory_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnlockVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 267 NTSTATUS NtUnmapViewOfSection ['HANDLE ProcessHandle', 'PVOID BaseAddress']
		case 267: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtUnmapViewOfSection_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnmapViewOfSection_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 268 NTSTATUS NtVdmControl ['VDMSERVICECLASS Service', 'PVOID ServiceData']
		case 268: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtVdmControl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtVdmControl_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 269 NTSTATUS NtWaitForDebugEvent ['HANDLE DebugObjectHandle', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout', 'PDBGUI_WAIT_STATE_CHANGE WaitStateChange']
		case 269: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtWaitForDebugEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitForDebugEvent_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 270 NTSTATUS NtWaitForMultipleObjects ['ULONG Count', 'HANDLE Handles[]', 'WAIT_TYPE WaitType', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout']
		case 270: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtWaitForMultipleObjects_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitForMultipleObjects_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 271 NTSTATUS NtWaitForSingleObject ['HANDLE Handle', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout']
		case 271: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtWaitForSingleObject_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitForSingleObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 272 NTSTATUS NtWaitHighEventPair ['HANDLE EventPairHandle']
		case 272: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtWaitHighEventPair_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitHighEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 273 NTSTATUS NtWaitLowEventPair ['HANDLE EventPairHandle']
		case 273: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtWaitLowEventPair_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitLowEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 274 NTSTATUS NtWriteFile ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PVOID Buffer', 'ULONG Length', 'PLARGE_INTEGER ByteOffset', 'PULONG Key']
		case 274: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtWriteFile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWriteFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 275 NTSTATUS NtWriteFileGather ['HANDLE FileHandle', 'HANDLE Event', 'PIO_APC_ROUTINE ApcRoutine', 'PVOID ApcContext', 'PIO_STATUS_BLOCK IoStatusBlock', 'PFILE_SEGMENT_ELEMENT SegmentArray', 'ULONG Length', 'PLARGE_INTEGER ByteOffset', 'PULONG Key']
		case 275: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtWriteFileGather_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint32_t));
				memcpy(&arg7, ctx->args[7], sizeof(uint32_t));
				memcpy(&arg8, ctx->args[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWriteFileGather_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 276 NTSTATUS NtWriteRequestData ['HANDLE PortHandle', 'PPORT_MESSAGE Message', 'ULONG DataEntryIndex', 'PVOID Buffer', 'SIZE_T BufferSize', 'PSIZE_T NumberOfBytesWritten']
		case 276: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtWriteRequestData_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWriteRequestData_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 277 NTSTATUS NtWriteVirtualMemory ['HANDLE ProcessHandle', 'PVOID BaseAddress', 'PVOID Buffer', 'SIZE_T BufferSize', 'PSIZE_T NumberOfBytesWritten']
		case 277: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtWriteVirtualMemory_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWriteVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 278 NTSTATUS NtYieldExecution ['']
		case 278: {
			if (PPP_CHECK_CB(on_NtYieldExecution_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_NtYieldExecution_return, cpu, pc) ;
		}; break;
		// 279 NTSTATUS NtCreateKeyedEvent ['PHANDLE KeyedEventHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes', 'ULONG Flags']
		case 279: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreateKeyedEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateKeyedEvent_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 280 NTSTATUS NtOpenKeyedEvent ['PHANDLE KeyedEventHandle', 'ACCESS_MASK DesiredAccess', 'POBJECT_ATTRIBUTES ObjectAttributes']
		case 280: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenKeyedEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenKeyedEvent_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 281 NTSTATUS NtReleaseKeyedEvent ['HANDLE KeyedEventHandle', 'PVOID KeyValue', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout']
		case 281: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtReleaseKeyedEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReleaseKeyedEvent_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 282 NTSTATUS NtWaitForKeyedEvent ['HANDLE KeyedEventHandle', 'PVOID KeyValue', 'BOOLEAN Alertable', 'PLARGE_INTEGER Timeout']
		case 282: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtWaitForKeyedEvent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitForKeyedEvent_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 283 NTSTATUS NtQueryPortInformationProcess ['']
		case 283: {
			if (PPP_CHECK_CB(on_NtQueryPortInformationProcess_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_NtQueryPortInformationProcess_return, cpu, pc) ;
		}; break;
		default:
			PPP_RUN_CB(on_unknown_sys_return, cpu, pc, ctx->no);
	}
	PPP_RUN_CB(on_all_sys_return, cpu, pc, ctx->no);
	PPP_RUN_CB(on_all_sys_return2, cpu, pc, call, ctx);
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */