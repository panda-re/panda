#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls_common.h"

extern "C" {
#include "gen_syscalls_ext_typedefs.h"
#include "gen_syscall_ppp_extern_return.h"
}

void syscall_return_switch_windows_2000_x86(CPUState *cpu, target_ulong pc, target_ulong ordinal, ReturnPoint &rp) {
#ifdef TARGET_I386
	switch(ordinal) {
		// 0 NTSTATUS NtAcceptConnectPort ['PHANDLE PortHandle', ' PVOID PortContext', ' PPORT_MESSAGE ConnectionRequest', ' BOOLEAN AcceptConnection', ' PPORT_VIEW ServerView', ' PREMOTE_PORT_VIEW ClientView']
		case 0: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtAcceptConnectPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAcceptConnectPort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 1 NTSTATUS NtAccessCheck ['PSECURITY_DESCRIPTOR SecurityDescriptor', ' HANDLE ClientToken', ' ACCESS_MASK DesiredAccess', ' PGENERIC_MAPPING GenericMapping', ' PPRIVILEGE_SET PrivilegeSet', ' PULONG PrivilegeSetLength', ' PACCESS_MASK GrantedAccess', ' PNTSTATUS AccessStatus']
		case 1: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtAccessCheck_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheck_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 2 NTSTATUS NtAccessCheckAndAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' PUNICODE_STRING ObjectTypeName', ' PUNICODE_STRING ObjectName', ' PSECURITY_DESCRIPTOR SecurityDescriptor', ' ACCESS_MASK DesiredAccess', ' PGENERIC_MAPPING GenericMapping', ' BOOLEAN ObjectCreation', ' PACCESS_MASK GrantedAccess', ' PNTSTATUS AccessStatus', ' PBOOLEAN GenerateOnClose']
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
			if (PPP_CHECK_CB(on_NtAccessCheckAndAuditAlarm_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
				memcpy(&arg10, rp.params[10], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheckAndAuditAlarm_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 3 NTSTATUS NtAccessCheckByType ['PSECURITY_DESCRIPTOR SecurityDescriptor', ' PSID PrincipalSelfSid', ' HANDLE ClientToken', ' ACCESS_MASK DesiredAccess', ' POBJECT_TYPE_LIST ObjectTypeList', ' ULONG ObjectTypeListLength', ' PGENERIC_MAPPING GenericMapping', ' PPRIVILEGE_SET PrivilegeSet', ' PULONG PrivilegeSetLength', ' PACCESS_MASK GrantedAccess', ' PNTSTATUS AccessStatus']
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
			if (PPP_CHECK_CB(on_NtAccessCheckByType_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
				memcpy(&arg10, rp.params[10], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheckByType_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 4 NTSTATUS NtAccessCheckByTypeAndAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' PUNICODE_STRING ObjectTypeName', ' PUNICODE_STRING ObjectName', ' PSECURITY_DESCRIPTOR SecurityDescriptor', ' PSID PrincipalSelfSid', ' ACCESS_MASK DesiredAccess', ' AUDIT_EVENT_TYPE AuditType', ' ULONG Flags', ' POBJECT_TYPE_LIST ObjectTypeList', ' ULONG ObjectTypeListLength', ' PGENERIC_MAPPING GenericMapping', ' BOOLEAN ObjectCreation', ' PACCESS_MASK GrantedAccess', ' PNTSTATUS AccessStatus', ' PBOOLEAN GenerateOnClose']
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
			if (PPP_CHECK_CB(on_NtAccessCheckByTypeAndAuditAlarm_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
				memcpy(&arg10, rp.params[10], sizeof(uint32_t));
				memcpy(&arg11, rp.params[11], sizeof(uint32_t));
				memcpy(&arg12, rp.params[12], sizeof(uint32_t));
				memcpy(&arg13, rp.params[13], sizeof(uint32_t));
				memcpy(&arg14, rp.params[14], sizeof(uint32_t));
				memcpy(&arg15, rp.params[15], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheckByTypeAndAuditAlarm_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15) ;
		}; break;
		// 5 NTSTATUS NtAccessCheckByTypeResultList ['PSECURITY_DESCRIPTOR SecurityDescriptor', ' PSID PrincipalSelfSid', ' HANDLE ClientToken', ' ACCESS_MASK DesiredAccess', ' POBJECT_TYPE_LIST ObjectTypeList', ' ULONG ObjectTypeListLength', ' PGENERIC_MAPPING GenericMapping', ' PPRIVILEGE_SET PrivilegeSet', ' PULONG PrivilegeSetLength', ' PACCESS_MASK GrantedAccess', ' PNTSTATUS AccessStatus']
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
			if (PPP_CHECK_CB(on_NtAccessCheckByTypeResultList_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
				memcpy(&arg10, rp.params[10], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheckByTypeResultList_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 6 NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' PUNICODE_STRING ObjectTypeName', ' PUNICODE_STRING ObjectName', ' PSECURITY_DESCRIPTOR SecurityDescriptor', ' PSID PrincipalSelfSid', ' ACCESS_MASK DesiredAccess', ' AUDIT_EVENT_TYPE AuditType', ' ULONG Flags', ' POBJECT_TYPE_LIST ObjectTypeList', ' ULONG ObjectTypeListLength', ' PGENERIC_MAPPING GenericMapping', ' BOOLEAN ObjectCreation', ' PACCESS_MASK GrantedAccess', ' PNTSTATUS AccessStatus', ' PBOOLEAN GenerateOnClose']
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
			if (PPP_CHECK_CB(on_NtAccessCheckByTypeResultListAndAuditAlarm_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
				memcpy(&arg10, rp.params[10], sizeof(uint32_t));
				memcpy(&arg11, rp.params[11], sizeof(uint32_t));
				memcpy(&arg12, rp.params[12], sizeof(uint32_t));
				memcpy(&arg13, rp.params[13], sizeof(uint32_t));
				memcpy(&arg14, rp.params[14], sizeof(uint32_t));
				memcpy(&arg15, rp.params[15], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheckByTypeResultListAndAuditAlarm_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15) ;
		}; break;
		// 7 NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarmByHandle ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' HANDLE ClientToken', ' PUNICODE_STRING ObjectTypeName', ' PUNICODE_STRING ObjectName', ' PSECURITY_DESCRIPTOR SecurityDescriptor', ' PSID PrincipalSelfSid', ' ACCESS_MASK DesiredAccess', ' AUDIT_EVENT_TYPE AuditType', ' ULONG Flags', ' POBJECT_TYPE_LIST ObjectTypeList', ' ULONG ObjectTypeListLength', ' PGENERIC_MAPPING GenericMapping', ' BOOLEAN ObjectCreation', ' PACCESS_MASK GrantedAccess', ' PNTSTATUS AccessStatus', ' PBOOLEAN GenerateOnClose']
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
			if (PPP_CHECK_CB(on_NtAccessCheckByTypeResultListAndAuditAlarmByHandle_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
				memcpy(&arg10, rp.params[10], sizeof(uint32_t));
				memcpy(&arg11, rp.params[11], sizeof(uint32_t));
				memcpy(&arg12, rp.params[12], sizeof(uint32_t));
				memcpy(&arg13, rp.params[13], sizeof(uint32_t));
				memcpy(&arg14, rp.params[14], sizeof(uint32_t));
				memcpy(&arg15, rp.params[15], sizeof(uint32_t));
				memcpy(&arg16, rp.params[16], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAccessCheckByTypeResultListAndAuditAlarmByHandle_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15, arg16) ;
		}; break;
		// 8 NTSTATUS NtAddAtom ['PWSTR AtomName', ' ULONG Length', ' PRTL_ATOM Atom']
		case 8: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAddAtom_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAddAtom_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 9 NTSTATUS NtAdjustGroupsToken ['HANDLE TokenHandle', ' BOOLEAN ResetToDefault', ' PTOKEN_GROUPS NewState', ' ULONG BufferLength', ' PTOKEN_GROUPS PreviousState', ' PULONG ReturnLength']
		case 9: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtAdjustGroupsToken_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAdjustGroupsToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 10 NTSTATUS NtAdjustPrivilegesToken ['HANDLE TokenHandle', ' BOOLEAN DisableAllPrivileges', ' PTOKEN_PRIVILEGES NewState', ' ULONG BufferLength', ' PTOKEN_PRIVILEGES PreviousState', ' PULONG ReturnLength']
		case 10: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtAdjustPrivilegesToken_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAdjustPrivilegesToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 11 NTSTATUS NtAlertResumeThread ['HANDLE ThreadHandle', ' PULONG PreviousSuspendCount']
		case 11: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAlertResumeThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlertResumeThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 12 NTSTATUS NtAlertThread ['HANDLE ThreadHandle']
		case 12: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtAlertThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlertThread_return, cpu, pc, arg0) ;
		}; break;
		// 13 NTSTATUS NtAllocateLocallyUniqueId ['PLUID Luid']
		case 13: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtAllocateLocallyUniqueId_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAllocateLocallyUniqueId_return, cpu, pc, arg0) ;
		}; break;
		// 14 NTSTATUS NtAllocateUserPhysicalPages ['HANDLE ProcessHandle', ' PULONG_PTR NumberOfPages', ' PULONG_PTR UserPfnArray']
		case 14: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAllocateUserPhysicalPages_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAllocateUserPhysicalPages_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 15 NTSTATUS NtAllocateUuids ['PULARGE_INTEGER Time', ' PULONG Range', ' PULONG Sequence', ' PCHAR Seed']
		case 15: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtAllocateUuids_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAllocateUuids_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 16 NTSTATUS NtAllocateVirtualMemory ['HANDLE ProcessHandle', ' PVOID *BaseAddress', ' ULONG_PTR ZeroBits', ' PSIZE_T RegionSize', ' ULONG AllocationType', ' ULONG Protect']
		case 16: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtAllocateVirtualMemory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAllocateVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 17 NTSTATUS NtAreMappedFilesTheSame ['PVOID File1MappedAsAnImage', ' PVOID File2MappedAsFile']
		case 17: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAreMappedFilesTheSame_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAreMappedFilesTheSame_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 18 NTSTATUS NtAssignProcessToJobObject ['HANDLE JobHandle', ' HANDLE ProcessHandle']
		case 18: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAssignProcessToJobObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAssignProcessToJobObject_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 19 NTSTATUS NtCallbackReturn ['PVOID OutputBuffer', ' ULONG OutputLength', ' NTSTATUS Status']
		case 19: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCallbackReturn_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCallbackReturn_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 20 NTSTATUS NtCancelIoFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock']
		case 20: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtCancelIoFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCancelIoFile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 21 NTSTATUS NtCancelTimer ['HANDLE TimerHandle', ' PBOOLEAN CurrentState']
		case 21: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtCancelTimer_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCancelTimer_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 23 NTSTATUS NtClearEvent ['HANDLE EventHandle']
		case 23: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtClearEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtClearEvent_return, cpu, pc, arg0) ;
		}; break;
		// 24 NTSTATUS NtClose ['HANDLE Handle']
		case 24: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtClose_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtClose_return, cpu, pc, arg0) ;
		}; break;
		// 25 NTSTATUS NtCloseObjectAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' BOOLEAN GenerateOnClose']
		case 25: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCloseObjectAuditAlarm_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCloseObjectAuditAlarm_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 26 NTSTATUS NtCompleteConnectPort ['HANDLE PortHandle']
		case 26: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtCompleteConnectPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCompleteConnectPort_return, cpu, pc, arg0) ;
		}; break;
		// 27 NTSTATUS NtConnectPort ['PHANDLE PortHandle', ' PUNICODE_STRING PortName', ' PSECURITY_QUALITY_OF_SERVICE SecurityQos', ' PPORT_VIEW ClientView', ' PREMOTE_PORT_VIEW ServerView', ' PULONG MaxMessageLength', ' PVOID ConnectionInformation', ' PULONG ConnectionInformationLength']
		case 27: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtConnectPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtConnectPort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 28 NTSTATUS NtContinue ['PCONTEXT ContextRecord', ' BOOLEAN TestAlert']
		case 28: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtContinue_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtContinue_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 29 NTSTATUS NtCreateDirectoryObject ['PHANDLE DirectoryHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 29: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCreateDirectoryObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateDirectoryObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 30 NTSTATUS NtCreateEvent ['PHANDLE EventHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' EVENT_TYPE EventType', ' BOOLEAN InitialState']
		case 30: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtCreateEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateEvent_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 31 NTSTATUS NtCreateEventPair ['PHANDLE EventPairHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 31: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCreateEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateEventPair_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 32 NTSTATUS NtCreateFile ['PHANDLE FileHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PIO_STATUS_BLOCK IoStatusBlock', ' PLARGE_INTEGER AllocationSize', ' ULONG FileAttributes', ' ULONG ShareAccess', ' ULONG CreateDisposition', ' ULONG CreateOptions', ' PVOID EaBuffer', ' ULONG EaLength']
		case 32: {
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
			if (PPP_CHECK_CB(on_NtCreateFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
				memcpy(&arg10, rp.params[10], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 33 NTSTATUS NtCreateIoCompletion ['PHANDLE IoCompletionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG Count']
		case 33: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreateIoCompletion_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateIoCompletion_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 34 NTSTATUS NtCreateJobObject ['PHANDLE JobHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 34: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCreateJobObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateJobObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 35 NTSTATUS NtCreateKey ['PHANDLE KeyHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG TitleIndex', ' PUNICODE_STRING Class', ' ULONG CreateOptions', ' PULONG Disposition']
		case 35: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtCreateKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 36 NTSTATUS NtCreateMailslotFile ['PHANDLE FileHandle', ' ULONG DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG CreateOptions', ' ULONG MailslotQuota', ' ULONG MaximumMessageSize', ' PLARGE_INTEGER ReadTimeout']
		case 36: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtCreateMailslotFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateMailslotFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 37 NTSTATUS NtCreateMutant ['PHANDLE MutantHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' BOOLEAN InitialOwner']
		case 37: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreateMutant_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateMutant_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 38 NTSTATUS NtCreateNamedPipeFile ['PHANDLE FileHandle', ' ULONG DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG ShareAccess', ' ULONG CreateDisposition', ' ULONG CreateOptions', ' ULONG NamedPipeType', ' ULONG ReadMode', ' ULONG CompletionMode', ' ULONG MaximumInstances', ' ULONG InboundQuota', ' ULONG OutboundQuota', ' PLARGE_INTEGER DefaultTimeout']
		case 38: {
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
			if (PPP_CHECK_CB(on_NtCreateNamedPipeFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
				memcpy(&arg10, rp.params[10], sizeof(uint32_t));
				memcpy(&arg11, rp.params[11], sizeof(uint32_t));
				memcpy(&arg12, rp.params[12], sizeof(uint32_t));
				memcpy(&arg13, rp.params[13], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateNamedPipeFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13) ;
		}; break;
		// 39 NTSTATUS NtCreatePagingFile ['PUNICODE_STRING PageFileName', ' PLARGE_INTEGER MinimumSize', ' PLARGE_INTEGER MaximumSize', ' ULONG Priority']
		case 39: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreatePagingFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreatePagingFile_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 40 NTSTATUS NtCreatePort ['PHANDLE PortHandle', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG MaxConnectionInfoLength', ' ULONG MaxMessageLength', ' ULONG MaxPoolUsage']
		case 40: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtCreatePort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreatePort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 41 NTSTATUS NtCreateProcess ['PHANDLE ProcessHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE ParentProcess', ' BOOLEAN InheritObjectTable', ' HANDLE SectionHandle', ' HANDLE DebugPort', ' HANDLE ExceptionPort']
		case 41: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtCreateProcess_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateProcess_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 42 NTSTATUS NtCreateProfile ['PHANDLE ProfileHandle', ' HANDLE Process', ' PVOID RangeBase', ' SIZE_T RangeSize', ' ULONG BucketSize', ' PULONG Buffer', ' ULONG BufferSize', ' KPROFILE_SOURCE ProfileSource', ' KAFFINITY Affinity']
		case 42: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtCreateProfile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateProfile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 43 NTSTATUS NtCreateSection ['PHANDLE SectionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PLARGE_INTEGER MaximumSize', ' ULONG SectionPageProtection', ' ULONG AllocationAttributes', ' HANDLE FileHandle']
		case 43: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtCreateSection_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateSection_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 44 NTSTATUS NtCreateSemaphore ['PHANDLE SemaphoreHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' LONG InitialCount', ' LONG MaximumCount']
		case 44: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			int32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_NtCreateSemaphore_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(int32_t));
				memcpy(&arg4, rp.params[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_NtCreateSemaphore_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 45 NTSTATUS NtCreateSymbolicLinkObject ['PHANDLE LinkHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PUNICODE_STRING LinkTarget']
		case 45: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreateSymbolicLinkObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateSymbolicLinkObject_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 46 NTSTATUS NtCreateThread ['PHANDLE ThreadHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE ProcessHandle', ' PCLIENT_ID ClientId', ' PCONTEXT ThreadContext', ' PINITIAL_TEB InitialTeb', ' BOOLEAN CreateSuspended']
		case 46: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtCreateThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateThread_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 47 NTSTATUS NtCreateTimer ['PHANDLE TimerHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' TIMER_TYPE TimerType']
		case 47: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreateTimer_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateTimer_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 48 NTSTATUS NtCreateToken ['PHANDLE TokenHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' TOKEN_TYPE TokenType', ' PLUID AuthenticationId', ' PLARGE_INTEGER ExpirationTime', ' PTOKEN_USER User', ' PTOKEN_GROUPS Groups', ' PTOKEN_PRIVILEGES Privileges', ' PTOKEN_OWNER Owner', ' PTOKEN_PRIMARY_GROUP PrimaryGroup', ' PTOKEN_DEFAULT_DACL DefaultDacl', ' PTOKEN_SOURCE TokenSource']
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
			uint32_t arg9;
			uint32_t arg10;
			uint32_t arg11;
			uint32_t arg12;
			if (PPP_CHECK_CB(on_NtCreateToken_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
				memcpy(&arg10, rp.params[10], sizeof(uint32_t));
				memcpy(&arg11, rp.params[11], sizeof(uint32_t));
				memcpy(&arg12, rp.params[12], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12) ;
		}; break;
		// 49 NTSTATUS NtCreateWaitablePort ['PHANDLE PortHandle', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG MaxConnectionInfoLength', ' ULONG MaxMessageLength', ' ULONG MaxPoolUsage']
		case 49: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtCreateWaitablePort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateWaitablePort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 50 NTSTATUS NtDelayExecution ['BOOLEAN Alertable', ' PLARGE_INTEGER DelayInterval']
		case 50: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtDelayExecution_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDelayExecution_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 51 NTSTATUS NtDeleteAtom ['RTL_ATOM Atom']
		case 51: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeleteAtom_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteAtom_return, cpu, pc, arg0) ;
		}; break;
		// 52 NTSTATUS NtDeleteFile ['POBJECT_ATTRIBUTES ObjectAttributes']
		case 52: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeleteFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteFile_return, cpu, pc, arg0) ;
		}; break;
		// 53 NTSTATUS NtDeleteKey ['HANDLE KeyHandle']
		case 53: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeleteKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteKey_return, cpu, pc, arg0) ;
		}; break;
		// 54 NTSTATUS NtDeleteObjectAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' BOOLEAN GenerateOnClose']
		case 54: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtDeleteObjectAuditAlarm_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteObjectAuditAlarm_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 55 NTSTATUS NtDeleteValueKey ['HANDLE KeyHandle', ' PUNICODE_STRING ValueName']
		case 55: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtDeleteValueKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteValueKey_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 56 NTSTATUS NtDeviceIoControlFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG IoControlCode', ' PVOID InputBuffer', ' ULONG InputBufferLength', ' PVOID OutputBuffer', ' ULONG OutputBufferLength']
		case 56: {
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
			if (PPP_CHECK_CB(on_NtDeviceIoControlFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeviceIoControlFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 57 NTSTATUS NtDisplayString ['PUNICODE_STRING String']
		case 57: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDisplayString_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDisplayString_return, cpu, pc, arg0) ;
		}; break;
		// 58 NTSTATUS NtDuplicateObject ['HANDLE SourceProcessHandle', ' HANDLE SourceHandle', ' HANDLE TargetProcessHandle', ' PHANDLE TargetHandle', ' ACCESS_MASK DesiredAccess', ' ULONG HandleAttributes', ' ULONG Options']
		case 58: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtDuplicateObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDuplicateObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 59 NTSTATUS NtDuplicateToken ['HANDLE ExistingTokenHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' BOOLEAN EffectiveOnly', ' TOKEN_TYPE TokenType', ' PHANDLE NewTokenHandle']
		case 59: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtDuplicateToken_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDuplicateToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 60 NTSTATUS NtEnumerateKey ['HANDLE KeyHandle', ' ULONG Index', ' KEY_INFORMATION_CLASS KeyInformationClass', ' PVOID KeyInformation', ' ULONG Length', ' PULONG ResultLength']
		case 60: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtEnumerateKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtEnumerateKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 61 NTSTATUS NtEnumerateValueKey ['HANDLE KeyHandle', ' ULONG Index', ' KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass', ' PVOID KeyValueInformation', ' ULONG Length', ' PULONG ResultLength']
		case 61: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtEnumerateValueKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtEnumerateValueKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 62 NTSTATUS NtExtendSection ['HANDLE SectionHandle', ' PLARGE_INTEGER NewSectionSize']
		case 62: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtExtendSection_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtExtendSection_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 63 NTSTATUS NtFilterToken ['HANDLE ExistingTokenHandle', ' ULONG Flags', ' PTOKEN_GROUPS SidsToDisable', ' PTOKEN_PRIVILEGES PrivilegesToDelete', ' PTOKEN_GROUPS RestrictedSids', ' PHANDLE NewTokenHandle']
		case 63: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtFilterToken_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFilterToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 64 NTSTATUS NtFindAtom ['PWSTR AtomName', ' ULONG Length', ' PRTL_ATOM Atom']
		case 64: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtFindAtom_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFindAtom_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 65 NTSTATUS NtFlushBuffersFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock']
		case 65: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtFlushBuffersFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFlushBuffersFile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 66 NTSTATUS NtFlushInstructionCache ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' SIZE_T Length']
		case 66: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtFlushInstructionCache_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFlushInstructionCache_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 67 NTSTATUS NtFlushKey ['HANDLE KeyHandle']
		case 67: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtFlushKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFlushKey_return, cpu, pc, arg0) ;
		}; break;
		// 68 NTSTATUS NtFlushVirtualMemory ['HANDLE ProcessHandle', ' PVOID *BaseAddress', ' PSIZE_T RegionSize', ' PIO_STATUS_BLOCK IoStatus']
		case 68: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtFlushVirtualMemory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFlushVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 69 NTSTATUS NtFlushWriteBuffer ['']
		case 69: {
			if (PPP_CHECK_CB(on_NtFlushWriteBuffer_return)) {
			}
			PPP_RUN_CB(on_NtFlushWriteBuffer_return, cpu, pc) ;
		}; break;
		// 70 NTSTATUS NtFreeUserPhysicalPages ['HANDLE ProcessHandle', ' PULONG_PTR NumberOfPages', ' PULONG_PTR UserPfnArray']
		case 70: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtFreeUserPhysicalPages_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFreeUserPhysicalPages_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 71 NTSTATUS NtFreeVirtualMemory ['HANDLE ProcessHandle', ' PVOID *BaseAddress', ' PSIZE_T RegionSize', ' ULONG FreeType']
		case 71: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtFreeVirtualMemory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFreeVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 72 NTSTATUS NtFsControlFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG IoControlCode', ' PVOID InputBuffer', ' ULONG InputBufferLength', ' PVOID OutputBuffer', ' ULONG OutputBufferLength']
		case 72: {
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
			if (PPP_CHECK_CB(on_NtFsControlFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFsControlFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 73 NTSTATUS NtGetContextThread ['HANDLE ThreadHandle', ' PCONTEXT ThreadContext']
		case 73: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtGetContextThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetContextThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 74 NTSTATUS NtGetDevicePowerState ['HANDLE Device', ' DEVICE_POWER_STATE *State']
		case 74: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtGetDevicePowerState_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetDevicePowerState_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 75 NTSTATUS NtGetPlugPlayEvent ['HANDLE EventHandle', ' PVOID Context', ' PPLUGPLAY_EVENT_BLOCK EventBlock', ' ULONG EventBufferSize']
		case 75: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtGetPlugPlayEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetPlugPlayEvent_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 77 NTSTATUS NtGetWriteWatch ['HANDLE ProcessHandle', ' ULONG Flags', ' PVOID BaseAddress', ' SIZE_T RegionSize', ' PVOID *UserAddressArray', ' PULONG_PTR EntriesInUserAddressArray', ' PULONG Granularity']
		case 77: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtGetWriteWatch_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetWriteWatch_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 78 NTSTATUS NtImpersonateAnonymousToken ['HANDLE ThreadHandle']
		case 78: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtImpersonateAnonymousToken_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtImpersonateAnonymousToken_return, cpu, pc, arg0) ;
		}; break;
		// 79 NTSTATUS NtImpersonateClientOfPort ['HANDLE PortHandle', ' PPORT_MESSAGE Message']
		case 79: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtImpersonateClientOfPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtImpersonateClientOfPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 80 NTSTATUS NtImpersonateThread ['HANDLE ServerThreadHandle', ' HANDLE ClientThreadHandle', ' PSECURITY_QUALITY_OF_SERVICE SecurityQos']
		case 80: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtImpersonateThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtImpersonateThread_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 81 NTSTATUS NtInitializeRegistry ['USHORT BootCondition']
		case 81: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtInitializeRegistry_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtInitializeRegistry_return, cpu, pc, arg0) ;
		}; break;
		// 82 NTSTATUS NtInitiatePowerAction ['POWER_ACTION SystemAction', ' SYSTEM_POWER_STATE MinSystemState', ' ULONG Flags', ' BOOLEAN Asynchronous']
		case 82: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtInitiatePowerAction_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtInitiatePowerAction_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 83 BOOLEAN NtIsSystemResumeAutomatic ['']
		case 83: {
			if (PPP_CHECK_CB(on_NtIsSystemResumeAutomatic_return)) {
			}
			PPP_RUN_CB(on_NtIsSystemResumeAutomatic_return, cpu, pc) ;
		}; break;
		// 84 NTSTATUS NtListenPort ['HANDLE PortHandle', ' PPORT_MESSAGE ConnectionRequest']
		case 84: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtListenPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtListenPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 85 NTSTATUS NtLoadDriver ['PUNICODE_STRING DriverServiceName']
		case 85: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtLoadDriver_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLoadDriver_return, cpu, pc, arg0) ;
		}; break;
		// 86 NTSTATUS NtLoadKey ['POBJECT_ATTRIBUTES TargetKey', ' POBJECT_ATTRIBUTES SourceFile']
		case 86: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtLoadKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLoadKey_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 87 NTSTATUS NtLoadKey2 ['POBJECT_ATTRIBUTES TargetKey', ' POBJECT_ATTRIBUTES SourceFile', ' ULONG Flags']
		case 87: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtLoadKey2_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLoadKey2_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 88 NTSTATUS NtLockFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PLARGE_INTEGER ByteOffset', ' PLARGE_INTEGER Length', ' ULONG Key', ' BOOLEAN FailImmediately', ' BOOLEAN ExclusiveLock']
		case 88: {
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
			if (PPP_CHECK_CB(on_NtLockFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLockFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 89 NTSTATUS NtLockVirtualMemory ['HANDLE ProcessHandle', ' PVOID *BaseAddress', ' PSIZE_T RegionSize', ' ULONG MapType']
		case 89: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtLockVirtualMemory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLockVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 90 NTSTATUS NtMakeTemporaryObject ['HANDLE Handle']
		case 90: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtMakeTemporaryObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtMakeTemporaryObject_return, cpu, pc, arg0) ;
		}; break;
		// 91 NTSTATUS NtMapUserPhysicalPages ['PVOID VirtualAddress', ' ULONG_PTR NumberOfPages', ' PULONG_PTR UserPfnArray']
		case 91: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtMapUserPhysicalPages_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtMapUserPhysicalPages_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 92 NTSTATUS NtMapUserPhysicalPagesScatter ['PVOID *VirtualAddresses', ' ULONG_PTR NumberOfPages', ' PULONG_PTR UserPfnArray']
		case 92: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtMapUserPhysicalPagesScatter_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtMapUserPhysicalPagesScatter_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 93 NTSTATUS NtMapViewOfSection ['HANDLE SectionHandle', ' HANDLE ProcessHandle', ' PVOID *BaseAddress', ' ULONG_PTR ZeroBits', ' SIZE_T CommitSize', ' PLARGE_INTEGER SectionOffset', ' PSIZE_T ViewSize', ' SECTION_INHERIT InheritDisposition', ' ULONG AllocationType', ' WIN32_PROTECTION_MASK Win32Protect']
		case 93: {
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
			if (PPP_CHECK_CB(on_NtMapViewOfSection_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtMapViewOfSection_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 94 NTSTATUS NtNotifyChangeDirectoryFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' ULONG CompletionFilter', ' BOOLEAN WatchTree']
		case 94: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtNotifyChangeDirectoryFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtNotifyChangeDirectoryFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 95 NTSTATUS NtNotifyChangeKey ['HANDLE KeyHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG CompletionFilter', ' BOOLEAN WatchTree', ' PVOID Buffer', ' ULONG BufferSize', ' BOOLEAN Asynchronous']
		case 95: {
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
			if (PPP_CHECK_CB(on_NtNotifyChangeKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtNotifyChangeKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 96 NTSTATUS NtNotifyChangeMultipleKeys ['HANDLE MasterKeyHandle', ' ULONG Count', ' OBJECT_ATTRIBUTES SlaveObjects[]', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG CompletionFilter', ' BOOLEAN WatchTree', ' PVOID Buffer', ' ULONG BufferSize', ' BOOLEAN Asynchronous']
		case 96: {
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
			if (PPP_CHECK_CB(on_NtNotifyChangeMultipleKeys_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
				memcpy(&arg10, rp.params[10], sizeof(uint32_t));
				memcpy(&arg11, rp.params[11], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtNotifyChangeMultipleKeys_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11) ;
		}; break;
		// 97 NTSTATUS NtOpenDirectoryObject ['PHANDLE DirectoryHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 97: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenDirectoryObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenDirectoryObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 98 NTSTATUS NtOpenEvent ['PHANDLE EventHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 98: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenEvent_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 99 NTSTATUS NtOpenEventPair ['PHANDLE EventPairHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 99: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenEventPair_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 100 NTSTATUS NtOpenFile ['PHANDLE FileHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG ShareAccess', ' ULONG OpenOptions']
		case 100: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtOpenFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 101 NTSTATUS NtOpenIoCompletion ['PHANDLE IoCompletionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 101: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenIoCompletion_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenIoCompletion_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 102 NTSTATUS NtOpenJobObject ['PHANDLE JobHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 102: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenJobObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenJobObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 103 NTSTATUS NtOpenKey ['PHANDLE KeyHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 103: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenKey_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 104 NTSTATUS NtOpenMutant ['PHANDLE MutantHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 104: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenMutant_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenMutant_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 105 NTSTATUS NtOpenObjectAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' PUNICODE_STRING ObjectTypeName', ' PUNICODE_STRING ObjectName', ' PSECURITY_DESCRIPTOR SecurityDescriptor', ' HANDLE ClientToken', ' ACCESS_MASK DesiredAccess', ' ACCESS_MASK GrantedAccess', ' PPRIVILEGE_SET Privileges', ' BOOLEAN ObjectCreation', ' BOOLEAN AccessGranted', ' PBOOLEAN GenerateOnClose']
		case 105: {
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
			if (PPP_CHECK_CB(on_NtOpenObjectAuditAlarm_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
				memcpy(&arg10, rp.params[10], sizeof(uint32_t));
				memcpy(&arg11, rp.params[11], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenObjectAuditAlarm_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11) ;
		}; break;
		// 106 NTSTATUS NtOpenProcess ['PHANDLE ProcessHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PCLIENT_ID ClientId']
		case 106: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtOpenProcess_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenProcess_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 107 NTSTATUS NtOpenProcessToken ['HANDLE ProcessHandle', ' ACCESS_MASK DesiredAccess', ' PHANDLE TokenHandle']
		case 107: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenProcessToken_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenProcessToken_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 108 NTSTATUS NtOpenSection ['PHANDLE SectionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 108: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenSection_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenSection_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 109 NTSTATUS NtOpenSemaphore ['PHANDLE SemaphoreHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 109: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenSemaphore_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenSemaphore_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 110 NTSTATUS NtOpenSymbolicLinkObject ['PHANDLE LinkHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 110: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenSymbolicLinkObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenSymbolicLinkObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 111 NTSTATUS NtOpenThread ['PHANDLE ThreadHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PCLIENT_ID ClientId']
		case 111: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtOpenThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenThread_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 112 NTSTATUS NtOpenThreadToken ['HANDLE ThreadHandle', ' ACCESS_MASK DesiredAccess', ' BOOLEAN OpenAsSelf', ' PHANDLE TokenHandle']
		case 112: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtOpenThreadToken_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenThreadToken_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 113 NTSTATUS NtOpenTimer ['PHANDLE TimerHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 113: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenTimer_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenTimer_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 114 NTSTATUS NtPlugPlayControl ['PLUGPLAY_CONTROL_CLASS PnPControlClass', ' PVOID PnPControlData', ' ULONG PnPControlDataLength']
		case 114: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtPlugPlayControl_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPlugPlayControl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 115 NTSTATUS NtPowerInformation ['POWER_INFORMATION_LEVEL InformationLevel', ' PVOID InputBuffer', ' ULONG InputBufferLength', ' PVOID OutputBuffer', ' ULONG OutputBufferLength']
		case 115: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtPowerInformation_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPowerInformation_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 116 NTSTATUS NtPrivilegeCheck ['HANDLE ClientToken', ' PPRIVILEGE_SET RequiredPrivileges', ' PBOOLEAN Result']
		case 116: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtPrivilegeCheck_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPrivilegeCheck_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 117 NTSTATUS NtPrivilegedServiceAuditAlarm ['PUNICODE_STRING SubsystemName', ' PUNICODE_STRING ServiceName', ' HANDLE ClientToken', ' PPRIVILEGE_SET Privileges', ' BOOLEAN AccessGranted']
		case 117: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtPrivilegedServiceAuditAlarm_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPrivilegedServiceAuditAlarm_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 118 NTSTATUS NtPrivilegeObjectAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' HANDLE ClientToken', ' ACCESS_MASK DesiredAccess', ' PPRIVILEGE_SET Privileges', ' BOOLEAN AccessGranted']
		case 118: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtPrivilegeObjectAuditAlarm_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPrivilegeObjectAuditAlarm_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 119 NTSTATUS NtProtectVirtualMemory ['HANDLE ProcessHandle', ' PVOID *BaseAddress', ' PSIZE_T RegionSize', ' WIN32_PROTECTION_MASK NewProtectWin32', ' PULONG OldProtect']
		case 119: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtProtectVirtualMemory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtProtectVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 120 NTSTATUS NtPulseEvent ['HANDLE EventHandle', ' PLONG PreviousState']
		case 120: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtPulseEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPulseEvent_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 121 NTSTATUS NtQueryInformationAtom ['RTL_ATOM Atom', ' ATOM_INFORMATION_CLASS InformationClass', ' PVOID AtomInformation', ' ULONG AtomInformationLength', ' PULONG ReturnLength']
		case 121: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationAtom_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationAtom_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 122 NTSTATUS NtQueryAttributesFile ['POBJECT_ATTRIBUTES ObjectAttributes', ' PFILE_BASIC_INFORMATION FileInformation']
		case 122: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryAttributesFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryAttributesFile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 123 NTSTATUS NtQueryDefaultLocale ['BOOLEAN UserProfile', ' PLCID DefaultLocaleId']
		case 123: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryDefaultLocale_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDefaultLocale_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 124 NTSTATUS NtQueryDefaultUILanguage ['LANGID *DefaultUILanguageId']
		case 124: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtQueryDefaultUILanguage_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDefaultUILanguage_return, cpu, pc, arg0) ;
		}; break;
		// 125 NTSTATUS NtQueryDirectoryFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FileInformation', ' ULONG Length', ' FILE_INFORMATION_CLASS FileInformationClass', ' BOOLEAN ReturnSingleEntry', ' PUNICODE_STRING FileName', ' BOOLEAN RestartScan']
		case 125: {
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
			if (PPP_CHECK_CB(on_NtQueryDirectoryFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
				memcpy(&arg9, rp.params[9], sizeof(uint32_t));
				memcpy(&arg10, rp.params[10], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDirectoryFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 126 NTSTATUS NtQueryDirectoryObject ['HANDLE DirectoryHandle', ' PVOID Buffer', ' ULONG Length', ' BOOLEAN ReturnSingleEntry', ' BOOLEAN RestartScan', ' PULONG Context', ' PULONG ReturnLength']
		case 126: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtQueryDirectoryObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDirectoryObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 127 NTSTATUS NtQueryEaFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' BOOLEAN ReturnSingleEntry', ' PVOID EaList', ' ULONG EaListLength', ' PULONG EaIndex', ' BOOLEAN RestartScan']
		case 127: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtQueryEaFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryEaFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 128 NTSTATUS NtQueryEvent ['HANDLE EventHandle', ' EVENT_INFORMATION_CLASS EventInformationClass', ' PVOID EventInformation', ' ULONG EventInformationLength', ' PULONG ReturnLength']
		case 128: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryEvent_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 129 NTSTATUS NtQueryFullAttributesFile ['POBJECT_ATTRIBUTES ObjectAttributes', ' PFILE_NETWORK_OPEN_INFORMATION FileInformation']
		case 129: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryFullAttributesFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryFullAttributesFile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 130 NTSTATUS NtQueryInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FileInformation', ' ULONG Length', ' FILE_INFORMATION_CLASS FileInformationClass']
		case 130: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 131 NTSTATUS NtQueryInformationJobObject ['HANDLE JobHandle', ' JOBOBJECTINFOCLASS JobObjectInformationClass', ' PVOID JobObjectInformation', ' ULONG JobObjectInformationLength', ' PULONG ReturnLength']
		case 131: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationJobObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationJobObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 132 NTSTATUS NtQueryIoCompletion ['HANDLE IoCompletionHandle', ' IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass', ' PVOID IoCompletionInformation', ' ULONG IoCompletionInformationLength', ' PULONG ReturnLength']
		case 132: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryIoCompletion_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryIoCompletion_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 133 NTSTATUS NtQueryInformationPort ['HANDLE PortHandle', ' PORT_INFORMATION_CLASS PortInformationClass', ' PVOID PortInformation', ' ULONG Length', ' PULONG ReturnLength']
		case 133: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationPort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 134 NTSTATUS NtQueryInformationProcess ['HANDLE ProcessHandle', ' PROCESSINFOCLASS ProcessInformationClass', ' PVOID ProcessInformation', ' ULONG ProcessInformationLength', ' PULONG ReturnLength']
		case 134: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationProcess_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationProcess_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 135 NTSTATUS NtQueryInformationThread ['HANDLE ThreadHandle', ' THREADINFOCLASS ThreadInformationClass', ' PVOID ThreadInformation', ' ULONG ThreadInformationLength', ' PULONG ReturnLength']
		case 135: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationThread_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 136 NTSTATUS NtQueryInformationToken ['HANDLE TokenHandle', ' TOKEN_INFORMATION_CLASS TokenInformationClass', ' PVOID TokenInformation', ' ULONG TokenInformationLength', ' PULONG ReturnLength']
		case 136: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationToken_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 137 NTSTATUS NtQueryInstallUILanguage ['LANGID *InstallUILanguageId']
		case 137: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtQueryInstallUILanguage_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInstallUILanguage_return, cpu, pc, arg0) ;
		}; break;
		// 138 NTSTATUS NtQueryIntervalProfile ['KPROFILE_SOURCE ProfileSource', ' PULONG Interval']
		case 138: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryIntervalProfile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryIntervalProfile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 139 NTSTATUS NtQueryKey ['HANDLE KeyHandle', ' KEY_INFORMATION_CLASS KeyInformationClass', ' PVOID KeyInformation', ' ULONG Length', ' PULONG ResultLength']
		case 139: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 140 NTSTATUS NtQueryMultipleValueKey ['HANDLE KeyHandle', ' PKEY_VALUE_ENTRY ValueEntries', ' ULONG EntryCount', ' PVOID ValueBuffer', ' PULONG BufferLength', ' PULONG RequiredBufferLength']
		case 140: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtQueryMultipleValueKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryMultipleValueKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 141 NTSTATUS NtQueryMutant ['HANDLE MutantHandle', ' MUTANT_INFORMATION_CLASS MutantInformationClass', ' PVOID MutantInformation', ' ULONG MutantInformationLength', ' PULONG ReturnLength']
		case 141: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryMutant_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryMutant_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 142 NTSTATUS NtQueryObject ['HANDLE Handle', ' OBJECT_INFORMATION_CLASS ObjectInformationClass', ' PVOID ObjectInformation', ' ULONG ObjectInformationLength', ' PULONG ReturnLength']
		case 142: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 143 NTSTATUS NtQueryOpenSubKeys ['POBJECT_ATTRIBUTES TargetKey', ' PULONG HandleCount']
		case 143: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryOpenSubKeys_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryOpenSubKeys_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 144 NTSTATUS NtQueryPerformanceCounter ['PLARGE_INTEGER PerformanceCounter', ' PLARGE_INTEGER PerformanceFrequency']
		case 144: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryPerformanceCounter_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryPerformanceCounter_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 145 NTSTATUS NtQueryQuotaInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' BOOLEAN ReturnSingleEntry', ' PVOID SidList', ' ULONG SidListLength', ' PULONG StartSid', ' BOOLEAN RestartScan']
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
			if (PPP_CHECK_CB(on_NtQueryQuotaInformationFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryQuotaInformationFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 146 NTSTATUS NtQuerySection ['HANDLE SectionHandle', ' SECTION_INFORMATION_CLASS SectionInformationClass', ' PVOID SectionInformation', ' SIZE_T SectionInformationLength', ' PSIZE_T ReturnLength']
		case 146: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQuerySection_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySection_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 147 NTSTATUS NtQuerySecurityObject ['HANDLE Handle', ' SECURITY_INFORMATION SecurityInformation', ' PSECURITY_DESCRIPTOR SecurityDescriptor', ' ULONG Length', ' PULONG LengthNeeded']
		case 147: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQuerySecurityObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySecurityObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 148 NTSTATUS NtQuerySemaphore ['HANDLE SemaphoreHandle', ' SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass', ' PVOID SemaphoreInformation', ' ULONG SemaphoreInformationLength', ' PULONG ReturnLength']
		case 148: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQuerySemaphore_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySemaphore_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 149 NTSTATUS NtQuerySymbolicLinkObject ['HANDLE LinkHandle', ' PUNICODE_STRING LinkTarget', ' PULONG ReturnedLength']
		case 149: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtQuerySymbolicLinkObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySymbolicLinkObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 150 NTSTATUS NtQuerySystemEnvironmentValue ['PUNICODE_STRING VariableName', ' PWSTR VariableValue', ' USHORT ValueLength', ' PUSHORT ReturnLength']
		case 150: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtQuerySystemEnvironmentValue_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySystemEnvironmentValue_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 151 NTSTATUS NtQuerySystemInformation ['SYSTEM_INFORMATION_CLASS SystemInformationClass', ' PVOID SystemInformation', ' ULONG SystemInformationLength', ' PULONG ReturnLength']
		case 151: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtQuerySystemInformation_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySystemInformation_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 152 NTSTATUS NtQuerySystemTime ['PLARGE_INTEGER SystemTime']
		case 152: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtQuerySystemTime_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySystemTime_return, cpu, pc, arg0) ;
		}; break;
		// 153 NTSTATUS NtQueryTimer ['HANDLE TimerHandle', ' TIMER_INFORMATION_CLASS TimerInformationClass', ' PVOID TimerInformation', ' ULONG TimerInformationLength', ' PULONG ReturnLength']
		case 153: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryTimer_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryTimer_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 154 NTSTATUS NtQueryTimerResolution ['PULONG MaximumTime', ' PULONG MinimumTime', ' PULONG CurrentTime']
		case 154: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtQueryTimerResolution_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryTimerResolution_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 155 NTSTATUS NtQueryValueKey ['HANDLE KeyHandle', ' PUNICODE_STRING ValueName', ' KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass', ' PVOID KeyValueInformation', ' ULONG Length', ' PULONG ResultLength']
		case 155: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtQueryValueKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryValueKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 156 NTSTATUS NtQueryVirtualMemory ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' MEMORY_INFORMATION_CLASS MemoryInformationClass', ' PVOID MemoryInformation', ' SIZE_T MemoryInformationLength', ' PSIZE_T ReturnLength']
		case 156: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtQueryVirtualMemory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 157 NTSTATUS NtQueryVolumeInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FsInformation', ' ULONG Length', ' FS_INFORMATION_CLASS FsInformationClass']
		case 157: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryVolumeInformationFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryVolumeInformationFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 158 NTSTATUS NtQueueApcThread ['HANDLE ThreadHandle', ' PPS_APC_ROUTINE ApcRoutine', ' PVOID ApcArgument1', ' PVOID ApcArgument2', ' PVOID ApcArgument3']
		case 158: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueueApcThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueueApcThread_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 159 NTSTATUS NtRaiseException ['PEXCEPTION_RECORD ExceptionRecord', ' PCONTEXT ContextRecord', ' BOOLEAN FirstChance']
		case 159: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtRaiseException_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRaiseException_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 160 NTSTATUS NtRaiseHardError ['NTSTATUS ErrorStatus', ' ULONG NumberOfParameters', ' ULONG UnicodeStringParameterMask', ' PULONG_PTR Parameters', ' ULONG ValidResponseOptions', ' PULONG Response']
		case 160: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtRaiseHardError_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRaiseHardError_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 161 NTSTATUS NtReadFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' PLARGE_INTEGER ByteOffset', ' PULONG Key']
		case 161: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtReadFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReadFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 162 NTSTATUS NtReadFileScatter ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PFILE_SEGMENT_ELEMENT SegmentArray', ' ULONG Length', ' PLARGE_INTEGER ByteOffset', ' PULONG Key']
		case 162: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtReadFileScatter_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReadFileScatter_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 163 NTSTATUS NtReadRequestData ['HANDLE PortHandle', ' PPORT_MESSAGE Message', ' ULONG DataEntryIndex', ' PVOID Buffer', ' SIZE_T BufferSize', ' PSIZE_T NumberOfBytesRead']
		case 163: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtReadRequestData_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReadRequestData_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 164 NTSTATUS NtReadVirtualMemory ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' PVOID Buffer', ' SIZE_T BufferSize', ' PSIZE_T NumberOfBytesRead']
		case 164: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtReadVirtualMemory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReadVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 165 NTSTATUS NtRegisterThreadTerminatePort ['HANDLE PortHandle']
		case 165: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtRegisterThreadTerminatePort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRegisterThreadTerminatePort_return, cpu, pc, arg0) ;
		}; break;
		// 166 NTSTATUS NtReleaseMutant ['HANDLE MutantHandle', ' PLONG PreviousCount']
		case 166: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtReleaseMutant_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReleaseMutant_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 167 NTSTATUS NtReleaseSemaphore ['HANDLE SemaphoreHandle', ' LONG ReleaseCount', ' PLONG PreviousCount']
		case 167: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtReleaseSemaphore_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(int32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReleaseSemaphore_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 168 NTSTATUS NtRemoveIoCompletion ['HANDLE IoCompletionHandle', ' PVOID *KeyContext', ' PVOID *ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PLARGE_INTEGER Timeout']
		case 168: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtRemoveIoCompletion_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRemoveIoCompletion_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 169 NTSTATUS NtReplaceKey ['POBJECT_ATTRIBUTES NewFile', ' HANDLE TargetHandle', ' POBJECT_ATTRIBUTES OldFile']
		case 169: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtReplaceKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplaceKey_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 170 NTSTATUS NtReplyPort ['HANDLE PortHandle', ' PPORT_MESSAGE ReplyMessage']
		case 170: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtReplyPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplyPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 171 NTSTATUS NtReplyWaitReceivePort ['HANDLE PortHandle', ' PVOID *PortContext ', ' PPORT_MESSAGE ReplyMessage', ' PPORT_MESSAGE ReceiveMessage']
		case 171: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtReplyWaitReceivePort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplyWaitReceivePort_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 172 NTSTATUS NtReplyWaitReceivePortEx ['HANDLE PortHandle', ' PVOID *PortContext', ' PPORT_MESSAGE ReplyMessage', ' PPORT_MESSAGE ReceiveMessage', ' PLARGE_INTEGER Timeout']
		case 172: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtReplyWaitReceivePortEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplyWaitReceivePortEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 173 NTSTATUS NtReplyWaitReplyPort ['HANDLE PortHandle', ' PPORT_MESSAGE ReplyMessage']
		case 173: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtReplyWaitReplyPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplyWaitReplyPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 175 NTSTATUS NtRequestPort ['HANDLE PortHandle', ' PPORT_MESSAGE RequestMessage']
		case 175: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRequestPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRequestPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 176 NTSTATUS NtRequestWaitReplyPort ['HANDLE PortHandle', ' PPORT_MESSAGE RequestMessage', ' PPORT_MESSAGE ReplyMessage']
		case 176: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtRequestWaitReplyPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRequestWaitReplyPort_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 178 NTSTATUS NtResetEvent ['HANDLE EventHandle', ' PLONG PreviousState']
		case 178: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtResetEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtResetEvent_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 179 NTSTATUS NtResetWriteWatch ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' SIZE_T RegionSize']
		case 179: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtResetWriteWatch_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtResetWriteWatch_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 180 NTSTATUS NtRestoreKey ['HANDLE KeyHandle', ' HANDLE FileHandle', ' ULONG Flags']
		case 180: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtRestoreKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRestoreKey_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 181 NTSTATUS NtResumeThread ['HANDLE ThreadHandle', ' PULONG PreviousSuspendCount']
		case 181: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtResumeThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtResumeThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 182 NTSTATUS NtSaveKey ['HANDLE KeyHandle', ' HANDLE FileHandle']
		case 182: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSaveKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSaveKey_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 183 NTSTATUS NtSaveMergedKeys ['HANDLE HighPrecedenceKeyHandle', ' HANDLE LowPrecedenceKeyHandle', ' HANDLE FileHandle']
		case 183: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSaveMergedKeys_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSaveMergedKeys_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 184 NTSTATUS NtSecureConnectPort ['PHANDLE PortHandle', ' PUNICODE_STRING PortName', ' PSECURITY_QUALITY_OF_SERVICE SecurityQos', ' PPORT_VIEW ClientView', ' PSID RequiredServerSid', ' PREMOTE_PORT_VIEW ServerView', ' PULONG MaxMessageLength', ' PVOID ConnectionInformation', ' PULONG ConnectionInformationLength']
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
			if (PPP_CHECK_CB(on_NtSecureConnectPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSecureConnectPort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 185 NTSTATUS NtSetIoCompletion ['HANDLE IoCompletionHandle', ' PVOID KeyContext', ' PVOID ApcContext', ' NTSTATUS IoStatus', ' ULONG_PTR IoStatusInformation']
		case 185: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtSetIoCompletion_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetIoCompletion_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 186 NTSTATUS NtSetContextThread ['HANDLE ThreadHandle', ' PCONTEXT ThreadContext']
		case 186: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetContextThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetContextThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 187 NTSTATUS NtSetDefaultHardErrorPort ['HANDLE DefaultHardErrorPort']
		case 187: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetDefaultHardErrorPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetDefaultHardErrorPort_return, cpu, pc, arg0) ;
		}; break;
		// 188 NTSTATUS NtSetDefaultLocale ['BOOLEAN UserProfile', ' LCID DefaultLocaleId']
		case 188: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetDefaultLocale_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetDefaultLocale_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 189 NTSTATUS NtSetDefaultUILanguage ['LANGID DefaultUILanguageId']
		case 189: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetDefaultUILanguage_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetDefaultUILanguage_return, cpu, pc, arg0) ;
		}; break;
		// 190 NTSTATUS NtSetEaFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length']
		case 190: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetEaFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetEaFile_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 191 NTSTATUS NtSetEvent ['HANDLE EventHandle', ' PLONG PreviousState']
		case 191: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetEvent_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 192 NTSTATUS NtSetHighEventPair ['HANDLE EventPairHandle']
		case 192: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetHighEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetHighEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 193 NTSTATUS NtSetHighWaitLowEventPair ['HANDLE EventPairHandle']
		case 193: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetHighWaitLowEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetHighWaitLowEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 194 NTSTATUS NtSetInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FileInformation', ' ULONG Length', ' FILE_INFORMATION_CLASS FileInformationClass']
		case 194: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtSetInformationFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 195 NTSTATUS NtSetInformationJobObject ['HANDLE JobHandle', ' JOBOBJECTINFOCLASS JobObjectInformationClass', ' PVOID JobObjectInformation', ' ULONG JobObjectInformationLength']
		case 195: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationJobObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationJobObject_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 196 NTSTATUS NtSetInformationKey ['HANDLE KeyHandle', ' KEY_SET_INFORMATION_CLASS KeySetInformationClass', ' PVOID KeySetInformation', ' ULONG KeySetInformationLength']
		case 196: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationKey_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 197 NTSTATUS NtSetInformationObject ['HANDLE Handle', ' OBJECT_INFORMATION_CLASS ObjectInformationClass', ' PVOID ObjectInformation', ' ULONG ObjectInformationLength']
		case 197: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationObject_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 198 NTSTATUS NtSetInformationProcess ['HANDLE ProcessHandle', ' PROCESSINFOCLASS ProcessInformationClass', ' PVOID ProcessInformation', ' ULONG ProcessInformationLength']
		case 198: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationProcess_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationProcess_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 199 NTSTATUS NtSetInformationThread ['HANDLE ThreadHandle', ' THREADINFOCLASS ThreadInformationClass', ' PVOID ThreadInformation', ' ULONG ThreadInformationLength']
		case 199: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationThread_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 200 NTSTATUS NtSetInformationToken ['HANDLE TokenHandle', ' TOKEN_INFORMATION_CLASS TokenInformationClass', ' PVOID TokenInformation', ' ULONG TokenInformationLength']
		case 200: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationToken_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationToken_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 201 NTSTATUS NtSetIntervalProfile ['ULONG Interval', ' KPROFILE_SOURCE Source']
		case 201: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetIntervalProfile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetIntervalProfile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 202 NTSTATUS NtSetLdtEntries ['ULONG Selector0', ' ULONG Entry0Low', ' ULONG Entry0Hi', ' ULONG Selector1', ' ULONG Entry1Low', ' ULONG Entry1Hi']
		case 202: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtSetLdtEntries_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetLdtEntries_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 203 NTSTATUS NtSetLowEventPair ['HANDLE EventPairHandle']
		case 203: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetLowEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetLowEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 204 NTSTATUS NtSetLowWaitHighEventPair ['HANDLE EventPairHandle']
		case 204: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetLowWaitHighEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetLowWaitHighEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 205 NTSTATUS NtSetQuotaInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length']
		case 205: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetQuotaInformationFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetQuotaInformationFile_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 206 NTSTATUS NtSetSecurityObject ['HANDLE Handle', ' SECURITY_INFORMATION SecurityInformation', ' PSECURITY_DESCRIPTOR SecurityDescriptor']
		case 206: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSetSecurityObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSecurityObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 207 NTSTATUS NtSetSystemEnvironmentValue ['PUNICODE_STRING VariableName', ' PUNICODE_STRING VariableValue']
		case 207: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetSystemEnvironmentValue_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSystemEnvironmentValue_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 208 NTSTATUS NtSetSystemInformation ['SYSTEM_INFORMATION_CLASS SystemInformationClass', ' PVOID SystemInformation', ' ULONG SystemInformationLength']
		case 208: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSetSystemInformation_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSystemInformation_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 209 NTSTATUS NtSetSystemPowerState ['POWER_ACTION SystemAction', ' SYSTEM_POWER_STATE MinSystemState', ' ULONG Flags']
		case 209: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSetSystemPowerState_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSystemPowerState_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 210 NTSTATUS NtSetSystemTime ['PLARGE_INTEGER SystemTime', ' PLARGE_INTEGER PreviousTime']
		case 210: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetSystemTime_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSystemTime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 211 NTSTATUS NtSetThreadExecutionState ['EXECUTION_STATE esFlags', ' PEXECUTION_STATE PreviousFlags']
		case 211: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetThreadExecutionState_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetThreadExecutionState_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 212 NTSTATUS NtSetTimer ['HANDLE TimerHandle', ' PLARGE_INTEGER DueTime', ' PTIMER_APC_ROUTINE TimerApcRoutine', ' PVOID TimerContext', ' BOOLEAN WakeTimer', ' LONG Period', ' PBOOLEAN PreviousState']
		case 212: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			int32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtSetTimer_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(int32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetTimer_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 213 NTSTATUS NtSetTimerResolution ['ULONG DesiredTime', ' BOOLEAN SetResolution', ' PULONG ActualTime']
		case 213: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSetTimerResolution_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetTimerResolution_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 214 NTSTATUS NtSetUuidSeed ['PCHAR Seed']
		case 214: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetUuidSeed_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetUuidSeed_return, cpu, pc, arg0) ;
		}; break;
		// 215 NTSTATUS NtSetValueKey ['HANDLE KeyHandle', ' PUNICODE_STRING ValueName', ' ULONG TitleIndex', ' ULONG Type', ' PVOID Data', ' ULONG DataSize']
		case 215: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtSetValueKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetValueKey_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 216 NTSTATUS NtSetVolumeInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FsInformation', ' ULONG Length', ' FS_INFORMATION_CLASS FsInformationClass']
		case 216: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtSetVolumeInformationFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetVolumeInformationFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 217 NTSTATUS NtShutdownSystem ['SHUTDOWN_ACTION Action']
		case 217: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtShutdownSystem_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtShutdownSystem_return, cpu, pc, arg0) ;
		}; break;
		// 218 NTSTATUS NtSignalAndWaitForSingleObject ['HANDLE SignalHandle', ' HANDLE WaitHandle', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout']
		case 218: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSignalAndWaitForSingleObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSignalAndWaitForSingleObject_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 219 NTSTATUS NtStartProfile ['HANDLE ProfileHandle']
		case 219: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtStartProfile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtStartProfile_return, cpu, pc, arg0) ;
		}; break;
		// 220 NTSTATUS NtStopProfile ['HANDLE ProfileHandle']
		case 220: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtStopProfile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtStopProfile_return, cpu, pc, arg0) ;
		}; break;
		// 221 NTSTATUS NtSuspendThread ['HANDLE ThreadHandle', ' PULONG PreviousSuspendCount']
		case 221: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSuspendThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSuspendThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 222 NTSTATUS NtSystemDebugControl ['SYSDBG_COMMAND Command', ' PVOID InputBuffer', ' ULONG InputBufferLength', ' PVOID OutputBuffer', ' ULONG OutputBufferLength', ' PULONG ReturnLength']
		case 222: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtSystemDebugControl_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSystemDebugControl_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 223 NTSTATUS NtTerminateJobObject ['HANDLE JobHandle', ' NTSTATUS ExitStatus']
		case 223: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtTerminateJobObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTerminateJobObject_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 224 NTSTATUS NtTerminateProcess ['HANDLE ProcessHandle', ' NTSTATUS ExitStatus']
		case 224: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtTerminateProcess_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTerminateProcess_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 225 NTSTATUS NtTerminateThread ['HANDLE ThreadHandle', ' NTSTATUS ExitStatus']
		case 225: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtTerminateThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTerminateThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 226 NTSTATUS NtTestAlert ['']
		case 226: {
			if (PPP_CHECK_CB(on_NtTestAlert_return)) {
			}
			PPP_RUN_CB(on_NtTestAlert_return, cpu, pc) ;
		}; break;
		// 227 NTSTATUS NtUnloadDriver ['PUNICODE_STRING DriverServiceName']
		case 227: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtUnloadDriver_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnloadDriver_return, cpu, pc, arg0) ;
		}; break;
		// 228 NTSTATUS NtUnloadKey ['POBJECT_ATTRIBUTES TargetKey']
		case 228: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtUnloadKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnloadKey_return, cpu, pc, arg0) ;
		}; break;
		// 229 NTSTATUS NtUnlockFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PLARGE_INTEGER ByteOffset', ' PLARGE_INTEGER Length', ' ULONG Key']
		case 229: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtUnlockFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnlockFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 230 NTSTATUS NtUnlockVirtualMemory ['HANDLE ProcessHandle', ' PVOID *BaseAddress', ' PSIZE_T RegionSize', ' ULONG MapType']
		case 230: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtUnlockVirtualMemory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnlockVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 231 NTSTATUS NtUnmapViewOfSection ['HANDLE ProcessHandle', ' PVOID BaseAddress']
		case 231: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtUnmapViewOfSection_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnmapViewOfSection_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 232 NTSTATUS NtVdmControl ['VDMSERVICECLASS Service', ' PVOID ServiceData']
		case 232: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtVdmControl_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtVdmControl_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 233 NTSTATUS NtWaitForMultipleObjects ['ULONG Count', ' HANDLE Handles[]', ' WAIT_TYPE WaitType', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout']
		case 233: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtWaitForMultipleObjects_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitForMultipleObjects_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 234 NTSTATUS NtWaitForSingleObject ['HANDLE Handle', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout']
		case 234: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtWaitForSingleObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitForSingleObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 235 NTSTATUS NtWaitHighEventPair ['HANDLE EventPairHandle']
		case 235: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtWaitHighEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitHighEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 236 NTSTATUS NtWaitLowEventPair ['HANDLE EventPairHandle']
		case 236: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtWaitLowEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitLowEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 237 NTSTATUS NtWriteFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' PLARGE_INTEGER ByteOffset', ' PULONG Key']
		case 237: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtWriteFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWriteFile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 238 NTSTATUS NtWriteFileGather ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PFILE_SEGMENT_ELEMENT SegmentArray', ' ULONG Length', ' PLARGE_INTEGER ByteOffset', ' PULONG Key']
		case 238: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtWriteFileGather_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
				memcpy(&arg8, rp.params[8], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWriteFileGather_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 239 NTSTATUS NtWriteRequestData ['HANDLE PortHandle', ' PPORT_MESSAGE Message', ' ULONG DataEntryIndex', ' PVOID Buffer', ' SIZE_T BufferSize', ' PSIZE_T NumberOfBytesWritten']
		case 239: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtWriteRequestData_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWriteRequestData_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 240 NTSTATUS NtWriteVirtualMemory ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' PVOID Buffer', ' SIZE_T BufferSize', ' PSIZE_T NumberOfBytesWritten']
		case 240: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtWriteVirtualMemory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWriteVirtualMemory_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 247 NTSTATUS NtYieldExecution ['']
		case 247: {
			if (PPP_CHECK_CB(on_NtYieldExecution_return)) {
			}
			PPP_RUN_CB(on_NtYieldExecution_return, cpu, pc) ;
		}; break;
		default:
			PPP_RUN_CB(on_unknown_sys_return, cpu, pc, rp.ordinal);
	}
	PPP_RUN_CB(on_all_sys_return, cpu, pc, rp.ordinal);
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */