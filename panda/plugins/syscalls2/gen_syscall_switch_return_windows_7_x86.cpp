#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls_common.h"

extern "C" {
#include "gen_syscalls_ext_typedefs.h"
#include "gen_syscall_ppp_extern_return.h"
}

void syscall_return_switch_windows_7_x86(CPUState *cpu, target_ulong pc, target_ulong ordinal, ReturnPoint &rp) {
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
		// 9 NTSTATUS NtAddBootEntry ['PBOOT_ENTRY BootEntry', ' PULONG Id']
		case 9: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAddBootEntry_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAddBootEntry_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 10 NTSTATUS NtAddDriverEntry ['PEFI_DRIVER_ENTRY DriverEntry', ' PULONG Id']
		case 10: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAddDriverEntry_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAddDriverEntry_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 11 NTSTATUS NtAdjustGroupsToken ['HANDLE TokenHandle', ' BOOLEAN ResetToDefault', ' PTOKEN_GROUPS NewState', ' ULONG BufferLength', ' PTOKEN_GROUPS PreviousState', ' PULONG ReturnLength']
		case 11: {
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
		// 12 NTSTATUS NtAdjustPrivilegesToken ['HANDLE TokenHandle', ' BOOLEAN DisableAllPrivileges', ' PTOKEN_PRIVILEGES NewState', ' ULONG BufferLength', ' PTOKEN_PRIVILEGES PreviousState', ' PULONG ReturnLength']
		case 12: {
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
		// 13 NTSTATUS NtAlertResumeThread ['HANDLE ThreadHandle', ' PULONG PreviousSuspendCount']
		case 13: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAlertResumeThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlertResumeThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 14 NTSTATUS NtAlertThread ['HANDLE ThreadHandle']
		case 14: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtAlertThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlertThread_return, cpu, pc, arg0) ;
		}; break;
		// 15 NTSTATUS NtAllocateLocallyUniqueId ['PLUID Luid']
		case 15: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtAllocateLocallyUniqueId_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAllocateLocallyUniqueId_return, cpu, pc, arg0) ;
		}; break;
		// 16 NTSTATUS NtAllocateReserveObject ['PHANDLE MemoryReserveHandle', ' POBJECT_ATTRIBUTES ObjectAttributes', ' MEMORY_RESERVE_TYPE Type']
		case 16: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAllocateReserveObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAllocateReserveObject_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 17 NTSTATUS NtAllocateUserPhysicalPages ['HANDLE ProcessHandle', ' PULONG_PTR NumberOfPages', ' PULONG_PTR UserPfnArray']
		case 17: {
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
		// 18 NTSTATUS NtAllocateUuids ['PULARGE_INTEGER Time', ' PULONG Range', ' PULONG Sequence', ' PCHAR Seed']
		case 18: {
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
		// 19 NTSTATUS NtAllocateVirtualMemory ['HANDLE ProcessHandle', ' PVOID *BaseAddress', ' ULONG_PTR ZeroBits', ' PSIZE_T RegionSize', ' ULONG AllocationType', ' ULONG Protect']
		case 19: {
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
		// 20 NTSTATUS NtAlpcAcceptConnectPort ['PHANDLE PortHandle', ' HANDLE ConnectionPortHandle', ' ULONG Flags', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PALPC_PORT_ATTRIBUTES PortAttributes', ' PVOID PortContext', ' PPORT_MESSAGE ConnectionRequest', ' PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes', ' BOOLEAN AcceptConnection']
		case 20: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtAlpcAcceptConnectPort_return)) {
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
			PPP_RUN_CB(on_NtAlpcAcceptConnectPort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 21 NTSTATUS NtAlpcCancelMessage ['HANDLE PortHandle', ' ULONG Flags', ' PALPC_CONTEXT_ATTR MessageContext']
		case 21: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAlpcCancelMessage_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcCancelMessage_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 22 NTSTATUS NtAlpcConnectPort ['PHANDLE PortHandle', ' PUNICODE_STRING PortName', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PALPC_PORT_ATTRIBUTES PortAttributes', ' ULONG Flags', ' PSID RequiredServerSid', ' PPORT_MESSAGE ConnectionMessage', ' PULONG BufferLength', ' PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes', ' PALPC_MESSAGE_ATTRIBUTES InMessageAttributes', ' PLARGE_INTEGER Timeout']
		case 22: {
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
			if (PPP_CHECK_CB(on_NtAlpcConnectPort_return)) {
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
			PPP_RUN_CB(on_NtAlpcConnectPort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 23 NTSTATUS NtAlpcCreatePort ['PHANDLE PortHandle', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PALPC_PORT_ATTRIBUTES PortAttributes']
		case 23: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAlpcCreatePort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcCreatePort_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 24 NTSTATUS NtAlpcCreatePortSection ['HANDLE PortHandle', ' ULONG Flags', ' HANDLE SectionHandle', ' SIZE_T SectionSize', ' PALPC_HANDLE AlpcSectionHandle', ' PSIZE_T ActualSectionSize']
		case 24: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtAlpcCreatePortSection_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcCreatePortSection_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 25 NTSTATUS NtAlpcCreateResourceReserve ['HANDLE PortHandle', ' ULONG Flags', ' SIZE_T MessageSize', ' PALPC_HANDLE ResourceId']
		case 25: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtAlpcCreateResourceReserve_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcCreateResourceReserve_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 26 NTSTATUS NtAlpcCreateSectionView ['HANDLE PortHandle', ' ULONG Flags', ' PALPC_DATA_VIEW_ATTR ViewAttributes']
		case 26: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAlpcCreateSectionView_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcCreateSectionView_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 27 NTSTATUS NtAlpcCreateSecurityContext ['HANDLE PortHandle', ' ULONG Flags', ' PALPC_SECURITY_ATTR SecurityAttribute']
		case 27: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAlpcCreateSecurityContext_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcCreateSecurityContext_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 28 NTSTATUS NtAlpcDeletePortSection ['HANDLE PortHandle', ' ULONG Flags', ' ALPC_HANDLE SectionHandle']
		case 28: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAlpcDeletePortSection_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcDeletePortSection_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 29 NTSTATUS NtAlpcDeleteResourceReserve ['HANDLE PortHandle', ' ULONG Flags', ' ALPC_HANDLE ResourceId']
		case 29: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAlpcDeleteResourceReserve_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcDeleteResourceReserve_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 30 NTSTATUS NtAlpcDeleteSectionView ['HANDLE PortHandle', ' ULONG Flags', ' PVOID ViewBase']
		case 30: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAlpcDeleteSectionView_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcDeleteSectionView_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 31 NTSTATUS NtAlpcDeleteSecurityContext ['HANDLE PortHandle', ' ULONG Flags', ' ALPC_HANDLE ContextHandle']
		case 31: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAlpcDeleteSecurityContext_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcDeleteSecurityContext_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 32 NTSTATUS NtAlpcDisconnectPort ['HANDLE PortHandle', ' ULONG Flags']
		case 32: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAlpcDisconnectPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcDisconnectPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 33 NTSTATUS NtAlpcImpersonateClientOfPort ['HANDLE PortHandle', ' PPORT_MESSAGE PortMessage', ' PVOID Reserved']
		case 33: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAlpcImpersonateClientOfPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcImpersonateClientOfPort_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 34 NTSTATUS NtAlpcOpenSenderProcess ['PHANDLE ProcessHandle', ' HANDLE PortHandle', ' PPORT_MESSAGE PortMessage', ' ULONG Flags', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 34: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtAlpcOpenSenderProcess_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcOpenSenderProcess_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 35 NTSTATUS NtAlpcOpenSenderThread ['PHANDLE ThreadHandle', ' HANDLE PortHandle', ' PPORT_MESSAGE PortMessage', ' ULONG Flags', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 35: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtAlpcOpenSenderThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcOpenSenderThread_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 36 NTSTATUS NtAlpcQueryInformation ['HANDLE PortHandle', ' ALPC_PORT_INFORMATION_CLASS PortInformationClass', ' PVOID PortInformation', ' ULONG Length', ' PULONG ReturnLength']
		case 36: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtAlpcQueryInformation_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcQueryInformation_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 37 NTSTATUS NtAlpcQueryInformationMessage ['HANDLE PortHandle', ' PPORT_MESSAGE PortMessage', ' ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass', ' PVOID MessageInformation', ' ULONG Length', ' PULONG ReturnLength']
		case 37: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtAlpcQueryInformationMessage_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcQueryInformationMessage_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 38 NTSTATUS NtAlpcRevokeSecurityContext ['HANDLE PortHandle', ' ULONG Flags', ' ALPC_HANDLE ContextHandle']
		case 38: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtAlpcRevokeSecurityContext_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcRevokeSecurityContext_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 39 NTSTATUS NtAlpcSendWaitReceivePort ['HANDLE PortHandle', ' ULONG Flags', ' PPORT_MESSAGE SendMessage', ' PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes', ' PPORT_MESSAGE ReceiveMessage', ' PULONG BufferLength', ' PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes', ' PLARGE_INTEGER Timeout']
		case 39: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtAlpcSendWaitReceivePort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcSendWaitReceivePort_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 40 NTSTATUS NtAlpcSetInformation ['HANDLE PortHandle', ' ALPC_PORT_INFORMATION_CLASS PortInformationClass', ' PVOID PortInformation', ' ULONG Length']
		case 40: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtAlpcSetInformation_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAlpcSetInformation_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 41 NTSTATUS NtApphelpCacheControl ['APPHELPCOMMAND type', ' PVOID buf']
		case 41: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtApphelpCacheControl_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtApphelpCacheControl_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 42 NTSTATUS NtAreMappedFilesTheSame ['PVOID File1MappedAsAnImage', ' PVOID File2MappedAsFile']
		case 42: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAreMappedFilesTheSame_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAreMappedFilesTheSame_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 43 NTSTATUS NtAssignProcessToJobObject ['HANDLE JobHandle', ' HANDLE ProcessHandle']
		case 43: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtAssignProcessToJobObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtAssignProcessToJobObject_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 44 NTSTATUS NtCallbackReturn ['PVOID OutputBuffer', ' ULONG OutputLength', ' NTSTATUS Status']
		case 44: {
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
		// 45 NTSTATUS NtCancelIoFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock']
		case 45: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtCancelIoFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCancelIoFile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 46 NTSTATUS NtCancelIoFileEx ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoRequestToCancel', ' PIO_STATUS_BLOCK IoStatusBlock']
		case 46: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCancelIoFileEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCancelIoFileEx_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 47 NTSTATUS NtCancelSynchronousIoFile ['HANDLE ThreadHandle', ' PIO_STATUS_BLOCK IoRequestToCancel', ' PIO_STATUS_BLOCK IoStatusBlock']
		case 47: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCancelSynchronousIoFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCancelSynchronousIoFile_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 48 NTSTATUS NtCancelTimer ['HANDLE TimerHandle', ' PBOOLEAN CurrentState']
		case 48: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtCancelTimer_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCancelTimer_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 49 NTSTATUS NtClearEvent ['HANDLE EventHandle']
		case 49: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtClearEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtClearEvent_return, cpu, pc, arg0) ;
		}; break;
		// 50 NTSTATUS NtClose ['HANDLE Handle']
		case 50: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtClose_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtClose_return, cpu, pc, arg0) ;
		}; break;
		// 51 NTSTATUS NtCloseObjectAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' BOOLEAN GenerateOnClose']
		case 51: {
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
		// 52 NTSTATUS NtCommitComplete ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
		case 52: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtCommitComplete_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCommitComplete_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 53 NTSTATUS NtCommitEnlistment ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
		case 53: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtCommitEnlistment_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCommitEnlistment_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 54 NTSTATUS NtCommitTransaction ['HANDLE TransactionHandle', ' BOOLEAN Wait']
		case 54: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtCommitTransaction_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCommitTransaction_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 55 NTSTATUS NtCompactKeys ['ULONG Count', ' HANDLE KeyArray[]']
		case 55: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtCompactKeys_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCompactKeys_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 56 NTSTATUS NtCompareTokens ['HANDLE FirstTokenHandle', ' HANDLE SecondTokenHandle', ' PBOOLEAN Equal']
		case 56: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCompareTokens_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCompareTokens_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 57 NTSTATUS NtCompleteConnectPort ['HANDLE PortHandle']
		case 57: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtCompleteConnectPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCompleteConnectPort_return, cpu, pc, arg0) ;
		}; break;
		// 58 NTSTATUS NtCompressKey ['HANDLE Key']
		case 58: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtCompressKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCompressKey_return, cpu, pc, arg0) ;
		}; break;
		// 59 NTSTATUS NtConnectPort ['PHANDLE PortHandle', ' PUNICODE_STRING PortName', ' PSECURITY_QUALITY_OF_SERVICE SecurityQos', ' PPORT_VIEW ClientView', ' PREMOTE_PORT_VIEW ServerView', ' PULONG MaxMessageLength', ' PVOID ConnectionInformation', ' PULONG ConnectionInformationLength']
		case 59: {
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
		// 60 NTSTATUS NtContinue ['PCONTEXT ContextRecord', ' BOOLEAN TestAlert']
		case 60: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtContinue_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtContinue_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 61 NTSTATUS NtCreateDebugObject ['PHANDLE DebugObjectHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG Flags']
		case 61: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreateDebugObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateDebugObject_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 62 NTSTATUS NtCreateDirectoryObject ['PHANDLE DirectoryHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 62: {
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
		// 63 NTSTATUS NtCreateEnlistment ['PHANDLE EnlistmentHandle', ' ACCESS_MASK DesiredAccess', ' HANDLE ResourceManagerHandle', ' HANDLE TransactionHandle', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG CreateOptions', ' NOTIFICATION_MASK NotificationMask', ' PVOID EnlistmentKey']
		case 63: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtCreateEnlistment_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateEnlistment_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 64 NTSTATUS NtCreateEvent ['PHANDLE EventHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' EVENT_TYPE EventType', ' BOOLEAN InitialState']
		case 64: {
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
		// 65 NTSTATUS NtCreateEventPair ['PHANDLE EventPairHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 65: {
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
		// 66 NTSTATUS NtCreateFile ['PHANDLE FileHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PIO_STATUS_BLOCK IoStatusBlock', ' PLARGE_INTEGER AllocationSize', ' ULONG FileAttributes', ' ULONG ShareAccess', ' ULONG CreateDisposition', ' ULONG CreateOptions', ' PVOID EaBuffer', ' ULONG EaLength']
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
		// 67 NTSTATUS NtCreateIoCompletion ['PHANDLE IoCompletionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG Count']
		case 67: {
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
		// 68 NTSTATUS NtCreateJobObject ['PHANDLE JobHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 68: {
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
		// 69 NTSTATUS NtCreateJobSet ['ULONG NumJob', ' PJOB_SET_ARRAY UserJobSet', ' ULONG Flags']
		case 69: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtCreateJobSet_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateJobSet_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 70 NTSTATUS NtCreateKey ['PHANDLE KeyHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG TitleIndex', ' PUNICODE_STRING Class', ' ULONG CreateOptions', ' PULONG Disposition']
		case 70: {
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
		// 71 NTSTATUS NtCreateKeyedEvent ['PHANDLE KeyedEventHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG Flags']
		case 71: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreateKeyedEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateKeyedEvent_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 72 NTSTATUS NtCreateKeyTransacted ['PHANDLE KeyHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG TitleIndex', ' PUNICODE_STRING Class', ' ULONG CreateOptions', ' HANDLE TransactionHandle', ' PULONG Disposition']
		case 72: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtCreateKeyTransacted_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateKeyTransacted_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 73 NTSTATUS NtCreateMailslotFile ['PHANDLE FileHandle', ' ULONG DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG CreateOptions', ' ULONG MailslotQuota', ' ULONG MaximumMessageSize', ' PLARGE_INTEGER ReadTimeout']
		case 73: {
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
		// 74 NTSTATUS NtCreateMutant ['PHANDLE MutantHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' BOOLEAN InitialOwner']
		case 74: {
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
		// 75 NTSTATUS NtCreateNamedPipeFile ['PHANDLE FileHandle', ' ULONG DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG ShareAccess', ' ULONG CreateDisposition', ' ULONG CreateOptions', ' ULONG NamedPipeType', ' ULONG ReadMode', ' ULONG CompletionMode', ' ULONG MaximumInstances', ' ULONG InboundQuota', ' ULONG OutboundQuota', ' PLARGE_INTEGER DefaultTimeout']
		case 75: {
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
		// 76 NTSTATUS NtCreatePagingFile ['PUNICODE_STRING PageFileName', ' PLARGE_INTEGER MinimumSize', ' PLARGE_INTEGER MaximumSize', ' ULONG Priority']
		case 76: {
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
		// 77 NTSTATUS NtCreatePort ['PHANDLE PortHandle', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG MaxConnectionInfoLength', ' ULONG MaxMessageLength', ' ULONG MaxPoolUsage']
		case 77: {
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
		// 78 NTSTATUS NtCreatePrivateNamespace ['PHANDLE NamespaceHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PVOID BoundaryDescriptor']
		case 78: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtCreatePrivateNamespace_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreatePrivateNamespace_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 79 NTSTATUS NtCreateProcess ['PHANDLE ProcessHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE ParentProcess', ' BOOLEAN InheritObjectTable', ' HANDLE SectionHandle', ' HANDLE DebugPort', ' HANDLE ExceptionPort']
		case 79: {
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
		// 80 NTSTATUS NtCreateProcessEx ['PHANDLE ProcessHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE ParentProcess', ' ULONG Flags', ' HANDLE SectionHandle', ' HANDLE DebugPort', ' HANDLE ExceptionPort', ' ULONG JobMemberLevel']
		case 80: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			uint32_t arg8;
			if (PPP_CHECK_CB(on_NtCreateProcessEx_return)) {
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
			PPP_RUN_CB(on_NtCreateProcessEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) ;
		}; break;
		// 81 NTSTATUS NtCreateProfile ['PHANDLE ProfileHandle', ' HANDLE Process', ' PVOID RangeBase', ' SIZE_T RangeSize', ' ULONG BucketSize', ' PULONG Buffer', ' ULONG BufferSize', ' KPROFILE_SOURCE ProfileSource', ' KAFFINITY Affinity']
		case 81: {
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
		// 82 NTSTATUS NtCreateProfileEx ['PHANDLE ProfileHandle', ' HANDLE Process', ' PVOID ProfileBase', ' SIZE_T ProfileSize', ' ULONG BucketSize', ' PULONG Buffer', ' ULONG BufferSize', ' KPROFILE_SOURCE ProfileSource', ' ULONG GroupAffinityCount', ' PGROUP_AFFINITY GroupAffinity']
		case 82: {
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
			if (PPP_CHECK_CB(on_NtCreateProfileEx_return)) {
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
			PPP_RUN_CB(on_NtCreateProfileEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 83 NTSTATUS NtCreateResourceManager ['PHANDLE ResourceManagerHandle', ' ACCESS_MASK DesiredAccess', ' HANDLE TmHandle', ' LPGUID RmGuid', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG CreateOptions', ' PUNICODE_STRING Description']
		case 83: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtCreateResourceManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateResourceManager_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 84 NTSTATUS NtCreateSection ['PHANDLE SectionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PLARGE_INTEGER MaximumSize', ' ULONG SectionPageProtection', ' ULONG AllocationAttributes', ' HANDLE FileHandle']
		case 84: {
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
		// 85 NTSTATUS NtCreateSemaphore ['PHANDLE SemaphoreHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' LONG InitialCount', ' LONG MaximumCount']
		case 85: {
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
		// 86 NTSTATUS NtCreateSymbolicLinkObject ['PHANDLE LinkHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PUNICODE_STRING LinkTarget']
		case 86: {
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
		// 87 NTSTATUS NtCreateThread ['PHANDLE ThreadHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE ProcessHandle', ' PCLIENT_ID ClientId', ' PCONTEXT ThreadContext', ' PINITIAL_TEB InitialTeb', ' BOOLEAN CreateSuspended']
		case 87: {
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
		// 88 NTSTATUS NtCreateThreadEx ['PHANDLE ThreadHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE ProcessHandle', ' PVOID StartRoutine', ' PVOID Argument', ' ULONG CreateFlags', ' ULONG_PTR ZeroBits', ' SIZE_T StackSize', ' SIZE_T MaximumStackSize', ' PPS_ATTRIBUTE_LIST AttributeList']
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
			uint32_t arg10;
			if (PPP_CHECK_CB(on_NtCreateThreadEx_return)) {
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
			PPP_RUN_CB(on_NtCreateThreadEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 89 NTSTATUS NtCreateTimer ['PHANDLE TimerHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' TIMER_TYPE TimerType']
		case 89: {
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
		// 90 NTSTATUS NtCreateToken ['PHANDLE TokenHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' TOKEN_TYPE TokenType', ' PLUID AuthenticationId', ' PLARGE_INTEGER ExpirationTime', ' PTOKEN_USER User', ' PTOKEN_GROUPS Groups', ' PTOKEN_PRIVILEGES Privileges', ' PTOKEN_OWNER Owner', ' PTOKEN_PRIMARY_GROUP PrimaryGroup', ' PTOKEN_DEFAULT_DACL DefaultDacl', ' PTOKEN_SOURCE TokenSource']
		case 90: {
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
		// 91 NTSTATUS NtCreateTransaction ['PHANDLE TransactionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' LPGUID Uow', ' HANDLE TmHandle', ' ULONG CreateOptions', ' ULONG IsolationLevel', ' ULONG IsolationFlags', ' PLARGE_INTEGER Timeout', ' PUNICODE_STRING Description']
		case 91: {
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
			if (PPP_CHECK_CB(on_NtCreateTransaction_return)) {
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
			PPP_RUN_CB(on_NtCreateTransaction_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 92 NTSTATUS NtCreateTransactionManager ['PHANDLE TmHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PUNICODE_STRING LogFileName', ' ULONG CreateOptions', ' ULONG CommitStrength']
		case 92: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtCreateTransactionManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtCreateTransactionManager_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 93 NTSTATUS NtCreateUserProcess ['PHANDLE ProcessHandle', ' PHANDLE ThreadHandle', ' ACCESS_MASK ProcessDesiredAccess', ' ACCESS_MASK ThreadDesiredAccess', ' POBJECT_ATTRIBUTES ProcessObjectAttributes', ' POBJECT_ATTRIBUTES ThreadObjectAttributes', ' ULONG ProcessFlags', ' ULONG ThreadFlags', ' PRTL_USER_PROCESS_PARAMETERS ProcessParameters', ' PPROCESS_CREATE_INFO CreateInfo', ' PPROCESS_ATTRIBUTE_LIST AttributeList']
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
			uint32_t arg10;
			if (PPP_CHECK_CB(on_NtCreateUserProcess_return)) {
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
			PPP_RUN_CB(on_NtCreateUserProcess_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) ;
		}; break;
		// 94 NTSTATUS NtCreateWaitablePort ['PHANDLE PortHandle', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG MaxConnectionInfoLength', ' ULONG MaxMessageLength', ' ULONG MaxPoolUsage']
		case 94: {
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
		// 95 NTSTATUS NtCreateWorkerFactory ['PHANDLE WorkerFactoryHandleReturn', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE CompletionPortHandle', ' HANDLE WorkerProcessHandle', ' PVOID StartRoutine', ' PVOID StartParameter', ' ULONG MaxThreadCount', ' SIZE_T StackReserve', ' SIZE_T StackCommit']
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
			if (PPP_CHECK_CB(on_NtCreateWorkerFactory_return)) {
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
			PPP_RUN_CB(on_NtCreateWorkerFactory_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) ;
		}; break;
		// 96 NTSTATUS NtDebugActiveProcess ['HANDLE ProcessHandle', ' HANDLE DebugObjectHandle']
		case 96: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtDebugActiveProcess_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDebugActiveProcess_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 97 NTSTATUS NtDebugContinue ['HANDLE DebugObjectHandle', ' PCLIENT_ID ClientId', ' NTSTATUS ContinueStatus']
		case 97: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtDebugContinue_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDebugContinue_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 98 NTSTATUS NtDelayExecution ['BOOLEAN Alertable', ' PLARGE_INTEGER DelayInterval']
		case 98: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtDelayExecution_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDelayExecution_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 99 NTSTATUS NtDeleteAtom ['RTL_ATOM Atom']
		case 99: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeleteAtom_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteAtom_return, cpu, pc, arg0) ;
		}; break;
		// 100 NTSTATUS NtDeleteBootEntry ['ULONG Id']
		case 100: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeleteBootEntry_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteBootEntry_return, cpu, pc, arg0) ;
		}; break;
		// 101 NTSTATUS NtDeleteDriverEntry ['ULONG Id']
		case 101: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeleteDriverEntry_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteDriverEntry_return, cpu, pc, arg0) ;
		}; break;
		// 102 NTSTATUS NtDeleteFile ['POBJECT_ATTRIBUTES ObjectAttributes']
		case 102: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeleteFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteFile_return, cpu, pc, arg0) ;
		}; break;
		// 103 NTSTATUS NtDeleteKey ['HANDLE KeyHandle']
		case 103: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeleteKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteKey_return, cpu, pc, arg0) ;
		}; break;
		// 104 NTSTATUS NtDeleteObjectAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' BOOLEAN GenerateOnClose']
		case 104: {
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
		// 105 NTSTATUS NtDeletePrivateNamespace ['HANDLE NamespaceHandle']
		case 105: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDeletePrivateNamespace_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeletePrivateNamespace_return, cpu, pc, arg0) ;
		}; break;
		// 106 NTSTATUS NtDeleteValueKey ['HANDLE KeyHandle', ' PUNICODE_STRING ValueName']
		case 106: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtDeleteValueKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDeleteValueKey_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 107 NTSTATUS NtDeviceIoControlFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG IoControlCode', ' PVOID InputBuffer', ' ULONG InputBufferLength', ' PVOID OutputBuffer', ' ULONG OutputBufferLength']
		case 107: {
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
		// 108 NTSTATUS NtDisableLastKnownGood ['']
		case 108: {
			if (PPP_CHECK_CB(on_NtDisableLastKnownGood_return)) {
			}
			PPP_RUN_CB(on_NtDisableLastKnownGood_return, cpu, pc) ;
		}; break;
		// 109 NTSTATUS NtDisplayString ['PUNICODE_STRING String']
		case 109: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDisplayString_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDisplayString_return, cpu, pc, arg0) ;
		}; break;
		// 110 NTSTATUS NtDrawText ['PUNICODE_STRING Text']
		case 110: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtDrawText_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtDrawText_return, cpu, pc, arg0) ;
		}; break;
		// 111 NTSTATUS NtDuplicateObject ['HANDLE SourceProcessHandle', ' HANDLE SourceHandle', ' HANDLE TargetProcessHandle', ' PHANDLE TargetHandle', ' ACCESS_MASK DesiredAccess', ' ULONG HandleAttributes', ' ULONG Options']
		case 111: {
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
		// 112 NTSTATUS NtDuplicateToken ['HANDLE ExistingTokenHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' BOOLEAN EffectiveOnly', ' TOKEN_TYPE TokenType', ' PHANDLE NewTokenHandle']
		case 112: {
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
		// 113 NTSTATUS NtEnableLastKnownGood ['']
		case 113: {
			if (PPP_CHECK_CB(on_NtEnableLastKnownGood_return)) {
			}
			PPP_RUN_CB(on_NtEnableLastKnownGood_return, cpu, pc) ;
		}; break;
		// 114 NTSTATUS NtEnumerateBootEntries ['PVOID Buffer', ' PULONG BufferLength']
		case 114: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtEnumerateBootEntries_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtEnumerateBootEntries_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 115 NTSTATUS NtEnumerateDriverEntries ['PVOID Buffer', ' PULONG BufferLength']
		case 115: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtEnumerateDriverEntries_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtEnumerateDriverEntries_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 116 NTSTATUS NtEnumerateKey ['HANDLE KeyHandle', ' ULONG Index', ' KEY_INFORMATION_CLASS KeyInformationClass', ' PVOID KeyInformation', ' ULONG Length', ' PULONG ResultLength']
		case 116: {
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
		// 117 NTSTATUS NtEnumerateSystemEnvironmentValuesEx ['ULONG InformationClass', ' PVOID Buffer', ' PULONG BufferLength']
		case 117: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtEnumerateSystemEnvironmentValuesEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtEnumerateSystemEnvironmentValuesEx_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 118 NTSTATUS NtEnumerateTransactionObject ['HANDLE RootObjectHandle', ' KTMOBJECT_TYPE QueryType', ' PKTMOBJECT_CURSOR ObjectCursor', ' ULONG ObjectCursorLength', ' PULONG ReturnLength']
		case 118: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtEnumerateTransactionObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtEnumerateTransactionObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 119 NTSTATUS NtEnumerateValueKey ['HANDLE KeyHandle', ' ULONG Index', ' KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass', ' PVOID KeyValueInformation', ' ULONG Length', ' PULONG ResultLength']
		case 119: {
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
		// 120 NTSTATUS NtExtendSection ['HANDLE SectionHandle', ' PLARGE_INTEGER NewSectionSize']
		case 120: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtExtendSection_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtExtendSection_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 121 NTSTATUS NtFilterToken ['HANDLE ExistingTokenHandle', ' ULONG Flags', ' PTOKEN_GROUPS SidsToDisable', ' PTOKEN_PRIVILEGES PrivilegesToDelete', ' PTOKEN_GROUPS RestrictedSids', ' PHANDLE NewTokenHandle']
		case 121: {
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
		// 122 NTSTATUS NtFindAtom ['PWSTR AtomName', ' ULONG Length', ' PRTL_ATOM Atom']
		case 122: {
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
		// 123 NTSTATUS NtFlushBuffersFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock']
		case 123: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtFlushBuffersFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFlushBuffersFile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 124 NTSTATUS NtFlushInstallUILanguage ['LANGID InstallUILanguage', ' ULONG SetComittedFlag']
		case 124: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtFlushInstallUILanguage_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFlushInstallUILanguage_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 125 NTSTATUS NtFlushInstructionCache ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' SIZE_T Length']
		case 125: {
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
		// 126 NTSTATUS NtFlushKey ['HANDLE KeyHandle']
		case 126: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtFlushKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFlushKey_return, cpu, pc, arg0) ;
		}; break;
		// 127 VOID NtFlushProcessWriteBuffers ['']
		case 127: {
			if (PPP_CHECK_CB(on_NtFlushProcessWriteBuffers_return)) {
			}
			PPP_RUN_CB(on_NtFlushProcessWriteBuffers_return, cpu, pc) ;
		}; break;
		// 128 NTSTATUS NtFlushVirtualMemory ['HANDLE ProcessHandle', ' PVOID *BaseAddress', ' PSIZE_T RegionSize', ' PIO_STATUS_BLOCK IoStatus']
		case 128: {
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
		// 129 NTSTATUS NtFlushWriteBuffer ['']
		case 129: {
			if (PPP_CHECK_CB(on_NtFlushWriteBuffer_return)) {
			}
			PPP_RUN_CB(on_NtFlushWriteBuffer_return, cpu, pc) ;
		}; break;
		// 130 NTSTATUS NtFreeUserPhysicalPages ['HANDLE ProcessHandle', ' PULONG_PTR NumberOfPages', ' PULONG_PTR UserPfnArray']
		case 130: {
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
		// 131 NTSTATUS NtFreeVirtualMemory ['HANDLE ProcessHandle', ' PVOID *BaseAddress', ' PSIZE_T RegionSize', ' ULONG FreeType']
		case 131: {
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
		// 132 NTSTATUS NtFreezeRegistry ['ULONG TimeOutInSeconds']
		case 132: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtFreezeRegistry_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFreezeRegistry_return, cpu, pc, arg0) ;
		}; break;
		// 133 NTSTATUS NtFreezeTransactions ['PLARGE_INTEGER FreezeTimeout', ' PLARGE_INTEGER ThawTimeout']
		case 133: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtFreezeTransactions_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtFreezeTransactions_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 134 NTSTATUS NtFsControlFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG IoControlCode', ' PVOID InputBuffer', ' ULONG InputBufferLength', ' PVOID OutputBuffer', ' ULONG OutputBufferLength']
		case 134: {
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
		// 135 NTSTATUS NtGetContextThread ['HANDLE ThreadHandle', ' PCONTEXT ThreadContext']
		case 135: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtGetContextThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetContextThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 136 ULONG NtGetCurrentProcessorNumber ['']
		case 136: {
			if (PPP_CHECK_CB(on_NtGetCurrentProcessorNumber_return)) {
			}
			PPP_RUN_CB(on_NtGetCurrentProcessorNumber_return, cpu, pc) ;
		}; break;
		// 137 NTSTATUS NtGetDevicePowerState ['HANDLE Device', ' DEVICE_POWER_STATE *State']
		case 137: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtGetDevicePowerState_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetDevicePowerState_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 138 NTSTATUS NtGetMUIRegistryInfo ['ULONG Flags', ' PULONG DataSize', ' PVOID Data']
		case 138: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtGetMUIRegistryInfo_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetMUIRegistryInfo_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 139 NTSTATUS NtGetNextProcess ['HANDLE ProcessHandle', ' ACCESS_MASK DesiredAccess', ' ULONG HandleAttributes', ' ULONG Flags', ' PHANDLE NewProcessHandle']
		case 139: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtGetNextProcess_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetNextProcess_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 140 NTSTATUS NtGetNextThread ['HANDLE ProcessHandle', ' HANDLE ThreadHandle', ' ACCESS_MASK DesiredAccess', ' ULONG HandleAttributes', ' ULONG Flags', ' PHANDLE NewThreadHandle']
		case 140: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtGetNextThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetNextThread_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 141 NTSTATUS NtGetNlsSectionPtr ['ULONG SectionType', ' ULONG SectionData', ' PVOID ContextData', ' PVOID *SectionPointer', ' PULONG SectionSize']
		case 141: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtGetNlsSectionPtr_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetNlsSectionPtr_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 142 NTSTATUS NtGetNotificationResourceManager ['HANDLE ResourceManagerHandle', ' PTRANSACTION_NOTIFICATION TransactionNotification', ' ULONG NotificationLength', ' PLARGE_INTEGER Timeout', ' PULONG ReturnLength', ' ULONG Asynchronous', ' ULONG_PTR AsynchronousContext']
		case 142: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			if (PPP_CHECK_CB(on_NtGetNotificationResourceManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtGetNotificationResourceManager_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 143 NTSTATUS NtGetPlugPlayEvent ['HANDLE EventHandle', ' PVOID Context', ' PPLUGPLAY_EVENT_BLOCK EventBlock', ' ULONG EventBufferSize']
		case 143: {
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
		// 144 NTSTATUS NtGetWriteWatch ['HANDLE ProcessHandle', ' ULONG Flags', ' PVOID BaseAddress', ' SIZE_T RegionSize', ' PVOID *UserAddressArray', ' PULONG_PTR EntriesInUserAddressArray', ' PULONG Granularity']
		case 144: {
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
		// 145 NTSTATUS NtImpersonateAnonymousToken ['HANDLE ThreadHandle']
		case 145: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtImpersonateAnonymousToken_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtImpersonateAnonymousToken_return, cpu, pc, arg0) ;
		}; break;
		// 146 NTSTATUS NtImpersonateClientOfPort ['HANDLE PortHandle', ' PPORT_MESSAGE Message']
		case 146: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtImpersonateClientOfPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtImpersonateClientOfPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 147 NTSTATUS NtImpersonateThread ['HANDLE ServerThreadHandle', ' HANDLE ClientThreadHandle', ' PSECURITY_QUALITY_OF_SERVICE SecurityQos']
		case 147: {
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
		// 148 NTSTATUS NtInitializeNlsFiles ['PVOID *BaseAddress', ' PLCID DefaultLocaleId', ' PLARGE_INTEGER DefaultCasingTableSize']
		case 148: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtInitializeNlsFiles_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtInitializeNlsFiles_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 149 NTSTATUS NtInitializeRegistry ['USHORT BootCondition']
		case 149: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtInitializeRegistry_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtInitializeRegistry_return, cpu, pc, arg0) ;
		}; break;
		// 150 NTSTATUS NtInitiatePowerAction ['POWER_ACTION SystemAction', ' SYSTEM_POWER_STATE MinSystemState', ' ULONG Flags', ' BOOLEAN Asynchronous']
		case 150: {
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
		// 151 NTSTATUS NtIsProcessInJob ['HANDLE ProcessHandle', ' HANDLE JobHandle']
		case 151: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtIsProcessInJob_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtIsProcessInJob_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 152 BOOLEAN NtIsSystemResumeAutomatic ['']
		case 152: {
			if (PPP_CHECK_CB(on_NtIsSystemResumeAutomatic_return)) {
			}
			PPP_RUN_CB(on_NtIsSystemResumeAutomatic_return, cpu, pc) ;
		}; break;
		// 153 NTSTATUS NtIsUILanguageComitted ['']
		case 153: {
			if (PPP_CHECK_CB(on_NtIsUILanguageComitted_return)) {
			}
			PPP_RUN_CB(on_NtIsUILanguageComitted_return, cpu, pc) ;
		}; break;
		// 154 NTSTATUS NtListenPort ['HANDLE PortHandle', ' PPORT_MESSAGE ConnectionRequest']
		case 154: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtListenPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtListenPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 155 NTSTATUS NtLoadDriver ['PUNICODE_STRING DriverServiceName']
		case 155: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtLoadDriver_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLoadDriver_return, cpu, pc, arg0) ;
		}; break;
		// 156 NTSTATUS NtLoadKey ['POBJECT_ATTRIBUTES TargetKey', ' POBJECT_ATTRIBUTES SourceFile']
		case 156: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtLoadKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLoadKey_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 157 NTSTATUS NtLoadKey2 ['POBJECT_ATTRIBUTES TargetKey', ' POBJECT_ATTRIBUTES SourceFile', ' ULONG Flags']
		case 157: {
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
		// 158 NTSTATUS NtLoadKeyEx ['POBJECT_ATTRIBUTES TargetKey', ' POBJECT_ATTRIBUTES SourceFile', ' ULONG Flags', ' HANDLE TrustClassKey ']
		case 158: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtLoadKeyEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLoadKeyEx_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 159 NTSTATUS NtLockFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PLARGE_INTEGER ByteOffset', ' PLARGE_INTEGER Length', ' ULONG Key', ' BOOLEAN FailImmediately', ' BOOLEAN ExclusiveLock']
		case 159: {
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
		// 160 NTSTATUS NtLockProductActivationKeys ['ULONG *pPrivateVer', ' ULONG *pSafeMode']
		case 160: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtLockProductActivationKeys_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLockProductActivationKeys_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 161 NTSTATUS NtLockRegistryKey ['HANDLE KeyHandle']
		case 161: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtLockRegistryKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtLockRegistryKey_return, cpu, pc, arg0) ;
		}; break;
		// 162 NTSTATUS NtLockVirtualMemory ['HANDLE ProcessHandle', ' PVOID *BaseAddress', ' PSIZE_T RegionSize', ' ULONG MapType']
		case 162: {
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
		// 163 NTSTATUS NtMakePermanentObject ['HANDLE Handle']
		case 163: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtMakePermanentObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtMakePermanentObject_return, cpu, pc, arg0) ;
		}; break;
		// 164 NTSTATUS NtMakeTemporaryObject ['HANDLE Handle']
		case 164: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtMakeTemporaryObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtMakeTemporaryObject_return, cpu, pc, arg0) ;
		}; break;
		// 165 NTSTATUS NtMapCMFModule ['ULONG What', ' ULONG Index', ' PULONG CacheIndexOut', ' PULONG CacheFlagsOut', ' PULONG ViewSizeOut', ' PVOID *BaseAddress']
		case 165: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtMapCMFModule_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtMapCMFModule_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 166 NTSTATUS NtMapUserPhysicalPages ['PVOID VirtualAddress', ' ULONG_PTR NumberOfPages', ' PULONG_PTR UserPfnArray']
		case 166: {
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
		// 167 NTSTATUS NtMapUserPhysicalPagesScatter ['PVOID *VirtualAddresses', ' ULONG_PTR NumberOfPages', ' PULONG_PTR UserPfnArray']
		case 167: {
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
		// 168 NTSTATUS NtMapViewOfSection ['HANDLE SectionHandle', ' HANDLE ProcessHandle', ' PVOID *BaseAddress', ' ULONG_PTR ZeroBits', ' SIZE_T CommitSize', ' PLARGE_INTEGER SectionOffset', ' PSIZE_T ViewSize', ' SECTION_INHERIT InheritDisposition', ' ULONG AllocationType', ' WIN32_PROTECTION_MASK Win32Protect']
		case 168: {
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
		// 169 NTSTATUS NtModifyBootEntry ['PBOOT_ENTRY BootEntry']
		case 169: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtModifyBootEntry_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtModifyBootEntry_return, cpu, pc, arg0) ;
		}; break;
		// 170 NTSTATUS NtModifyDriverEntry ['PEFI_DRIVER_ENTRY DriverEntry']
		case 170: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtModifyDriverEntry_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtModifyDriverEntry_return, cpu, pc, arg0) ;
		}; break;
		// 171 NTSTATUS NtNotifyChangeDirectoryFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' ULONG CompletionFilter', ' BOOLEAN WatchTree']
		case 171: {
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
		// 172 NTSTATUS NtNotifyChangeKey ['HANDLE KeyHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG CompletionFilter', ' BOOLEAN WatchTree', ' PVOID Buffer', ' ULONG BufferSize', ' BOOLEAN Asynchronous']
		case 172: {
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
		// 173 NTSTATUS NtNotifyChangeMultipleKeys ['HANDLE MasterKeyHandle', ' ULONG Count', ' OBJECT_ATTRIBUTES SlaveObjects[]', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG CompletionFilter', ' BOOLEAN WatchTree', ' PVOID Buffer', ' ULONG BufferSize', ' BOOLEAN Asynchronous']
		case 173: {
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
		// 174 NTSTATUS NtNotifyChangeSession ['HANDLE Session', ' ULONG IoStateSequence', ' PVOID Reserved', ' ULONG Action', ' IO_SESSION_STATE IoState', ' IO_SESSION_STATE IoState2', ' PVOID Buffer', ' ULONG BufferSize']
		case 174: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			uint32_t arg6;
			uint32_t arg7;
			if (PPP_CHECK_CB(on_NtNotifyChangeSession_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
				memcpy(&arg6, rp.params[6], sizeof(uint32_t));
				memcpy(&arg7, rp.params[7], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtNotifyChangeSession_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) ;
		}; break;
		// 175 NTSTATUS NtOpenDirectoryObject ['PHANDLE DirectoryHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 175: {
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
		// 176 NTSTATUS NtOpenEnlistment ['PHANDLE EnlistmentHandle', ' ACCESS_MASK DesiredAccess', ' HANDLE ResourceManagerHandle', ' LPGUID EnlistmentGuid', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 176: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtOpenEnlistment_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenEnlistment_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 177 NTSTATUS NtOpenEvent ['PHANDLE EventHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 177: {
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
		// 178 NTSTATUS NtOpenEventPair ['PHANDLE EventPairHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 178: {
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
		// 179 NTSTATUS NtOpenFile ['PHANDLE FileHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG ShareAccess', ' ULONG OpenOptions']
		case 179: {
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
		// 180 NTSTATUS NtOpenIoCompletion ['PHANDLE IoCompletionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 180: {
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
		// 181 NTSTATUS NtOpenJobObject ['PHANDLE JobHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 181: {
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
		// 182 NTSTATUS NtOpenKey ['PHANDLE KeyHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 182: {
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
		// 183 NTSTATUS NtOpenKeyEx ['PHANDLE KeyHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG OpenOptions']
		case 183: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtOpenKeyEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenKeyEx_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 184 NTSTATUS NtOpenKeyedEvent ['PHANDLE KeyedEventHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 184: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenKeyedEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenKeyedEvent_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 185 NTSTATUS NtOpenKeyTransacted ['PHANDLE KeyHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE TransactionHandle']
		case 185: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtOpenKeyTransacted_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenKeyTransacted_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 186 NTSTATUS NtOpenKeyTransactedEx ['PHANDLE KeyHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG OpenOptions', ' HANDLE TransactionHandle']
		case 186: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtOpenKeyTransactedEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenKeyTransactedEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 187 NTSTATUS NtOpenMutant ['PHANDLE MutantHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 187: {
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
		// 188 NTSTATUS NtOpenObjectAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' PUNICODE_STRING ObjectTypeName', ' PUNICODE_STRING ObjectName', ' PSECURITY_DESCRIPTOR SecurityDescriptor', ' HANDLE ClientToken', ' ACCESS_MASK DesiredAccess', ' ACCESS_MASK GrantedAccess', ' PPRIVILEGE_SET Privileges', ' BOOLEAN ObjectCreation', ' BOOLEAN AccessGranted', ' PBOOLEAN GenerateOnClose']
		case 188: {
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
		// 189 NTSTATUS NtOpenPrivateNamespace ['PHANDLE NamespaceHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PVOID BoundaryDescriptor']
		case 189: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtOpenPrivateNamespace_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenPrivateNamespace_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 190 NTSTATUS NtOpenProcess ['PHANDLE ProcessHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PCLIENT_ID ClientId']
		case 190: {
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
		// 191 NTSTATUS NtOpenProcessToken ['HANDLE ProcessHandle', ' ACCESS_MASK DesiredAccess', ' PHANDLE TokenHandle']
		case 191: {
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
		// 192 NTSTATUS NtOpenProcessTokenEx ['HANDLE ProcessHandle', ' ACCESS_MASK DesiredAccess', ' ULONG HandleAttributes', ' PHANDLE TokenHandle']
		case 192: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtOpenProcessTokenEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenProcessTokenEx_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 193 NTSTATUS NtOpenResourceManager ['PHANDLE ResourceManagerHandle', ' ACCESS_MASK DesiredAccess', ' HANDLE TmHandle', ' LPGUID ResourceManagerGuid', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 193: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtOpenResourceManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenResourceManager_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 194 NTSTATUS NtOpenSection ['PHANDLE SectionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 194: {
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
		// 195 NTSTATUS NtOpenSemaphore ['PHANDLE SemaphoreHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 195: {
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
		// 196 NTSTATUS NtOpenSession ['PHANDLE SessionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 196: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtOpenSession_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenSession_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 197 NTSTATUS NtOpenSymbolicLinkObject ['PHANDLE LinkHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 197: {
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
		// 198 NTSTATUS NtOpenThread ['PHANDLE ThreadHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PCLIENT_ID ClientId']
		case 198: {
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
		// 199 NTSTATUS NtOpenThreadToken ['HANDLE ThreadHandle', ' ACCESS_MASK DesiredAccess', ' BOOLEAN OpenAsSelf', ' PHANDLE TokenHandle']
		case 199: {
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
		// 200 NTSTATUS NtOpenThreadTokenEx ['HANDLE ThreadHandle', ' ACCESS_MASK DesiredAccess', ' BOOLEAN OpenAsSelf', ' ULONG HandleAttributes', ' PHANDLE TokenHandle']
		case 200: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtOpenThreadTokenEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenThreadTokenEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 201 NTSTATUS NtOpenTimer ['PHANDLE TimerHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
		case 201: {
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
		// 202 NTSTATUS NtOpenTransaction ['PHANDLE TransactionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' LPGUID Uow', ' HANDLE TmHandle']
		case 202: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtOpenTransaction_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenTransaction_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 203 NTSTATUS NtOpenTransactionManager ['PHANDLE TmHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PUNICODE_STRING LogFileName', ' LPGUID TmIdentity', ' ULONG OpenOptions']
		case 203: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtOpenTransactionManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtOpenTransactionManager_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 204 NTSTATUS NtPlugPlayControl ['PLUGPLAY_CONTROL_CLASS PnPControlClass', ' PVOID PnPControlData', ' ULONG PnPControlDataLength']
		case 204: {
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
		// 205 NTSTATUS NtPowerInformation ['POWER_INFORMATION_LEVEL InformationLevel', ' PVOID InputBuffer', ' ULONG InputBufferLength', ' PVOID OutputBuffer', ' ULONG OutputBufferLength']
		case 205: {
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
		// 206 NTSTATUS NtPrepareComplete ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
		case 206: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtPrepareComplete_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPrepareComplete_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 207 NTSTATUS NtPrepareEnlistment ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
		case 207: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtPrepareEnlistment_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPrepareEnlistment_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 208 NTSTATUS NtPrePrepareComplete ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
		case 208: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtPrePrepareComplete_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPrePrepareComplete_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 209 NTSTATUS NtPrePrepareEnlistment ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
		case 209: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtPrePrepareEnlistment_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPrePrepareEnlistment_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 210 NTSTATUS NtPrivilegeCheck ['HANDLE ClientToken', ' PPRIVILEGE_SET RequiredPrivileges', ' PBOOLEAN Result']
		case 210: {
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
		// 211 NTSTATUS NtPrivilegedServiceAuditAlarm ['PUNICODE_STRING SubsystemName', ' PUNICODE_STRING ServiceName', ' HANDLE ClientToken', ' PPRIVILEGE_SET Privileges', ' BOOLEAN AccessGranted']
		case 211: {
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
		// 212 NTSTATUS NtPrivilegeObjectAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' HANDLE ClientToken', ' ACCESS_MASK DesiredAccess', ' PPRIVILEGE_SET Privileges', ' BOOLEAN AccessGranted']
		case 212: {
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
		// 213 NTSTATUS NtPropagationComplete ['HANDLE ResourceManagerHandle', ' ULONG RequestCookie', ' ULONG BufferLength', ' PVOID Buffer']
		case 213: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtPropagationComplete_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPropagationComplete_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 214 NTSTATUS NtPropagationFailed ['HANDLE ResourceManagerHandle', ' ULONG RequestCookie', ' NTSTATUS PropStatus']
		case 214: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtPropagationFailed_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPropagationFailed_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 215 NTSTATUS NtProtectVirtualMemory ['HANDLE ProcessHandle', ' PVOID *BaseAddress', ' PSIZE_T RegionSize', ' WIN32_PROTECTION_MASK NewProtectWin32', ' PULONG OldProtect']
		case 215: {
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
		// 216 NTSTATUS NtPulseEvent ['HANDLE EventHandle', ' PLONG PreviousState']
		case 216: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtPulseEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtPulseEvent_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 217 NTSTATUS NtQueryAttributesFile ['POBJECT_ATTRIBUTES ObjectAttributes', ' PFILE_BASIC_INFORMATION FileInformation']
		case 217: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryAttributesFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryAttributesFile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 218 NTSTATUS NtQueryBootEntryOrder ['PULONG Ids', ' PULONG Count']
		case 218: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryBootEntryOrder_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryBootEntryOrder_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 219 NTSTATUS NtQueryBootOptions ['PBOOT_OPTIONS BootOptions', ' PULONG BootOptionsLength']
		case 219: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryBootOptions_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryBootOptions_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 220 NTSTATUS NtQueryDebugFilterState ['ULONG ComponentId', ' ULONG Level']
		case 220: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryDebugFilterState_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDebugFilterState_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 221 NTSTATUS NtQueryDefaultLocale ['BOOLEAN UserProfile', ' PLCID DefaultLocaleId']
		case 221: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryDefaultLocale_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDefaultLocale_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 222 NTSTATUS NtQueryDefaultUILanguage ['LANGID *DefaultUILanguageId']
		case 222: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtQueryDefaultUILanguage_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDefaultUILanguage_return, cpu, pc, arg0) ;
		}; break;
		// 223 NTSTATUS NtQueryDirectoryFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FileInformation', ' ULONG Length', ' FILE_INFORMATION_CLASS FileInformationClass', ' BOOLEAN ReturnSingleEntry', ' PUNICODE_STRING FileName', ' BOOLEAN RestartScan']
		case 223: {
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
		// 224 NTSTATUS NtQueryDirectoryObject ['HANDLE DirectoryHandle', ' PVOID Buffer', ' ULONG Length', ' BOOLEAN ReturnSingleEntry', ' BOOLEAN RestartScan', ' PULONG Context', ' PULONG ReturnLength']
		case 224: {
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
		// 225 NTSTATUS NtQueryDriverEntryOrder ['PULONG Ids', ' PULONG Count']
		case 225: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryDriverEntryOrder_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryDriverEntryOrder_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 226 NTSTATUS NtQueryEaFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' BOOLEAN ReturnSingleEntry', ' PVOID EaList', ' ULONG EaListLength', ' PULONG EaIndex', ' BOOLEAN RestartScan']
		case 226: {
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
		// 227 NTSTATUS NtQueryEvent ['HANDLE EventHandle', ' EVENT_INFORMATION_CLASS EventInformationClass', ' PVOID EventInformation', ' ULONG EventInformationLength', ' PULONG ReturnLength']
		case 227: {
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
		// 228 NTSTATUS NtQueryFullAttributesFile ['POBJECT_ATTRIBUTES ObjectAttributes', ' PFILE_NETWORK_OPEN_INFORMATION FileInformation']
		case 228: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryFullAttributesFile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryFullAttributesFile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 229 NTSTATUS NtQueryInformationAtom ['RTL_ATOM Atom', ' ATOM_INFORMATION_CLASS InformationClass', ' PVOID AtomInformation', ' ULONG AtomInformationLength', ' PULONG ReturnLength']
		case 229: {
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
		// 230 NTSTATUS NtQueryInformationEnlistment ['HANDLE EnlistmentHandle', ' ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass', ' PVOID EnlistmentInformation', ' ULONG EnlistmentInformationLength', ' PULONG ReturnLength']
		case 230: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationEnlistment_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationEnlistment_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 231 NTSTATUS NtQueryInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FileInformation', ' ULONG Length', ' FILE_INFORMATION_CLASS FileInformationClass']
		case 231: {
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
		// 232 NTSTATUS NtQueryInformationJobObject ['HANDLE JobHandle', ' JOBOBJECTINFOCLASS JobObjectInformationClass', ' PVOID JobObjectInformation', ' ULONG JobObjectInformationLength', ' PULONG ReturnLength']
		case 232: {
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
		// 233 NTSTATUS NtQueryInformationPort ['HANDLE PortHandle', ' PORT_INFORMATION_CLASS PortInformationClass', ' PVOID PortInformation', ' ULONG Length', ' PULONG ReturnLength']
		case 233: {
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
		// 234 NTSTATUS NtQueryInformationProcess ['HANDLE ProcessHandle', ' PROCESSINFOCLASS ProcessInformationClass', ' PVOID ProcessInformation', ' ULONG ProcessInformationLength', ' PULONG ReturnLength']
		case 234: {
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
		// 235 NTSTATUS NtQueryInformationResourceManager ['HANDLE ResourceManagerHandle', ' RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass', ' PVOID ResourceManagerInformation', ' ULONG ResourceManagerInformationLength', ' PULONG ReturnLength']
		case 235: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationResourceManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationResourceManager_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 236 NTSTATUS NtQueryInformationThread ['HANDLE ThreadHandle', ' THREADINFOCLASS ThreadInformationClass', ' PVOID ThreadInformation', ' ULONG ThreadInformationLength', ' PULONG ReturnLength']
		case 236: {
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
		// 237 NTSTATUS NtQueryInformationToken ['HANDLE TokenHandle', ' TOKEN_INFORMATION_CLASS TokenInformationClass', ' PVOID TokenInformation', ' ULONG TokenInformationLength', ' PULONG ReturnLength']
		case 237: {
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
		// 238 NTSTATUS NtQueryInformationTransaction ['HANDLE TransactionHandle', ' TRANSACTION_INFORMATION_CLASS TransactionInformationClass', ' PVOID TransactionInformation', ' ULONG TransactionInformationLength', ' PULONG ReturnLength']
		case 238: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationTransaction_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationTransaction_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 239 NTSTATUS NtQueryInformationTransactionManager ['HANDLE TransactionManagerHandle', ' TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass', ' PVOID TransactionManagerInformation', ' ULONG TransactionManagerInformationLength', ' PULONG ReturnLength']
		case 239: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationTransactionManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationTransactionManager_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 240 NTSTATUS NtQueryInformationWorkerFactory ['HANDLE WorkerFactoryHandle', ' WORKERFACTORYINFOCLASS WorkerFactoryInformationClass', ' PVOID WorkerFactoryInformation', ' ULONG WorkerFactoryInformationLength', ' PULONG ReturnLength']
		case 240: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryInformationWorkerFactory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInformationWorkerFactory_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 241 NTSTATUS NtQueryInstallUILanguage ['LANGID *InstallUILanguageId']
		case 241: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtQueryInstallUILanguage_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryInstallUILanguage_return, cpu, pc, arg0) ;
		}; break;
		// 242 NTSTATUS NtQueryIntervalProfile ['KPROFILE_SOURCE ProfileSource', ' PULONG Interval']
		case 242: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryIntervalProfile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryIntervalProfile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 243 NTSTATUS NtQueryIoCompletion ['HANDLE IoCompletionHandle', ' IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass', ' PVOID IoCompletionInformation', ' ULONG IoCompletionInformationLength', ' PULONG ReturnLength']
		case 243: {
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
		// 244 NTSTATUS NtQueryKey ['HANDLE KeyHandle', ' KEY_INFORMATION_CLASS KeyInformationClass', ' PVOID KeyInformation', ' ULONG Length', ' PULONG ResultLength']
		case 244: {
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
		// 245 NTSTATUS NtQueryLicenseValue ['PUNICODE_STRING Name', ' PULONG Type', ' PVOID Buffer', ' ULONG Length', ' PULONG ReturnedLength']
		case 245: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQueryLicenseValue_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryLicenseValue_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 246 NTSTATUS NtQueryMultipleValueKey ['HANDLE KeyHandle', ' PKEY_VALUE_ENTRY ValueEntries', ' ULONG EntryCount', ' PVOID ValueBuffer', ' PULONG BufferLength', ' PULONG RequiredBufferLength']
		case 246: {
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
		// 247 NTSTATUS NtQueryMutant ['HANDLE MutantHandle', ' MUTANT_INFORMATION_CLASS MutantInformationClass', ' PVOID MutantInformation', ' ULONG MutantInformationLength', ' PULONG ReturnLength']
		case 247: {
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
		// 248 NTSTATUS NtQueryObject ['HANDLE Handle', ' OBJECT_INFORMATION_CLASS ObjectInformationClass', ' PVOID ObjectInformation', ' ULONG ObjectInformationLength', ' PULONG ReturnLength']
		case 248: {
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
		// 249 NTSTATUS NtQueryOpenSubKeys ['POBJECT_ATTRIBUTES TargetKey', ' PULONG HandleCount']
		case 249: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryOpenSubKeys_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryOpenSubKeys_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 250 NTSTATUS NtQueryOpenSubKeysEx ['POBJECT_ATTRIBUTES TargetKey', ' ULONG BufferLength', ' PVOID Buffer', ' PULONG RequiredSize']
		case 250: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtQueryOpenSubKeysEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryOpenSubKeysEx_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 251 NTSTATUS NtQueryPerformanceCounter ['PLARGE_INTEGER PerformanceCounter', ' PLARGE_INTEGER PerformanceFrequency']
		case 251: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtQueryPerformanceCounter_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueryPerformanceCounter_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 252 NTSTATUS NtQueryPortInformationProcess ['']
		case 252: {
			if (PPP_CHECK_CB(on_NtQueryPortInformationProcess_return)) {
			}
			PPP_RUN_CB(on_NtQueryPortInformationProcess_return, cpu, pc) ;
		}; break;
		// 253 NTSTATUS NtQueryQuotaInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' BOOLEAN ReturnSingleEntry', ' PVOID SidList', ' ULONG SidListLength', ' PULONG StartSid', ' BOOLEAN RestartScan']
		case 253: {
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
		// 254 NTSTATUS NtQuerySection ['HANDLE SectionHandle', ' SECTION_INFORMATION_CLASS SectionInformationClass', ' PVOID SectionInformation', ' SIZE_T SectionInformationLength', ' PSIZE_T ReturnLength']
		case 254: {
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
		// 255 NTSTATUS NtQuerySecurityAttributesToken ['HANDLE TokenHandle', ' PUNICODE_STRING Attributes', ' ULONG NumberOfAttributes', ' PVOID Buffer', ' ULONG Length', ' PULONG ReturnLength']
		case 255: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtQuerySecurityAttributesToken_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySecurityAttributesToken_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 256 NTSTATUS NtQuerySecurityObject ['HANDLE Handle', ' SECURITY_INFORMATION SecurityInformation', ' PSECURITY_DESCRIPTOR SecurityDescriptor', ' ULONG Length', ' PULONG LengthNeeded']
		case 256: {
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
		// 257 NTSTATUS NtQuerySemaphore ['HANDLE SemaphoreHandle', ' SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass', ' PVOID SemaphoreInformation', ' ULONG SemaphoreInformationLength', ' PULONG ReturnLength']
		case 257: {
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
		// 258 NTSTATUS NtQuerySymbolicLinkObject ['HANDLE LinkHandle', ' PUNICODE_STRING LinkTarget', ' PULONG ReturnedLength']
		case 258: {
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
		// 259 NTSTATUS NtQuerySystemEnvironmentValue ['PUNICODE_STRING VariableName', ' PWSTR VariableValue', ' USHORT ValueLength', ' PUSHORT ReturnLength']
		case 259: {
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
		// 260 NTSTATUS NtQuerySystemEnvironmentValueEx ['PUNICODE_STRING VariableName', ' LPGUID VendorGuid', ' PVOID Value', ' PULONG ValueLength', ' PULONG Attributes']
		case 260: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtQuerySystemEnvironmentValueEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySystemEnvironmentValueEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 261 NTSTATUS NtQuerySystemInformation ['SYSTEM_INFORMATION_CLASS SystemInformationClass', ' PVOID SystemInformation', ' ULONG SystemInformationLength', ' PULONG ReturnLength']
		case 261: {
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
		// 262 NTSTATUS NtQuerySystemInformationEx ['SYSTEM_INFORMATION_CLASS SystemInformationClass', ' PVOID QueryInformation', ' ULONG QueryInformationLength', ' PVOID SystemInformation', ' ULONG SystemInformationLength', ' PULONG ReturnLength']
		case 262: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtQuerySystemInformationEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySystemInformationEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 263 NTSTATUS NtQuerySystemTime ['PLARGE_INTEGER SystemTime']
		case 263: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtQuerySystemTime_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQuerySystemTime_return, cpu, pc, arg0) ;
		}; break;
		// 264 NTSTATUS NtQueryTimer ['HANDLE TimerHandle', ' TIMER_INFORMATION_CLASS TimerInformationClass', ' PVOID TimerInformation', ' ULONG TimerInformationLength', ' PULONG ReturnLength']
		case 264: {
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
		// 265 NTSTATUS NtQueryTimerResolution ['PULONG MaximumTime', ' PULONG MinimumTime', ' PULONG CurrentTime']
		case 265: {
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
		// 266 NTSTATUS NtQueryValueKey ['HANDLE KeyHandle', ' PUNICODE_STRING ValueName', ' KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass', ' PVOID KeyValueInformation', ' ULONG Length', ' PULONG ResultLength']
		case 266: {
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
		// 267 NTSTATUS NtQueryVirtualMemory ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' MEMORY_INFORMATION_CLASS MemoryInformationClass', ' PVOID MemoryInformation', ' SIZE_T MemoryInformationLength', ' PSIZE_T ReturnLength']
		case 267: {
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
		// 268 NTSTATUS NtQueryVolumeInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FsInformation', ' ULONG Length', ' FS_INFORMATION_CLASS FsInformationClass']
		case 268: {
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
		// 269 NTSTATUS NtQueueApcThread ['HANDLE ThreadHandle', ' PPS_APC_ROUTINE ApcRoutine', ' PVOID ApcArgument1', ' PVOID ApcArgument2', ' PVOID ApcArgument3']
		case 269: {
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
		// 270 NTSTATUS NtQueueApcThreadEx ['HANDLE ThreadHandle', ' HANDLE UserApcReserveHandle', ' PPS_APC_ROUTINE ApcRoutine', ' PVOID ApcArgument1', ' PVOID ApcArgument2', ' PVOID ApcArgument3']
		case 270: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtQueueApcThreadEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtQueueApcThreadEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 271 NTSTATUS NtRaiseException ['PEXCEPTION_RECORD ExceptionRecord', ' PCONTEXT ContextRecord', ' BOOLEAN FirstChance']
		case 271: {
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
		// 272 NTSTATUS NtRaiseHardError ['NTSTATUS ErrorStatus', ' ULONG NumberOfParameters', ' ULONG UnicodeStringParameterMask', ' PULONG_PTR Parameters', ' ULONG ValidResponseOptions', ' PULONG Response']
		case 272: {
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
		// 273 NTSTATUS NtReadFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' PLARGE_INTEGER ByteOffset', ' PULONG Key']
		case 273: {
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
		// 274 NTSTATUS NtReadFileScatter ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PFILE_SEGMENT_ELEMENT SegmentArray', ' ULONG Length', ' PLARGE_INTEGER ByteOffset', ' PULONG Key']
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
		// 275 NTSTATUS NtReadOnlyEnlistment ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
		case 275: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtReadOnlyEnlistment_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReadOnlyEnlistment_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 276 NTSTATUS NtReadRequestData ['HANDLE PortHandle', ' PPORT_MESSAGE Message', ' ULONG DataEntryIndex', ' PVOID Buffer', ' SIZE_T BufferSize', ' PSIZE_T NumberOfBytesRead']
		case 276: {
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
		// 277 NTSTATUS NtReadVirtualMemory ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' PVOID Buffer', ' SIZE_T BufferSize', ' PSIZE_T NumberOfBytesRead']
		case 277: {
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
		// 278 NTSTATUS NtRecoverEnlistment ['HANDLE EnlistmentHandle', ' PVOID EnlistmentKey']
		case 278: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRecoverEnlistment_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRecoverEnlistment_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 279 NTSTATUS NtRecoverResourceManager ['HANDLE ResourceManagerHandle']
		case 279: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtRecoverResourceManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRecoverResourceManager_return, cpu, pc, arg0) ;
		}; break;
		// 280 NTSTATUS NtRecoverTransactionManager ['HANDLE TransactionManagerHandle']
		case 280: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtRecoverTransactionManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRecoverTransactionManager_return, cpu, pc, arg0) ;
		}; break;
		// 281 NTSTATUS NtRegisterProtocolAddressInformation ['HANDLE ResourceManager', ' PCRM_PROTOCOL_ID ProtocolId', ' ULONG ProtocolInformationSize', ' PVOID ProtocolInformation', ' ULONG CreateOptions']
		case 281: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtRegisterProtocolAddressInformation_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRegisterProtocolAddressInformation_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 282 NTSTATUS NtRegisterThreadTerminatePort ['HANDLE PortHandle']
		case 282: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtRegisterThreadTerminatePort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRegisterThreadTerminatePort_return, cpu, pc, arg0) ;
		}; break;
		// 283 NTSTATUS NtReleaseKeyedEvent ['HANDLE KeyedEventHandle', ' PVOID KeyValue', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout']
		case 283: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtReleaseKeyedEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReleaseKeyedEvent_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 284 NTSTATUS NtReleaseMutant ['HANDLE MutantHandle', ' PLONG PreviousCount']
		case 284: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtReleaseMutant_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReleaseMutant_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 285 NTSTATUS NtReleaseSemaphore ['HANDLE SemaphoreHandle', ' LONG ReleaseCount', ' PLONG PreviousCount']
		case 285: {
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
		// 286 NTSTATUS NtReleaseWorkerFactoryWorker ['HANDLE WorkerFactoryHandle']
		case 286: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtReleaseWorkerFactoryWorker_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReleaseWorkerFactoryWorker_return, cpu, pc, arg0) ;
		}; break;
		// 287 NTSTATUS NtRemoveIoCompletion ['HANDLE IoCompletionHandle', ' PVOID *KeyContext', ' PVOID *ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PLARGE_INTEGER Timeout']
		case 287: {
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
		// 288 NTSTATUS NtRemoveIoCompletionEx ['HANDLE IoCompletionHandle', ' PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation', ' ULONG Count', ' PULONG NumEntriesRemoved', ' PLARGE_INTEGER Timeout', ' BOOLEAN Alertable']
		case 288: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtRemoveIoCompletionEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRemoveIoCompletionEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 289 NTSTATUS NtRemoveProcessDebug ['HANDLE ProcessHandle', ' HANDLE DebugObjectHandle']
		case 289: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRemoveProcessDebug_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRemoveProcessDebug_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 290 NTSTATUS NtRenameKey ['HANDLE KeyHandle', ' PUNICODE_STRING NewName']
		case 290: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRenameKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRenameKey_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 291 NTSTATUS NtRenameTransactionManager ['PUNICODE_STRING LogFileName', ' LPGUID ExistingTransactionManagerGuid']
		case 291: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRenameTransactionManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRenameTransactionManager_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 292 NTSTATUS NtReplaceKey ['POBJECT_ATTRIBUTES NewFile', ' HANDLE TargetHandle', ' POBJECT_ATTRIBUTES OldFile']
		case 292: {
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
		// 293 NTSTATUS NtReplacePartitionUnit ['PUNICODE_STRING TargetInstancePath', ' PUNICODE_STRING SpareInstancePath', ' ULONG Flags']
		case 293: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtReplacePartitionUnit_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplacePartitionUnit_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 294 NTSTATUS NtReplyPort ['HANDLE PortHandle', ' PPORT_MESSAGE ReplyMessage']
		case 294: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtReplyPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplyPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 295 NTSTATUS NtReplyWaitReceivePort ['HANDLE PortHandle', ' PVOID *PortContext ', ' PPORT_MESSAGE ReplyMessage', ' PPORT_MESSAGE ReceiveMessage']
		case 295: {
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
		// 296 NTSTATUS NtReplyWaitReceivePortEx ['HANDLE PortHandle', ' PVOID *PortContext', ' PPORT_MESSAGE ReplyMessage', ' PPORT_MESSAGE ReceiveMessage', ' PLARGE_INTEGER Timeout']
		case 296: {
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
		// 297 NTSTATUS NtReplyWaitReplyPort ['HANDLE PortHandle', ' PPORT_MESSAGE ReplyMessage']
		case 297: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtReplyWaitReplyPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtReplyWaitReplyPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 298 NTSTATUS NtRequestPort ['HANDLE PortHandle', ' PPORT_MESSAGE RequestMessage']
		case 298: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRequestPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRequestPort_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 299 NTSTATUS NtRequestWaitReplyPort ['HANDLE PortHandle', ' PPORT_MESSAGE RequestMessage', ' PPORT_MESSAGE ReplyMessage']
		case 299: {
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
		// 300 NTSTATUS NtResetEvent ['HANDLE EventHandle', ' PLONG PreviousState']
		case 300: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtResetEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtResetEvent_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 301 NTSTATUS NtResetWriteWatch ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' SIZE_T RegionSize']
		case 301: {
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
		// 302 NTSTATUS NtRestoreKey ['HANDLE KeyHandle', ' HANDLE FileHandle', ' ULONG Flags']
		case 302: {
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
		// 303 NTSTATUS NtResumeProcess ['HANDLE ProcessHandle']
		case 303: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtResumeProcess_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtResumeProcess_return, cpu, pc, arg0) ;
		}; break;
		// 304 NTSTATUS NtResumeThread ['HANDLE ThreadHandle', ' PULONG PreviousSuspendCount']
		case 304: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtResumeThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtResumeThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 305 NTSTATUS NtRollbackComplete ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
		case 305: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRollbackComplete_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRollbackComplete_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 306 NTSTATUS NtRollbackEnlistment ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
		case 306: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRollbackEnlistment_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRollbackEnlistment_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 307 NTSTATUS NtRollbackTransaction ['HANDLE TransactionHandle', ' BOOLEAN Wait']
		case 307: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRollbackTransaction_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRollbackTransaction_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 308 NTSTATUS NtRollforwardTransactionManager ['HANDLE TransactionManagerHandle', ' PLARGE_INTEGER TmVirtualClock']
		case 308: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtRollforwardTransactionManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtRollforwardTransactionManager_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 309 NTSTATUS NtSaveKey ['HANDLE KeyHandle', ' HANDLE FileHandle']
		case 309: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSaveKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSaveKey_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 310 NTSTATUS NtSaveKeyEx ['HANDLE KeyHandle', ' HANDLE FileHandle', ' ULONG Format']
		case 310: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSaveKeyEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSaveKeyEx_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 311 NTSTATUS NtSaveMergedKeys ['HANDLE HighPrecedenceKeyHandle', ' HANDLE LowPrecedenceKeyHandle', ' HANDLE FileHandle']
		case 311: {
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
		// 312 NTSTATUS NtSecureConnectPort ['PHANDLE PortHandle', ' PUNICODE_STRING PortName', ' PSECURITY_QUALITY_OF_SERVICE SecurityQos', ' PPORT_VIEW ClientView', ' PSID RequiredServerSid', ' PREMOTE_PORT_VIEW ServerView', ' PULONG MaxMessageLength', ' PVOID ConnectionInformation', ' PULONG ConnectionInformationLength']
		case 312: {
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
		// 313 NTSTATUS NtSerializeBoot ['']
		case 313: {
			if (PPP_CHECK_CB(on_NtSerializeBoot_return)) {
			}
			PPP_RUN_CB(on_NtSerializeBoot_return, cpu, pc) ;
		}; break;
		// 314 NTSTATUS NtSetBootEntryOrder ['PULONG Ids', ' ULONG Count']
		case 314: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetBootEntryOrder_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetBootEntryOrder_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 315 NTSTATUS NtSetBootOptions ['PBOOT_OPTIONS BootOptions', ' ULONG FieldsToChange']
		case 315: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetBootOptions_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetBootOptions_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 316 NTSTATUS NtSetContextThread ['HANDLE ThreadHandle', ' PCONTEXT ThreadContext']
		case 316: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetContextThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetContextThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 317 NTSTATUS NtSetDebugFilterState ['ULONG ComponentId', ' ULONG Level', ' BOOLEAN State']
		case 317: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_NtSetDebugFilterState_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetDebugFilterState_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 318 NTSTATUS NtSetDefaultHardErrorPort ['HANDLE DefaultHardErrorPort']
		case 318: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetDefaultHardErrorPort_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetDefaultHardErrorPort_return, cpu, pc, arg0) ;
		}; break;
		// 319 NTSTATUS NtSetDefaultLocale ['BOOLEAN UserProfile', ' LCID DefaultLocaleId']
		case 319: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetDefaultLocale_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetDefaultLocale_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 320 NTSTATUS NtSetDefaultUILanguage ['LANGID DefaultUILanguageId']
		case 320: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetDefaultUILanguage_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetDefaultUILanguage_return, cpu, pc, arg0) ;
		}; break;
		// 321 NTSTATUS NtSetDriverEntryOrder ['PULONG Ids', ' ULONG Count']
		case 321: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetDriverEntryOrder_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetDriverEntryOrder_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 322 NTSTATUS NtSetEaFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length']
		case 322: {
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
		// 323 NTSTATUS NtSetEvent ['HANDLE EventHandle', ' PLONG PreviousState']
		case 323: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetEvent_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 324 NTSTATUS NtSetEventBoostPriority ['HANDLE EventHandle']
		case 324: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetEventBoostPriority_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetEventBoostPriority_return, cpu, pc, arg0) ;
		}; break;
		// 325 NTSTATUS NtSetHighEventPair ['HANDLE EventPairHandle']
		case 325: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetHighEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetHighEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 326 NTSTATUS NtSetHighWaitLowEventPair ['HANDLE EventPairHandle']
		case 326: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetHighWaitLowEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetHighWaitLowEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 327 NTSTATUS NtSetInformationDebugObject ['HANDLE DebugObjectHandle', ' DEBUGOBJECTINFOCLASS DebugObjectInformationClass', ' PVOID DebugInformation', ' ULONG DebugInformationLength', ' PULONG ReturnLength']
		case 327: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtSetInformationDebugObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationDebugObject_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 328 NTSTATUS NtSetInformationEnlistment ['HANDLE EnlistmentHandle', ' ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass', ' PVOID EnlistmentInformation', ' ULONG EnlistmentInformationLength']
		case 328: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationEnlistment_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationEnlistment_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 329 NTSTATUS NtSetInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FileInformation', ' ULONG Length', ' FILE_INFORMATION_CLASS FileInformationClass']
		case 329: {
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
		// 330 NTSTATUS NtSetInformationJobObject ['HANDLE JobHandle', ' JOBOBJECTINFOCLASS JobObjectInformationClass', ' PVOID JobObjectInformation', ' ULONG JobObjectInformationLength']
		case 330: {
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
		// 331 NTSTATUS NtSetInformationKey ['HANDLE KeyHandle', ' KEY_SET_INFORMATION_CLASS KeySetInformationClass', ' PVOID KeySetInformation', ' ULONG KeySetInformationLength']
		case 331: {
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
		// 332 NTSTATUS NtSetInformationObject ['HANDLE Handle', ' OBJECT_INFORMATION_CLASS ObjectInformationClass', ' PVOID ObjectInformation', ' ULONG ObjectInformationLength']
		case 332: {
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
		// 333 NTSTATUS NtSetInformationProcess ['HANDLE ProcessHandle', ' PROCESSINFOCLASS ProcessInformationClass', ' PVOID ProcessInformation', ' ULONG ProcessInformationLength']
		case 333: {
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
		// 334 NTSTATUS NtSetInformationResourceManager ['HANDLE ResourceManagerHandle', ' RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass', ' PVOID ResourceManagerInformation', ' ULONG ResourceManagerInformationLength']
		case 334: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationResourceManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationResourceManager_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 335 NTSTATUS NtSetInformationThread ['HANDLE ThreadHandle', ' THREADINFOCLASS ThreadInformationClass', ' PVOID ThreadInformation', ' ULONG ThreadInformationLength']
		case 335: {
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
		// 336 NTSTATUS NtSetInformationToken ['HANDLE TokenHandle', ' TOKEN_INFORMATION_CLASS TokenInformationClass', ' PVOID TokenInformation', ' ULONG TokenInformationLength']
		case 336: {
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
		// 337 NTSTATUS NtSetInformationTransaction ['HANDLE TransactionHandle', ' TRANSACTION_INFORMATION_CLASS TransactionInformationClass', ' PVOID TransactionInformation', ' ULONG TransactionInformationLength']
		case 337: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationTransaction_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationTransaction_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 338 NTSTATUS NtSetInformationTransactionManager ['HANDLE TmHandle', ' TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass', ' PVOID TransactionManagerInformation', ' ULONG TransactionManagerInformationLength']
		case 338: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationTransactionManager_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationTransactionManager_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 339 NTSTATUS NtSetInformationWorkerFactory ['HANDLE WorkerFactoryHandle', ' WORKERFACTORYINFOCLASS WorkerFactoryInformationClass', ' PVOID WorkerFactoryInformation', ' ULONG WorkerFactoryInformationLength']
		case 339: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetInformationWorkerFactory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetInformationWorkerFactory_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 340 NTSTATUS NtSetIntervalProfile ['ULONG Interval', ' KPROFILE_SOURCE Source']
		case 340: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetIntervalProfile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetIntervalProfile_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 341 NTSTATUS NtSetIoCompletion ['HANDLE IoCompletionHandle', ' PVOID KeyContext', ' PVOID ApcContext', ' NTSTATUS IoStatus', ' ULONG_PTR IoStatusInformation']
		case 341: {
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
		// 342 NTSTATUS NtSetIoCompletionEx ['HANDLE IoCompletionHandle', ' HANDLE IoCompletionReserveHandle', ' PVOID KeyContext', ' PVOID ApcContext', ' NTSTATUS IoStatus', ' ULONG_PTR IoStatusInformation']
		case 342: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtSetIoCompletionEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetIoCompletionEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 343 NTSTATUS NtSetLdtEntries ['ULONG Selector0', ' ULONG Entry0Low', ' ULONG Entry0Hi', ' ULONG Selector1', ' ULONG Entry1Low', ' ULONG Entry1Hi']
		case 343: {
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
		// 344 NTSTATUS NtSetLowEventPair ['HANDLE EventPairHandle']
		case 344: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetLowEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetLowEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 345 NTSTATUS NtSetLowWaitHighEventPair ['HANDLE EventPairHandle']
		case 345: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetLowWaitHighEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetLowWaitHighEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 346 NTSTATUS NtSetQuotaInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length']
		case 346: {
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
		// 347 NTSTATUS NtSetSecurityObject ['HANDLE Handle', ' SECURITY_INFORMATION SecurityInformation', ' PSECURITY_DESCRIPTOR SecurityDescriptor']
		case 347: {
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
		// 348 NTSTATUS NtSetSystemEnvironmentValue ['PUNICODE_STRING VariableName', ' PUNICODE_STRING VariableValue']
		case 348: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetSystemEnvironmentValue_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSystemEnvironmentValue_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 349 NTSTATUS NtSetSystemEnvironmentValueEx ['PUNICODE_STRING VariableName', ' LPGUID VendorGuid', ' PVOID Value', ' ULONG ValueLength', ' ULONG Attributes']
		case 349: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtSetSystemEnvironmentValueEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSystemEnvironmentValueEx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 350 NTSTATUS NtSetSystemInformation ['SYSTEM_INFORMATION_CLASS SystemInformationClass', ' PVOID SystemInformation', ' ULONG SystemInformationLength']
		case 350: {
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
		// 351 NTSTATUS NtSetSystemPowerState ['POWER_ACTION SystemAction', ' SYSTEM_POWER_STATE MinSystemState', ' ULONG Flags']
		case 351: {
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
		// 352 NTSTATUS NtSetSystemTime ['PLARGE_INTEGER SystemTime', ' PLARGE_INTEGER PreviousTime']
		case 352: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetSystemTime_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetSystemTime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 353 NTSTATUS NtSetThreadExecutionState ['EXECUTION_STATE esFlags', ' PEXECUTION_STATE PreviousFlags']
		case 353: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSetThreadExecutionState_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetThreadExecutionState_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 354 NTSTATUS NtSetTimer ['HANDLE TimerHandle', ' PLARGE_INTEGER DueTime', ' PTIMER_APC_ROUTINE TimerApcRoutine', ' PVOID TimerContext', ' BOOLEAN WakeTimer', ' LONG Period', ' PBOOLEAN PreviousState']
		case 354: {
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
		// 355 NTSTATUS NtSetTimerEx ['HANDLE TimerHandle', ' TIMER_SET_INFORMATION_CLASS TimerSetInformationClass', ' PVOID TimerSetInformation', ' ULONG TimerSetInformationLength']
		case 355: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtSetTimerEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetTimerEx_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 356 NTSTATUS NtSetTimerResolution ['ULONG DesiredTime', ' BOOLEAN SetResolution', ' PULONG ActualTime']
		case 356: {
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
		// 357 NTSTATUS NtSetUuidSeed ['PCHAR Seed']
		case 357: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSetUuidSeed_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSetUuidSeed_return, cpu, pc, arg0) ;
		}; break;
		// 358 NTSTATUS NtSetValueKey ['HANDLE KeyHandle', ' PUNICODE_STRING ValueName', ' ULONG TitleIndex', ' ULONG Type', ' PVOID Data', ' ULONG DataSize']
		case 358: {
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
		// 359 NTSTATUS NtSetVolumeInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FsInformation', ' ULONG Length', ' FS_INFORMATION_CLASS FsInformationClass']
		case 359: {
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
		// 360 NTSTATUS NtShutdownSystem ['SHUTDOWN_ACTION Action']
		case 360: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtShutdownSystem_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtShutdownSystem_return, cpu, pc, arg0) ;
		}; break;
		// 361 NTSTATUS NtShutdownWorkerFactory ['HANDLE WorkerFactoryHandle', ' LONG *PendingWorkerCount']
		case 361: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtShutdownWorkerFactory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtShutdownWorkerFactory_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 362 NTSTATUS NtSignalAndWaitForSingleObject ['HANDLE SignalHandle', ' HANDLE WaitHandle', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout']
		case 362: {
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
		// 363 NTSTATUS NtSinglePhaseReject ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
		case 363: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSinglePhaseReject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSinglePhaseReject_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 364 NTSTATUS NtStartProfile ['HANDLE ProfileHandle']
		case 364: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtStartProfile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtStartProfile_return, cpu, pc, arg0) ;
		}; break;
		// 365 NTSTATUS NtStopProfile ['HANDLE ProfileHandle']
		case 365: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtStopProfile_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtStopProfile_return, cpu, pc, arg0) ;
		}; break;
		// 366 NTSTATUS NtSuspendProcess ['HANDLE ProcessHandle']
		case 366: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtSuspendProcess_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSuspendProcess_return, cpu, pc, arg0) ;
		}; break;
		// 367 NTSTATUS NtSuspendThread ['HANDLE ThreadHandle', ' PULONG PreviousSuspendCount']
		case 367: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtSuspendThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtSuspendThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 368 NTSTATUS NtSystemDebugControl ['SYSDBG_COMMAND Command', ' PVOID InputBuffer', ' ULONG InputBufferLength', ' PVOID OutputBuffer', ' ULONG OutputBufferLength', ' PULONG ReturnLength']
		case 368: {
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
		// 369 NTSTATUS NtTerminateJobObject ['HANDLE JobHandle', ' NTSTATUS ExitStatus']
		case 369: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtTerminateJobObject_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTerminateJobObject_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 370 NTSTATUS NtTerminateProcess ['HANDLE ProcessHandle', ' NTSTATUS ExitStatus']
		case 370: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtTerminateProcess_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTerminateProcess_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 371 NTSTATUS NtTerminateThread ['HANDLE ThreadHandle', ' NTSTATUS ExitStatus']
		case 371: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtTerminateThread_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTerminateThread_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 372 NTSTATUS NtTestAlert ['']
		case 372: {
			if (PPP_CHECK_CB(on_NtTestAlert_return)) {
			}
			PPP_RUN_CB(on_NtTestAlert_return, cpu, pc) ;
		}; break;
		// 373 NTSTATUS NtThawRegistry ['']
		case 373: {
			if (PPP_CHECK_CB(on_NtThawRegistry_return)) {
			}
			PPP_RUN_CB(on_NtThawRegistry_return, cpu, pc) ;
		}; break;
		// 374 NTSTATUS NtThawTransactions ['']
		case 374: {
			if (PPP_CHECK_CB(on_NtThawTransactions_return)) {
			}
			PPP_RUN_CB(on_NtThawTransactions_return, cpu, pc) ;
		}; break;
		// 375 NTSTATUS NtTraceControl ['ULONG FunctionCode', ' PVOID InBuffer', ' ULONG InBufferLen', ' PVOID OutBuffer', ' ULONG OutBufferLen', ' PULONG ReturnLength']
		case 375: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_NtTraceControl_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
				memcpy(&arg5, rp.params[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTraceControl_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 376 NTSTATUS NtTraceEvent ['HANDLE TraceHandle', ' ULONG Flags', ' ULONG FieldSize', ' PVOID Fields']
		case 376: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtTraceEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTraceEvent_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 377 NTSTATUS NtTranslateFilePath ['PFILE_PATH InputFilePath', ' ULONG OutputType', ' PFILE_PATH OutputFilePath', ' PULONG OutputFilePathLength']
		case 377: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtTranslateFilePath_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtTranslateFilePath_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 378 NTSTATUS NtUmsThreadYield ['PVOID SchedulerParam']
		case 378: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtUmsThreadYield_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUmsThreadYield_return, cpu, pc, arg0) ;
		}; break;
		// 379 NTSTATUS NtUnloadDriver ['PUNICODE_STRING DriverServiceName']
		case 379: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtUnloadDriver_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnloadDriver_return, cpu, pc, arg0) ;
		}; break;
		// 380 NTSTATUS NtUnloadKey ['POBJECT_ATTRIBUTES TargetKey']
		case 380: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtUnloadKey_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnloadKey_return, cpu, pc, arg0) ;
		}; break;
		// 381 NTSTATUS NtUnloadKey2 ['POBJECT_ATTRIBUTES TargetKey', ' ULONG Flags']
		case 381: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtUnloadKey2_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnloadKey2_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 382 NTSTATUS NtUnloadKeyEx ['POBJECT_ATTRIBUTES TargetKey', ' HANDLE Event']
		case 382: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtUnloadKeyEx_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnloadKeyEx_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 383 NTSTATUS NtUnlockFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PLARGE_INTEGER ByteOffset', ' PLARGE_INTEGER Length', ' ULONG Key']
		case 383: {
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
		// 384 NTSTATUS NtUnlockVirtualMemory ['HANDLE ProcessHandle', ' PVOID *BaseAddress', ' PSIZE_T RegionSize', ' ULONG MapType']
		case 384: {
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
		// 385 NTSTATUS NtUnmapViewOfSection ['HANDLE ProcessHandle', ' PVOID BaseAddress']
		case 385: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtUnmapViewOfSection_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtUnmapViewOfSection_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 386 NTSTATUS NtVdmControl ['VDMSERVICECLASS Service', ' PVOID ServiceData']
		case 386: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtVdmControl_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtVdmControl_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 387 NTSTATUS NtWaitForDebugEvent ['HANDLE DebugObjectHandle', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout', ' PDBGUI_WAIT_STATE_CHANGE WaitStateChange']
		case 387: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtWaitForDebugEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitForDebugEvent_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 388 NTSTATUS NtWaitForKeyedEvent ['HANDLE KeyedEventHandle', ' PVOID KeyValue', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout']
		case 388: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_NtWaitForKeyedEvent_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitForKeyedEvent_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 389 NTSTATUS NtWaitForMultipleObjects ['ULONG Count', ' HANDLE Handles[]', ' WAIT_TYPE WaitType', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout']
		case 389: {
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
		// 390 NTSTATUS NtWaitForMultipleObjects32 ['ULONG Count', ' LONG Handles[]', ' WAIT_TYPE WaitType', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout']
		case 390: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_NtWaitForMultipleObjects32_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
				memcpy(&arg2, rp.params[2], sizeof(uint32_t));
				memcpy(&arg3, rp.params[3], sizeof(uint32_t));
				memcpy(&arg4, rp.params[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitForMultipleObjects32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 391 NTSTATUS NtWaitForSingleObject ['HANDLE Handle', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout']
		case 391: {
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
		// 392 NTSTATUS NtWaitForWorkViaWorkerFactory ['HANDLE WorkerFactoryHandle', ' PFILE_IO_COMPLETION_INFORMATION MiniPacket']
		case 392: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_NtWaitForWorkViaWorkerFactory_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
				memcpy(&arg1, rp.params[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitForWorkViaWorkerFactory_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 393 NTSTATUS NtWaitHighEventPair ['HANDLE EventPairHandle']
		case 393: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtWaitHighEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitHighEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 394 NTSTATUS NtWaitLowEventPair ['HANDLE EventPairHandle']
		case 394: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtWaitLowEventPair_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWaitLowEventPair_return, cpu, pc, arg0) ;
		}; break;
		// 395 NTSTATUS NtWorkerFactoryWorkerReady ['HANDLE WorkerFactoryHandle']
		case 395: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_NtWorkerFactoryWorkerReady_return)) {
				memcpy(&arg0, rp.params[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_NtWorkerFactoryWorkerReady_return, cpu, pc, arg0) ;
		}; break;
		// 396 NTSTATUS NtWriteFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' PLARGE_INTEGER ByteOffset', ' PULONG Key']
		case 396: {
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
		// 397 NTSTATUS NtWriteFileGather ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PFILE_SEGMENT_ELEMENT SegmentArray', ' ULONG Length', ' PLARGE_INTEGER ByteOffset', ' PULONG Key']
		case 397: {
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
		// 398 NTSTATUS NtWriteRequestData ['HANDLE PortHandle', ' PPORT_MESSAGE Message', ' ULONG DataEntryIndex', ' PVOID Buffer', ' SIZE_T BufferSize', ' PSIZE_T NumberOfBytesWritten']
		case 398: {
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
		// 399 NTSTATUS NtWriteVirtualMemory ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' PVOID Buffer', ' SIZE_T BufferSize', ' PSIZE_T NumberOfBytesWritten']
		case 399: {
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
		// 400 NTSTATUS NtYieldExecution ['']
		case 400: {
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