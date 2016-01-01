Plugin: win7proc
===========

Summary
-------

Arguments
---------

        const char *proclog_filename = panda_parse_string(args, "log_prefix", DEFAULT_LOG_FILE);

Dependencies
------------

    //    panda_require("syscalls2");
    PPP_REG_CB("syscalls2", on_NtCreateUserProcess_return, w7p_NtCreateUserProcess_return);
    PPP_REG_CB("syscalls2", on_NtTerminateProcess_enter, w7p_NtTerminateProcess_enter);
    PPP_REG_CB("syscalls2", on_NtCreateFile_enter, w7p_NtCreateFile_enter);
    PPP_REG_CB("syscalls2", on_NtReadFile_enter, w7p_NtReadFile_enter);
    PPP_REG_CB("syscalls2", on_NtDeleteFile_enter, w7p_NtDeleteFile_enter);
    PPP_REG_CB("syscalls2", on_NtWriteFile_enter, w7p_NtWriteFile_enter);
    PPP_REG_CB("syscalls2", on_NtCreateKey_return, w7p_NtCreateKey_return);
    //    PPP_REG_CB("syscalls2", on_NtCreateKeyTransacted_enter, w7p_NtCreateKeyTransacted_enter);
    PPP_REG_CB("syscalls2", on_NtOpenKey_return, w7p_NtOpenKey_return);
    PPP_REG_CB("syscalls2", on_NtOpenKeyEx_return, w7p_NtOpenKeyEx_return);
    //    PPP_REG_CB("syscalls2", on_NtOpenKeyTransacted_enter, w7p_NtOpenKeyTransacted_enter);
    //    PPP_REG_CB("syscalls2", on_NtOpenKeyTransactedEx_enter, w7p_NtOpenKeyTransactedEx_enter);
    PPP_REG_CB("syscalls2", on_NtDeleteKey_enter, w7p_NtDeleteKey_enter);
    PPP_REG_CB("syscalls2", on_NtQueryKey_enter, w7p_NtQueryKey_enter);
    PPP_REG_CB("syscalls2", on_NtQueryValueKey_enter, w7p_NtQueryValueKey_enter);
    PPP_REG_CB("syscalls2", on_NtDeleteValueKey_enter, w7p_NtDeleteValueKey_enter);
    PPP_REG_CB("syscalls2", on_NtEnumerateKey_enter, w7p_NtEnumerateKey_enter);
    PPP_REG_CB("syscalls2", on_NtSetValueKey_enter, w7p_NtSetValueKey_enter);
    PPP_REG_CB("syscalls2", on_NtCreateSection_return, w7p_NtCreateSection_return);
    PPP_REG_CB("syscalls2", on_NtOpenSection_return, w7p_NtOpenSection_return);
    PPP_REG_CB("syscalls2", on_NtMapViewOfSection_return, w7p_NtMapViewOfSection_return);
    PPP_REG_CB("syscalls2", on_NtCreatePort_return, w7p_NtCreatePort_return);
    PPP_REG_CB("syscalls2", on_NtConnectPort_return, w7p_NtConnectPort_return);
    PPP_REG_CB("syscalls2", on_NtListenPort_return, w7p_NtListenPort_return);
    PPP_REG_CB("syscalls2", on_NtAcceptConnectPort_return, w7p_NtAcceptConnectPort_return);
    PPP_REG_CB("syscalls2", on_NtCompleteConnectPort_return, w7p_NtCompleteConnectPort_return);
    PPP_REG_CB("syscalls2", on_NtRequestPort_return, w7p_NtRequestPort_return);
    PPP_REG_CB("syscalls2", on_NtRequestWaitReplyPort_return, w7p_NtRequestWaitReplyPort_return);
    PPP_REG_CB("syscalls2", on_NtReplyPort_return, w7p_NtReplyPort_return);
    PPP_REG_CB("syscalls2", on_NtReplyWaitReplyPort_return, w7p_NtReplyWaitReplyPort_return);
    PPP_REG_CB("syscalls2", on_NtReplyWaitReceivePort_return, w7p_NtReplyWaitReceivePort_return);
    PPP_REG_CB("syscalls2", on_NtImpersonateClientOfPort_return, w7p_NtImpersonateClientOfPort_return);
    PPP_REG_CB("syscalls2", on_NtReadVirtualMemory_return, w7p_NtReadVirtualMemory_return);
    PPP_REG_CB("syscalls2", on_NtWriteVirtualMemory_return, w7p_NtWriteVirtualMemory_return);

APIs and Callbacks
------------------





Example
-------

