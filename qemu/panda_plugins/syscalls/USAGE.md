Plugin: syscalls
===========

Summary
-------

The `syscalls` plugin intercepts and logs system calls made in the guest OS, along with their arguments. Currently, only Linux x86 and ARM are supported.

**Warning**: The `syscalls` plugin is officially **deprecated**, and `syscalls2` is its preferred replacement. However, `syscalls` still enjoys two advantages over `syscalls`:

* `syscalls` can automatically produce a text log of system calls, with their arguments.
* Getting the value of an out parameter at return time is not supported in `syscalls2` except for Windows 32-bit guests.

Arguments
---------

* `file`: string, defaults to "syscalls.txt". The filename to log to when printing out the name and value of each system call.

Dependencies
------------

None.

APIs and Callbacks
------------------

The `syscalls` plugin provides APIs for getting notified before a system call executes and being notified of returns. Note that because these callbacks use C++, they are not available to plugins written in C.

    enum class Callback_RC : int {
        NORMAL = 0,
        ERROR,
        INVALIDATE,
    };

    //ReturnPoints contain a contuation that does something

    typedef std::unique_ptr<CallbackData> CallbackDataPtr;

    static CallbackDataPtr make_callbackptr(CallbackData* data){
        return CallbackDataPtr(data);
    }

    static Callback_RC null_callback(CallbackData*, CPUState*, target_asid){
        return Callback_RC::NORMAL;
    }

    struct ReturnPoint {
        ReturnPoint() = delete;
        ReturnPoint(target_ulong retaddr, target_asid process_id,
                    CallbackData* data = nullptr,
                    std::function<Callback_RC(CallbackData*, CPUState*, target_asid)> callback = null_callback){
            this->retaddr = retaddr;
            this->process_id = process_id;
            opaque = make_callbackptr(data);
            this->callback = callback;
        }
        target_ulong retaddr;
        target_asid process_id;
        CallbackDataPtr opaque;
        std::function<Callback_RC(CallbackData*, CPUState*, target_asid)> callback;
    };

    typedef void (*pre_exec_callback_t)(CPUState*, target_ulong);

    void appendReturnPoint(ReturnPoint&& rp);

    void registerExecPreCallback(pre_exec_callback_t callback);

Example
-------

FIXME
