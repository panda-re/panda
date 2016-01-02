Plugin: syscalls
===========

Summary
-------

Arguments
---------

    sclog_filename = panda_parse_string(args, "file", NULL);

Dependencies
------------



APIs and Callbacks
------------------


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

