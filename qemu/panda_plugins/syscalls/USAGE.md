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




#include "syscalls_common.hpp"

void appendReturnPoint(ReturnPoint&& rp);

void registerExecPreCallback(pre_exec_callback_t callback);

Example
-------

