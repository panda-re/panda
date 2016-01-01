Plugin: stringsearch
===========

Summary
-------

Arguments
---------

    const char *arg_str = panda_parse_string(args, "str", "");
    n_callers = panda_parse_uint64(args, "callers", 16);
    const char *prefix = panda_parse_string(args, "name", "stringsearch");

Dependencies
------------

stringsearch/stringsearch.cpp:    panda_require("callstack_instr");
stringsearch/stringsearch.cpp:    if(!init_callstack_instr_api()) return false;

APIs and Callbacks
------------------

stringsearch/stringsearch.cpp:PPP_PROT_REG_CB(on_ssm);



Example
-------

