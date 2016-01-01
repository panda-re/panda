Plugin: tstringsearch
===========

Summary
-------

Arguments
---------

    enable_taint_instr_count = panda_parse_uint64(args, "instr_count", 0);
    positional_tainting = panda_parse_bool(args, "pos");

Dependencies
------------

    panda_require("stringsearch");
    panda_require("taint2");
    assert(init_taint2_api());
    PPP_REG_CB("stringsearch", on_ssm, tstringsearch_match) ;

APIs and Callbacks
------------------





Example
-------

