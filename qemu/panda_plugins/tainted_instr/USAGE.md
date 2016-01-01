Plugin: tainted_instr
===========

Summary
-------

Arguments
---------

    summary = panda_parse_bool(args, "summary");

Dependencies
------------

    panda_require("taint2");
    assert(init_taint2_api());
    panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    PPP_REG_CB("taint2", on_taint_change, taint_change);

APIs and Callbacks
------------------





Example
-------

