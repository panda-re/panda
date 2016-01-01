Plugin: tainted_branch
===========

Summary
-------

Arguments
---------



Dependencies
------------

        PPP_REG_CB("taint2", on_branch2, tbranch_on_branch_taint2); 
    panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    panda_require("taint2");
    assert (init_taint2_api());    

APIs and Callbacks
------------------





Example
-------

