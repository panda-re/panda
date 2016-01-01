Plugin: win7x86intro
===========

Summary
-------

Arguments
---------



Dependencies
------------

    panda_require("osi");
    PPP_REG_CB("osi", on_get_current_process, on_get_current_process);
    PPP_REG_CB("osi", on_get_processes, on_get_processes);
    PPP_REG_CB("osi", on_get_libraries, on_get_libraries);
    PPP_REG_CB("osi", on_free_osiproc, on_free_osiproc);
    PPP_REG_CB("osi", on_free_osiprocs, on_free_osiprocs);
    PPP_REG_CB("osi", on_free_osimodules, on_free_osimodules);

APIs and Callbacks
------------------





Example
-------

