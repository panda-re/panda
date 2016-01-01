Plugin: useafterfree
===========

Summary
-------

Arguments
---------

    alloc_guest_addr = panda_parse_ulong(args, "alloc", 0x7787209D);
    free_guest_addr = panda_parse_ulong(args, "free", 0x77871F31);
    realloc_guest_addr = panda_parse_ulong(args, "realloc", 0x77877E54);
    right_cr3 = panda_parse_ulong(args, "cr3", 0x3F98B320);
    word_size = panda_parse_uint64(args, "word", 4);

Dependencies
------------

    PPP_REG_CB("callstack_instr", on_ret, process_ret);

APIs and Callbacks
------------------





Example
-------

