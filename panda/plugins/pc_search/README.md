Plugin: pc_search
===========

Summary
-------

The `pc_search` plugin takes one or more program counter inputs and outputs a text file of the corresponding guest instruction values identified during a replay.

If you use the `first_last_only` option, the output will contain just the first and last guest instructions identified for each program counter instead of outputting every single one.  This is useful for using the output with plugins like the `scissors` plugin which takes a start and end guest instructions as parameters.

This plugin supports i386 and x86_64.  It also has limited support for PowerPC.

Arguments
---------

* `pc` - Single program counter value to search for during a replay.  Can be specified as decimal or hexadecimal.  Throws an error if pc_file or pc_range argument is also passed. (default: 0)
* `pc_file` - Filename of input text file containing pc values.  Each pc value must be on a separate line in the file.  Each pc can be specified as decimal or hexadecimal.  Throws an error if pc or pc_range argument is also passed. (default: null)
* `pc_range` - Range of pc values to search for.  Should contain 2 pc values separated by a dash/hyphen e.g. 1234-5678.  Values can be specified as decimal or hexadecimal.  Throws an error if pc or pc_file argument is also passed. (default: null)
* `first_last_only` - Outputs just the first and last guest instructions for each program counter instead of all. (default:  `false`)
* `out_file` - Filename of output text file to write pc matches.  Output values are written in hex format.  (default: `pc_matches.txt`)

Dependencies
------------

None.

APIs and Callbacks
------------------

None.

Example
-------

Passing a single pc:

    $PANDA_PATH/x86_64-softmmu/panda-system-x86_64 -replay foo \
        -panda pc_search:pc=0x77c47f06
        
Passing multiple pcs and getting just first and last occurrence:

    $PANDA_PATH/x86_64-softmmu/panda-system-x86_64 -replay foo \
        -panda pc_search:first_last_only=true,pc_file="pc_input.txt",out_file="my_pc_matches.txt"
        
Passing a range of pcs:

    $PANDA_PATH/x86_64-softmmu/panda-system-x86_64 -replay foo \
        -panda pc_search:pc_range=0x79a33c06-0x79a33d32,out_file="my_pc_matches.txt"



