Plugin: tainted_branch
===========

Summary
-------

The `tainted_branch` plugin produces a report in PANDA log or Comma Separated Value (CSV) format that lists information on every branch instruction in the replay that depends on tainted data. This plugin is used with other plugins which taint data, such as `file_taint` or `tstringsearch`. This can be very useful for doing things like determining what parts of the program can be influenced by user input.

Output in PANDA log format can be done in "summary" or default mode. The PANDA log file name is specified using the "-pandalog" option to PANDA.  Note that all numbers in the PANDA log are in decimal.

The PANDA log format default mode reports the guest address of the block including the tainted branch, the callstack, information on each taint found, and the instruction count of the tainted branch or its block.  Each taint report found reports its Taint Compute Number (i.e. how many computations on the tainted item are involved between when the taint was introduced and the time of the report), the native address of where the taint labels are, the taint labels, and the offset into the buffer in the guest of the item whose taint is being reported on. Note that each taint label set is only reported the first time it is encountered.  The label set address can be used to find the label set for subsequent instances.  Following is a copy of part of a PANDA log.  The section labeled "uniqueLabelSet" is what is omitted from subsequent reports for the same label set.

```
{
  "pc": "4196548",     <===== the guest address of the block containing the tainted branch
  "taintedBranch": {
    "callStack": {
      "addr": [
        "140055226136624", 
        "4195897", 
        "4407804", 
        "4414864"
      ]
    }, 
    "taintQuery": [
      {
        "tcn": 1,     <===== Taint Compute Number
        "uniqueLabelSet": {
          "ptr": "140192956884936",     <===== address of this label set
          "label": [
            8, 
            9, 
            10, 
            11
          ]
        }, 
        "ptr": "140192956884936",     <===== address of this label set
        "offset": 0     <===== offset into buffer in guest of thing whose taint is being queried
      }
    ]
  }, 
  "instr": "21191791"     <===== guest instruction count
}
```

The PANDA log "summary" mode is not really a summary of the PANDA log default mode, as it includes the Address Space Identifier (ASID), which is not included in the default mode output.  It also reports the guest address of each tainted branch.

In either PANDA log mode, the liveness option can be used to include a list of the labels which have appeared on tainted branches and the number of times each one has appeared.  This option makes it easier to determine if a particular label was ever used to determine which path to take in a conditional branch.

The "ignore_helpers" option can be used to omit taint reports that are generated from within LLVM helper functions.  This can be useful if the output will be processed by analysis tools that cannot process helper functions.

Output in CSV format can also be done in "summary" or default mode.  The "summary" output lists the same information as seen in the PANDA log summary output.  The default mode lists for each tainted branch the guest address of the block including the tainted branch, the instruction count, and a space-separated list of labels.  Note that the liveness option cannot be used with CSV output.  It is also not possible to produce PANDA log and CSV output at the same time.

Arguments
---------

- `csvfile`: string, optional:  name of file to save CSV output to
- `indirect_jumps`: boolean, optional: also report indirect jumps
- `liveness`:  boolean, optional:  report live labels to the PANDA log
- `ignore_helpers`:  boolean, optional:  do not report taint from within helper functions
- `summary`: boolean, optional:  only save the ASID and PC of the tainted branches

Dependencies
------------

`tainted_branch` uses `taint2` to track taint, and `callstack_instr` to provide callstack information whenever tainted branches are encountered.

APIs and Callbacks
------------------

A function is provided to get the liveness count for a particular label:
```C
uint64_t get_liveness(uint32_t l);
```

Example
-------

To taint data from a file named `foo.dat` on Linux and then find out what branches depend on data from that file, placing output into the pandalog `foo.plog`:

    $PANDA_PATH/x86_64-softmmu/panda-system-x86_64 -replay foo -panda osi \
        -panda osi_linux:kconf_group=debian-3.2.63-i686 \
        -panda syscalls2:profile=linux_x86 \
        -panda file_taint:filename=foo.dat \
        -panda tainted_branch \
        -pandalog foo.plog

