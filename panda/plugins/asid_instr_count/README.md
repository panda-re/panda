Plugin: asid\_instr\_count
===========

Summary
-------

This plugin provides a per-asid instruction count.

For each asid, keep track of the total number of instructions previously
executed by all other asids.  This allows us to 'correct' the instruction
count for an asid by subtraction.  Which means we can now take two instructions
counts obtained via calls to asid\_instr\_count(asid) and subtract them to know
how many instructions were executed between the two.  Without this accounting,
we'd be including execution by other asids.

Arguments
---------

None.

Dependencies
------------

None.

APIs and Callbacks
------------------

Name: **get_instr_count_current_asid**

Signature:

```C
Instr get_instr_count_current_asid(void);
```

Description: Returns instruction count for current asid (subtracting out
instructions for other asids)

NOTE: this means this isn't the actual instruction count within the replay, but it is
now safe, e.g., to subtract two instruction counts

Name: **get_instr_count_by_asid**

Signature:

```C
Instr get_instr_count_by_asid(target_ulong asid);
```

Description: Returns instruction count for input parameter asid (subtracting out
instructions for other asids)

NOTE: this means this isn't the actual instruction count within the replay, but it is
now safe, e.g., to subtract two instruction counts

Example
-------

None.  This plugin is intended to be used only by other plugins.

