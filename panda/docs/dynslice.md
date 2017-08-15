Architecture-Neutral Dynamic Slicing with PANDA
===============================================

Dynamic slicing is a classic technique first described by [Korel and
Laski](http://dl.acm.org/citation.cfm?id=56386) in 1988. It essentially
allows a user to pick a value seen in an execution trace and ask "what
instructions were used in computing this value?". It does so by
following dataflow backward through the trace, marking any instructions
that handle data along the way. Thus, it is somewhat like a dynamic
taint analysis, but in reverse.

Dynamic slicing has been used in a number of security applications,
including my own [Virtuoso](http://dl.acm.org/citation.cfm?id=2006772),
where we used it to extract out algorithms that compute useful
introspection data. It is also extremely useful in reverse engineering,
as it lets you pick out any value and figure out where it came from.
Given this, it is a natural fit to add to PANDA.

The basic algorithm is quite simple, and can be expressed in a few lines
of pseudocode. Given an execution trace:

```python
    # initialize a working set containing the data whose computation we
    # want to understand
    work = { initial slice variables }

    # walk backward through the trace
    for insn in reversed(trace):
        if work ∩ defines(insn) != ∅:
            mark(insn)
            work = work ∖ defines(insn)
            work = work ∪ uses(insn)
```

The `defines` and `uses` functions above just get the variables used or
defined by a given instruction. For example, for the LLVM instruction
`%x = add i32 %y, %z`, the uses would be `{%y, %z}` and the defines
would be `{ %x }`. In some cases dynamic information may be needed to
get the full set of uses or defines, as with memory loads and stores.
For example, in the instruction `store i32 %val, i32* %ptr`, the
instruction affects the four bytes of memory pointed to by `%ptr`; this
information is only known at runtime and must be saved along with the
basic instruction trace.

At the end, the marked instructions will be those that were used to
compute the variable specified at the beginning in this particular
trace.

Note that this simplified algorithm doesn't say anything about what to
do with branches and other control-flow statements. These are
technically only needed for *executable dynamic slicing*, where we want
the additional property that we can run the sliced code on its own.
Since we're mainly interested in analysis, we won't consider branches
for now.

Dynamic Slicing on LLVM
-----------------------

PANDA's ability to lift native code up to LLVM is a huge help in
simplifying program analyses. It has three main benefits:

1. [LLVM instructions](http://llvm.org/docs/LangRef.html) are much
    simpler and fewer in number than native code, meaning that analyses
    which need to model each instruction (like taint and dynamic
    slicing) are vastly easier to write.
1. Since the LLVM is generated from TCG operations, and QEMU already
   lifts native code to TCG for every architecture it supports, analyses
   on LLVM automatically work for every architecture QEMU supports.
1. Unlike analyses that work only on TCG, however, we can also analyze
   functions written in C by compiling them to LLVM bitcode with
   `clang`. This is critical, since significant portions of QEMU's guest
   emulation (for example, floating point operations) are implemented as
   C "helper" functions. Translating these to LLVM allows our analyses
   to be complete.

Thus, to implement dynamic slicing in PANDA, we will take advantage of
its ability to create traces in LLVM mode, implemented by the
`llvm_trace` plugin.

Execution Tracing in PANDA with `llvm_trace`
--------------------------------------------

To capture a useful execution trace, we want three things:

1. A list of basic blocks executed in the guest.
1. The corresponding code for each basic block.
1. Dynamic information, such as the address of memory loads and stores
   and the

This is precisely what the `llvm_trace` plugin produces. When enabled,
it runs guest code in LLVM mode, where each basic block of native code
is translate to LLVM and then compiled to host code using the [LLVM
MCJIT](http://llvm.org/docs/MCJITDesignAndImplementation.html); helper
functions are also compiled to LLVM and executed by the JIT.

Before each basic block executes, `llvm_trace` logs the name of the
corresponding LLVM function, which provides capability (1). At the end
of execution, it dumps out an [LLVM bitcode
module](http://llvm.org/docs/BitCodeFormat.html) containing all the code
(translated code and helper functions) seen during the trace, giving us
(2). Finally, it instruments the LLVM code to log information about
memory loads and stores and branches taken within the LLVM code (i.e.,
the information described in (3)).

The traces are stored in a simple row-based format called TUBTF (Tim's
Uncomplicated Binary Trace Format). Each row consists of 7 64-bit
unsigned integers that record the entry type, program counter, address
space, and up to four arguments whose type depends on the entry. Since
each row is fixed-width and of integer type, it makes it very easy to
load up in something like `numpy`. However, it is not particularly
space-efficient: a single 120 million instruction trace takes up about
57 gigabytes! The logs are highly compressible, however; the same 57G
log is a mere 2.7G when compressed with `gzip`.

To actually produce a trace, run:

```sh
cd <arch>-softmmu
./qemu-system-<arch> -replay <replay> -panda 'llvm_trace:tubt=1,base=<output_dir>'
```

Which will produce `llvm-mod.bc` and `tubtf.log` in the `<output_dir>`
directory.

Using PANDA's Dynamic Slicer
----------------------------

Because dynamic slicing operates on a trace in reverse, we first need to
reverse the logfile. This is done using the `logreverse_mmap` tool:

```sh
cd <arch>-softmmu/panda_tools/
./logreverse_mmap tubtf.log
```

Note that since it reverses the file in-place, you may want to make a
backup of the original somewhere.

Now we can actually do some slicing. First we will need some criteria
to slice on, such as some registers or memory we're interested in. The
usage information for the `dynslice` utility shows what options we have
for slicing conditions:

    Usage: ./dynslice [OPTIONS] <llvm_mod> <dynlog> <criterion> [<criterion> ...]
    Options:
      -b                : include branch conditions in slice
      -d                : enable debug output
      -v                : show progress meter
      -a                : just align, don't slice
      -w                : print working set after each block
      -n NUM -p PC      : skip ahead to TB NUM-PC
      -o OUTPUT         : save results to OUTPUT
      <llvm_mod>        : the LLVM bitcode module
      <dynlog>          : the TUBT log file
      <criterion> ...   : the slicing criteria, i.e., what to slice on
                          Use REG_[N] for registers, MEM_[PADDR] for memory

So if we want to track four bytes at physical address `0x12000`, we could
do:

```sh
./dynslice llvm-mod.bc tubtf.log MEM_12000 MEM_12001 MEM_12002 MEM_1203
```

Both the `N` in `REG_[N]` and the `PADDR` in `MEM_[PADDR]` are
hexadecimal numbers.

At the end, you'll get a report of how many instructions were included
in the slice:

    Done slicing. Marked 32539 blocks, 66639872 instructions.

How do you actually see what instructions in a given basic block were
sliced? `dynslice` also saves a binary log indicating which instructions
inside each block were marked, named `slice_report.bin`. Using that and
the `slice_viewer` utility, you can see what's marked in a given
block. Generated LLVM blocks are named as `tcg-llvm-tb-N-XXXXX`, where
`XXXXX` is the address of the code at the beginning of the block and `N`
is a counter (to prevent collisions when two blocks occupy the same
virtual address at different points in the trace). So to see, for
example, the marked instructions in `tcg-llvm-tb-31408-74b92bec`, we can
do:

```sh
./slice_viewer llvm-mod.bc slice_report.bin tcg-llvm-tb-31408-74b92bec
```

And we'll get the output below:

    *** Function tcg-llvm-tb-31408-74b92bec ***
    >>> Block 0
        %1 = alloca i64
        %2 = alloca i64
        %3 = alloca i64
        %4 = alloca i64
    *   %5 = getelementptr i64* %0, i32 0
        %6 = ptrtoint i64* %5 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 0, i64 %6)
    *   %env_v = load i64* %5
        %7 = add i64 %env_v, 128
        %8 = inttoptr i64 %7 to i64*
        %9 = ptrtoint i64* %8 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %9)
        store i64 1958292460, i64* %8
        store volatile i64 2, i64* inttoptr (i64 29287216 to i64*)
        store volatile i64 1958292460, i64* inttoptr (i64 29287224 to i64*), !pcupdate.md !0
        %10 = add i64 %env_v, 56032
        %11 = inttoptr i64 %10 to i64*
        %12 = ptrtoint i64* %11 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %12)
        store i64 1958292460, i64* %11
        %13 = add i64 %env_v, 56016
        %14 = inttoptr i64 %13 to i64*
        %15 = ptrtoint i64* %14 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 0, i64 %15)
        %tmp12_v = load i64* %14
        %tmp12_v1 = add i64 %tmp12_v, 1
        %16 = add i64 %env_v, 56016
        %17 = inttoptr i64 %16 to i64*
        %18 = ptrtoint i64* %17 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %18)
        store i64 %tmp12_v1, i64* %17
        %19 = add i64 %env_v, 40
        %rbp_ptr = inttoptr i64 %19 to i64*
        %20 = ptrtoint i64* %rbp_ptr to i64
        call void @log_dynval(i64 59634320, i32 0, i32 0, i64 %20)
        %rbp_v = load i64* %rbp_ptr
        %tmp2_v = add i64 %rbp_v, -16
        %tmp2_v2 = and i64 %tmp2_v, 4294967295
        %21 = call i32 @__ldl_mmu_panda(i64 %tmp2_v2, i32 1)
        %tmp0_v = zext i32 %21 to i64
    *   %22 = add i64 %env_v, 32
    *   %rsp_ptr = inttoptr i64 %22 to i64*
        %23 = ptrtoint i64* %rsp_ptr to i64
        call void @log_dynval(i64 59634320, i32 0, i32 0, i64 %23)
    *   %rsp_v = load i64* %rsp_ptr
    *   %tmp2_v3 = add i64 %rsp_v, -4
    *   %tmp2_v4 = and i64 %tmp2_v3, 4294967295
        %24 = trunc i64 %tmp0_v to i32
        call void @__stl_mmu_panda(i64 %tmp2_v4, i32 %24, i32 1)
    *   %25 = trunc i64 %tmp2_v4 to i32
    *   %tmp-12_v = zext i32 %25 to i64
        %26 = ptrtoint i64* %rsp_ptr to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %26)
        store i64 %tmp-12_v, i64* %rsp_ptr
        %27 = add i64 %env_v, 128
        %28 = inttoptr i64 %27 to i64*
        %29 = ptrtoint i64* %28 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 0, i64 %29)
        %tmp4_v = load i64* %28
        %tmp4_v6 = add i64 %tmp4_v, 3
        %30 = add i64 %env_v, 128
        %31 = inttoptr i64 %30 to i64*
        %32 = ptrtoint i64* %31 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %32)
        store i64 %tmp4_v6, i64* %31
        store volatile i64 26, i64* inttoptr (i64 29287216 to i64*)
        store volatile i64 1958292463, i64* inttoptr (i64 29287224 to i64*), !pcupdate.md !0
        %33 = add i64 %env_v, 56032
        %34 = inttoptr i64 %33 to i64*
        %35 = ptrtoint i64* %34 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %35)
        store i64 1958292463, i64* %34
        %36 = add i64 %env_v, 56016
        %37 = inttoptr i64 %36 to i64*
        %38 = ptrtoint i64* %37 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 0, i64 %38)
        %tmp12_v7 = load i64* %37
        %tmp12_v8 = add i64 %tmp12_v7, 1
        %39 = add i64 %env_v, 56016
        %40 = inttoptr i64 %39 to i64*
        %41 = ptrtoint i64* %40 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %41)
        store i64 %tmp12_v8, i64* %40
        %42 = add i64 %env_v, 0
        %rax_ptr = inttoptr i64 %42 to i64*
        %43 = ptrtoint i64* %rax_ptr to i64
        call void @log_dynval(i64 59634320, i32 0, i32 0, i64 %43)
        %rax_v = load i64* %rax_ptr
    *   %tmp2_v9 = add i64 %tmp-12_v, -4
    *   %tmp2_v10 = and i64 %tmp2_v9, 4294967295
        %44 = trunc i64 %rax_v to i32
        call void @__stl_mmu_panda(i64 %tmp2_v10, i32 %44, i32 1)
    *   %45 = trunc i64 %tmp2_v10 to i32
    *   %tmp-12_v12 = zext i32 %45 to i64
        %46 = ptrtoint i64* %rsp_ptr to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %46)
        store i64 %tmp-12_v12, i64* %rsp_ptr
        %47 = add i64 %env_v, 128
        %48 = inttoptr i64 %47 to i64*
        %49 = ptrtoint i64* %48 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 0, i64 %49)
        %tmp4_v13 = load i64* %48
        %tmp4_v14 = add i64 %tmp4_v13, 1
        %50 = add i64 %env_v, 128
        %51 = inttoptr i64 %50 to i64*
        %52 = ptrtoint i64* %51 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %52)
        store i64 %tmp4_v14, i64* %51
        store volatile i64 45, i64* inttoptr (i64 29287216 to i64*)
        store volatile i64 1958292464, i64* inttoptr (i64 29287224 to i64*), !pcupdate.md !0
        %53 = add i64 %env_v, 56032
        %54 = inttoptr i64 %53 to i64*
        %55 = ptrtoint i64* %54 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %55)
        store i64 1958292464, i64* %54
        %56 = add i64 %env_v, 56016
        %57 = inttoptr i64 %56 to i64*
        %58 = ptrtoint i64* %57 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 0, i64 %58)
        %tmp12_v15 = load i64* %57
        %tmp12_v16 = add i64 %tmp12_v15, 1
        %59 = add i64 %env_v, 56016
        %60 = inttoptr i64 %59 to i64*
        %61 = ptrtoint i64* %60 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %61)
        store i64 %tmp12_v16, i64* %60
        %62 = call i32 @__ldl_mmu_panda(i64 1958221188, i32 1)
        %tmp0_v17 = zext i32 %62 to i64
    *   %tmp2_v18 = add i64 %tmp-12_v12, -4
    *   %tmp2_v19 = and i64 %tmp2_v18, 4294967295
        call void @__stl_mmu_panda(i64 %tmp2_v19, i32 1958292470, i32 1)
    *   %63 = trunc i64 %tmp2_v19 to i32
    *   %tmp-12_v21 = zext i32 %63 to i64
        %64 = ptrtoint i64* %rsp_ptr to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %64)
    *   store i64 %tmp-12_v21, i64* %rsp_ptr
        %65 = add i64 %env_v, 128
        %66 = inttoptr i64 %65 to i64*
        %67 = ptrtoint i64* %66 to i64
        call void @log_dynval(i64 59634320, i32 0, i32 2, i64 %67)
        store i64 %tmp0_v17, i64* %66
        ret i64 0

Marked instructions appear with an asterisk.
