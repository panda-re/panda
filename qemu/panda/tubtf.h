#ifndef __TUBTF_H_
#define __TUBTF_H_



/*

  TUBTF: Tim's Uncomplicated Binary Trace Format.  An implementation of a simple
  fixed-width binary execution trace file format.


  ==============================================================================
  CONCEPTS

  A trace is a temporal record of a program or whole operating system's
  execution.  It consists of a sequence of trace elements, in temporal order.
  A trace element can contain a variety of dynamic information such as the
  current process (cr3) and program counter (eip), or the dynamic values of
  registers used in LD or ST operations.  It can also contain information
  at a much higher semantic level, such as use/def info, results of taint
  queries, etc.

  ==============================================================================
  HEADER

  The trace file begins with a short header in the following format.  width is
  in bytes, here.

  field  offset width  name
  0      0      4      version
  1      4      4      colw (0=32-bit 1=64bit)
  2      8      8      contents_bits
  3      16     4      num_rows

  Header is 20 bytes long.

  version is an unsigned int indicates the version of the trace format.

  colw is an unsigned int.  It is 0 if columns in the trace body are 32-bits
  and 1 if they are 64-bits.  Use this to select a trace formats that naturally
  support 32 and 64-bit architectures, as appropriate.

  num_rows is an unsigned int.  It is the number of trace elements in the trace
  body.  See next section.

  contents_bits is a bitvector that indicates what kinds of trace elements are
  present.  See tubtf_elements.h for more info.  This is where new kinds of
  elements are defined and collisions avoided.  Yes, this is only 64 bits, so
  only 64 kinds of trace elements can be differentiated.

  ==============================================================================
  TRACE BODY

  Immediately following the header is the trace body which is a matrix of
  num_rows rows and 7 columns.
  cw is the number of bytes in a column.
  If colw=0 then cw=4 elsif colw=1 then cw=8.
  The seven columns have the following meanings.

  field  width   name
  0      cw      cr3
  1      cw      eip
  2      cw      type
  3      cw      arg1
  4      cw      arg2
  5      cw      arg3
  6      cw      arg4

  The first two fields identify process and program counter (for x86).
  NOTE: eip should be a virtual address here, not a physical address.
  The next field, "type", is used to differentiate between a number of possible
  trace element variants
  The remaining args have different meanings for different types.
  See below for details

  The fact that the trace body is a big square matrix means that it can
  readily be loaded into python with numpy and then navigated, analyzed, and
  queried.

 */



//#include <stdio.h>
#include <stdint.h>

#define TUBTF_NUM_COL 7

typedef enum {
  TUBTF_COLW_32,
  TUBTF_COLW_64
} TubtfColw;

// struct for the tubtf trace info
typedef struct tubtf_struct {
  uint32_t version;
  TubtfColw colw;
  // bitvector specifying what things are going into this trace
  uint64_t contents_bits;
  uint32_t num_rows;
  char *filename;
  void *fp;
} TubtfTrace;

// opens trace file & writes header
// colw: 0 means 32-bit columns, 1 means 64-bit columns in trace body
void tubtf_open(char *filename, TubtfColw colw);

uint32_t tubtf_element_size(void);

// writes a single trace element
void tubtf_write_el_32(uint32_t cr3, uint32_t eip, uint32_t type, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4);
void tubtf_write_el_64(uint64_t cr3, uint64_t eip, uint64_t type, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

// close the trace file and write header
void tubtf_close(void);




/*


  type  element_type
  0     def
  1     use
  2     tainted jmp
  3     tainted test
  4     tainted cmp
  5     tainted ld addr
  6     tainted ld val
  7     tainted st addr
  8     tainted st val
  9     tainted fn arg

  ------------------------------------------------------------------------------
  USE/DEF ELEMENT

  type = 0 (use)
  type = 1 (def)

  These trace elements are "use"s and "def"s.  A def is a store to some
  address or register.  A use is a load.

  arg1 is the address of the load/store
  arg2 is the size, in bytes

  Very low addresses indicate registers.  Note that this assumes very low
  addresses in memory aren't used for load/stores!
  XXX is this idiotic?
  The current assignments of very low addresses to registers is given by the
  following table.

  addr  reg
  0     eax
  4     ecx
  8     edx
  12    ebx
  16    ebp
  20    esp
  24    esi
  28    edi

  ------------------------------------------------------------------------------
  TAINTED JMP ELEMENT

  type = 2

  This trace element indicates that the taint system found the target of
  a jump to be tainted.  Note that taint queries are on individual bytes.

  arg1 -- jmp addr
  arg2 -- byte offset within jmp target for taint query
  arg3 -- taint set number

  Some more details.  JMP target is in T0.  For x86, the lowest four bytes of T0
  contain the virtual address of the jmp target.  We thus make four taint
  queries, one for each of those four bytes, as each byte can have different
  taint.  Taint set number is the result of the taint query, and tells us which
  bytes in the input this byte in the jmp target depends on.   See below for
  more information about taint set numbers and taint sets.

  ------------------------------------------------------------------------------
  TAINTED TEST OR COMPARE

  type = 3 (test) and type = 4 (cmp)

  This trace element indicates that the taint system found one of the arguments
  of a test or compare to be tainted.

  arg1 -- indicates which test/compare argument.
  arg2 -- byte offset within argument for taint query
  arg3 -- taint set number

  These arguments are in T0 and T1, which are internal Qemu registers, so mapping
  back to machine registers or memory is problematic.  However, arg1 can tell us
  if we have something like "test T0, T0".  Note that there are TWO taint queries
  for a single test/cmp (one for each argument).

  ------------------------------------------------------------------------------
  TAINTED LD ADDR

  type = 5

  This trace element indicates that the taint system found the address of a load
  to be tainted.

  arg1 -- unused
  arg2 -- byte offset within load address for taint query
  arg3 -- taint set number

  ------------------------------------------------------------------------------
  TAINTED LD VALUE

  type = 6

  This trace element indicates that the taint system found the value loaded to be
  tainted.

  arg1 -- unused
  arg2 -- byte offset within value for taint query
  arg3 -- taint set number

  ------------------------------------------------------------------------------
  TAINTED ST ADDR AND VALUE

  type = 7 (tainted st addr)
  type = 8 (tainted st value)

  These two work the same as tainted ld address and value.

  ------------------------------------------------------------------------------
  TAINTED FUNCTION ARGUMENT

  type = 9

  This trace element indicates that the taint system found an argument to a
  function to be tainted.  At function call sites, the taint system assumes
  function arguments to be 4 bytes apiece and looks for taint on the stack
  or in ecx/edx (fastcall).

  arg1 -- indicates the kind of argument
  arg2 -- byte offset within the argument for taint query
  arg3 -- taint set number

  arg1 value   argument_kind

  0            value of 1st 4-byte stack arg tainted
  ...
  7            value of 8th 4-byte stack arg tainted
  8            data pointed to by 1st 4-byte stack arg tainted
  ...
  15           data pointed to by 8th 4-byte stack arg tainted
  16           string (null term) pointed to by 1st 4-byte stack arg is tainted
  ...
  17           string (null term) pointed to by 8th 4-byte stack arg is tainted
  18           ecx tainted
  19           edx tainted

  ------------------------------------------------------------------------------
  TAINTED VALUE EXPRESSIONS

  Tainted value expressions are a way of tracking not just taint but also the full
  derivation of a multi-byte value.  For each 1, 2, and 4 byte value that is the
  result of a info_flow_compute (taint transfer with more than one source and one dest),
  we compute a unique hash for that quantity s.t. we can identify it later whenever
  we observe it.  We also keep track of the (dest, src1, src2) information which
  means we have a tree of derivations.

  types
   14    tainted value expr (tve) jmp target
   15    tve test arg
   16    tve cmp arg
   17    tve ld addr
   18    tve ld val
   19    tve st addr
   20    tve st arg

   These work rather like taint query trace elements above.  However, tve expressions
   are for multi-byte quantities (byte, short, or dword).  So the meanings of the
   args are different

   For all types,

   arg2 -- is the unique int for this tve

   For the test/cmp types (unused in other cases)

   arg1 -- is 0 if T0 is the arg and 1 if T1 is the arg.

   arg3 is unused

  ------------------------------------------------------------------------------
  TAINT SETS AND TAINT SET NUMBERS

  A taint query on a single byte in memory or in a register (or on hard drive)
  returns a taint set.  The elements of the set are labels which indicate
  dependence upon individual bytes in an input.  Consider the following queries
  and results.

  taint_query(eax, 0) = ([12], type=copy)

  Here, the taint system tells us that 0th byte of eax is derived from the 12th
  byte in the input.  The "type" tells us, further, that it is a direct copy of
  that input byte.

  taint_query(0xdeadbeef) = ([4096,4097], type=121)

  Here, the taint system determined that the byte at address 0xdeadbeef derives
  from the two bytes starting at input offset 4096.  The type=121 is an
  indication of the number of computations that have occurred to produce this
  label set.  Lower type number is closer to input.

  In order to be able to write the results of taint queries to a trace with
  fixed width elements, each taint set is represented in the trace by a uint32.
  This is accomplished by generating a hashtable mapping taint sets to uint32s,
  on the fly, whilst writing the trace.  This mapping is inverted and written to
  a file separate from the trace.

*/




typedef enum {
  TUBTFE_USE =          0,
  TUBTFE_DEF =          1,
  TUBTFE_TJMP =         2,   // tainted jmp target
  TUBTFE_TTEST =        3,   // tainted test arg
  TUBTFE_TCMP =         4,   // tainted cmp arg
  TUBTFE_TLDA =         5,   // tainted ld addr
  TUBTFE_TLDV =         6,   // tainted ld val
  TUBTFE_TSTA =         7,   // tainted st addr
  TUBTFE_TSTV =         8,   // tainted st val
  TUBTFE_TFNA_VAL =     9,   // tainted fn arg value
  TUBTFE_TFNA_PTR =     10,  // tainted data pointed to by fn arg
  TUBTFE_TFNA_STR =     11,  // tainted data string pointed to by fn arg
  TUBTFE_TFNA_ECX =     12,  // tainted fastcall fn arg value ecx
  TUBTFE_TFNA_EDX =     13,  // tainted fastcall fn arg value edx
  TUBTFE_TVE_JMP =      14,  // tainted value expr (tve) jmp target
  TUBTFE_TVE_TEST_T0 =  15,  // tve test arg
  TUBTFE_TVE_TEST_T1 =  16,  // tve test arg
  TUBTFE_TVE_CMP_T0 =   17,  // tve cmp arg
  TUBTFE_TVE_CMP_T1 =   18,  // tve cmp arg
  TUBTFE_TVE_LDA =      19,  // tve ld addr
  TUBTFE_TVE_LDV =      20,  // tve ld val
  TUBTFE_TVE_STA =      21,  // tve st addr
  TUBTFE_TVE_STV =      22,  // tve st arg

  // LLVM trace stuff
  TUBTFE_LLVM_FN =         30,  // entering LLVM function
  TUBTFE_LLVM_DV_LOAD =    31,  // dyn load
  TUBTFE_LLVM_DV_STORE =   32,  // dyn store
  TUBTFE_LLVM_DV_BRANCH =  33,  // dyn branch
  TUBTFE_LLVM_DV_SELECT =  34,  // dyn select
  TUBTFE_LLVM_DV_SWITCH =  35,  // dyn switch
  TUBTFE_LLVM_EXCEPTION =  36,   // some kind of fail?
} TubtfEIType;


#endif
