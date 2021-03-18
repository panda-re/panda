#ifndef __PANDA_ADDR_H__
#define __PANDA_ADDR_H__

#include <stdint.h>


// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

/* these need to be the same size because when we have an unknown dynamic value
 * that we need to fill in later, we need to fix up the taint op in the buffer
 */
typedef uint64_t HAddr;    // hard drive
typedef uint64_t MAddr;    // physical ram
typedef uint64_t IAddr;    // io buffers (net & hd)
typedef uint64_t PAddr;    // port addresses (x86-specific)
typedef uint64_t LAddr;    // local values
typedef uint64_t GReg;     // guest general purpose register
typedef uint64_t GSpec;    // guest special address, like floating point regs
typedef uint64_t Unk;      // unknown type that needs to be fixed up
typedef uint64_t Const;    // constant that we currently treat as untainted
typedef uint64_t Ret;      // LLVM return value, also temp register

typedef enum {HADDR, MADDR, IADDR, PADDR, LADDR, GREG, GSPEC,
    UNK, CONST, RET, ADDR_LAST} AddrType;

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
typedef union {
    HAddr ha;
    MAddr ma;
    IAddr ia;
    PAddr pa;
    LAddr la;
    GReg gr;
    GSpec gs;
    Unk ua;
    Const con;
    Ret ret;
} ValueUnion;


#if 0
// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

typedef uint64_t ValueUnion;

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
#endif

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.
typedef enum {
    IRRELEVANT=5,  // memory access to CPU state we don't care about
    EXCEPTION=1,    // indicates that there was a memory exception
    READLOG,        // indicates that we need to read from dynamic log
    FUNCARG         // indicates that we need to copy to the current frame + 1
} AddrFlag;

typedef enum {
    INSNREADLOG=1 // indicates that we need to read from dynamic log
} InsnFlag;

typedef struct addr_struct {
  AddrType typ;
  ValueUnion val;
  uint16_t off;   // offset within local registers and guest registers
  AddrFlag flag;  // indication that we might need to look up address from log
} Addr;

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#endif
