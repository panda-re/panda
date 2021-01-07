/*
 * update_cb_switch.c
 * Test the bit twiddling in the update_cb_switch.h file in the taint2 plugin.
 * Only the troublesome twiddling, which required corrections, are tested.
 * These were mostly related to implicit casts messing up the results.
 *
 * Author:  Laura L. Mann
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>  // to get uint64_t
#include <cassert>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>

#include "qemu/osdep.h"        // needed for host-utils.h
#include "qemu/host-utils.h"   // needed for clz64 and ctz64

#include "taint_utils.h"
#include "taint2/taint_ops_ins_flags.h"

// needed by the switch
#define tassert(cond) assert((cond))

#define PANDA_MSG ""

const int CB_WIDTH = 128;
const llvm::APInt NOT_LITERAL(CB_WIDTH, ~0UL);

/*
 * Run a test, and print out the results.  Note that not all arguments are used
 * by all tests, and may be dummied up for those tests.
 * Input:
 *    ocname:  The name of the LLVM opcode being tested
 *    opcode:  The LLVM opcode being tested
 *    literals1:  The literal at position 1 in the literals vector
 *    last_literal:  The last literal in the LLVM instruction being tested
 *    size:  The number of bytes the LLVM instruction operates upon
 *    orig_cb_mask:  The original cb mask for the bytes being operated on
 *    orig_zero_mask:  The original zero mask for the bytes being operated on
 *    orig_one_mask:  The original one mask for the bytes being operated on
 *    expected_cb_mask:  The expected cb mask for the bytes being operated on
 *    expected_zero_mask:  The expected zero mask
 *    expected_one_mask:  The expected one mask
 */
static void runTest(const char *ocname, unsigned int opcode,
                    llvm::APInt literals1, llvm::APInt last_literal,
                    uint64_t size, llvm::APInt orig_cb_mask,
                    llvm::APInt orig_zero_mask, llvm::APInt orig_one_mask,
                    llvm::APInt expected_cb_mask,
                    llvm::APInt expected_zero_mask,
                    llvm::APInt expected_one_mask)
{

    // set up some variables needed by the update_cb switch
    int log2 = 0;
    llvm::APInt cb_mask = orig_cb_mask;
    llvm::APInt zero_mask = orig_zero_mask;
    llvm::APInt one_mask = orig_one_mask;

    // fake flags int that will never be used, just so will compile
    uint64_t instruction_flags = 0;

    // really only need literals[1], and then only for some tests
    std::vector<llvm::APInt> literals;
    literals.reserve(2);
    literals.push_back(literals1);
    literals.push_back(literals1);
    
    // the real code being tested
#include "../../update_cb_switch.h"

    // opcode is needed by update_cb_switch.h, but as it changes from LLVM
    // version to version, it is not printed out below

    // and the answers are...
    printf("%s:  size=%ld, lastlit=0x%.16lx%.16lx, orig (cb,0,1) "
           "(0x%.16lx%.16lx, 0x%.16lx%.16lx, 0x%.16lx%.16lx) => new "
           "(0x%.16lx%.16lx, 0x%.16lx%.16lx, 0x%.16lx%.16lx) - ",
           ocname, size, apint_hi_bits(last_literal),
           apint_lo_bits(last_literal), apint_hi_bits(orig_cb_mask),
           apint_lo_bits(orig_cb_mask), apint_hi_bits(orig_zero_mask),
           apint_lo_bits(orig_zero_mask), apint_hi_bits(orig_one_mask),
           apint_lo_bits(orig_one_mask), apint_hi_bits(cb_mask),
           apint_lo_bits(cb_mask), apint_hi_bits(zero_mask),
           apint_lo_bits(zero_mask), apint_hi_bits(one_mask),
           apint_lo_bits(one_mask));
    if ((cb_mask == expected_cb_mask) && (zero_mask == expected_zero_mask) &&
        (one_mask == expected_one_mask)) {
        printf("GOOD\n");
    } else {
        printf("BAD (%.16lx%.16lx, %.16lx%.16lx, %.16lx%.16lx\n",
               apint_hi_bits(expected_cb_mask), apint_lo_bits(expected_cb_mask),
               apint_hi_bits(expected_zero_mask),
               apint_lo_bits(expected_zero_mask),
               apint_hi_bits(expected_one_mask),
               apint_lo_bits(expected_one_mask));
    }
}

int main(int argc, char **argv)
{
    // I am intentionally not calculating the expected results, because such
    // calculations could suffer from the same errors that I am trying to verify
    // have been eradicated from the update_cb function.  Instead, I am figuring
    // out the expected values manually and entering them in explicitly below.
    
    // LLVM Sub has no bit twiddling
    
    // LLVM Add
    printf("===== TESTING LLVM ADD INSTRUCTION =====\n");
    unsigned int opcode = llvm::Instruction::Add;
    llvm::APInt literals1 =
        make_128bit_apint(0, 0); // not really needed for this test
    llvm::APInt last_literal = make_128bit_apint(0, 4);
    uint64_t size = 4;       // not really needed for this test

    // as the same calculation is done for zero and one masks, can test 2
    // scenarios with one test (the controlled bits mask isn't changed)
    llvm::APInt cb_mask = make_128bit_apint(0, 0xfeedface);
    llvm::APInt expect_cb = cb_mask;
    llvm::APInt zero_mask = make_128bit_apint(0, 0xfffffffffffffffe);
    llvm::APInt expect_zero = make_128bit_apint(0, 0xfffffffffffffff8);
    llvm::APInt one_mask = make_128bit_apint(0, 0xbaadf00d);
    llvm::APInt expect_one = make_128bit_apint(0, 0xbaadf008);
    runTest("Add", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);

    expect_one = 0xbadf008;
    one_mask = 0xbadf00d;
    zero_mask = 0;
    expect_zero = 0;
    runTest("Add", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0x3ade68b1;
    cb_mask = 0xfffffffffffffffe;
    expect_cb = cb_mask;
    zero_mask = 0xbaadf00d;
    expect_zero = 0x80000000;
    one_mask = 0xfffffffffffffffe;
    expect_one = 0xffffffffc0000000;
    runTest("Add", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    zero_mask = 0xbadf00d;
    expect_zero = 0;
    one_mask = 0;
    expect_one = 0;
    runTest("Add", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0xffffffff;
    zero_mask = 0xfffffffffffffffe;
    expect_zero = 0xffffffff00000000;
    one_mask = 0xbaadf00d;
    expect_one = 0;
    runTest("Add", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    zero_mask = 0xbadf00d;
    expect_zero = 0;
    one_mask = 0;
    expect_one = 0;
    runTest("Add", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0x807060504030201f;
    zero_mask = 0xfffffffffffffffe;
    expect_zero = 0;
    one_mask = 0xbaadf00d;
    expect_one = 0;
    runTest("Add", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    zero_mask = 0xbadf00d;
    expect_zero = 0;
    one_mask = 0;
    expect_one = 0;
    runTest("Add", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0;
    zero_mask = 0x600df00d;
    expect_zero = 0x600df00d;
    one_mask = 0;
    expect_one = 0;
    runTest("Add", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 0xfeedface600df00d;
    zero_mask = 0xfffffffffffffffe;
    expect_zero = 0x0;
    one_mask = 0;
    expect_one = 0;
    runTest("Add", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    // LLVM Xor is not problematic
    // LLVM ZExt and the others in that group do nothing, so easy to get right!
    
    // LLVM Trunc
    // as the same calculation is done for all 3 masks, can test 3 scenarios
    // with one test
    printf("===== TESTING LLVM TRUNC INSTRUCTION =====\n");
    opcode = llvm::Instruction::Trunc;
    literals1 = 0;  // not really needed for this test
    last_literal = 0;  // not really needed
    size = 4;
    cb_mask = 0xfeedface;
    expect_cb = 0xfeedface;
    zero_mask = 0x600df00d;
    expect_zero = 0x600df00d;
    one_mask = 0;
    expect_one = 0;
    runTest("Trunc", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    cb_mask = 0x0;
    expect_cb = 0x0;
    zero_mask = 0xfeedface600df00d;
    expect_zero = 0x600df00d;
    one_mask = 0x600df00dfeed;
    expect_one = 0xf00dfeed;
    runTest("Trunc", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    size = 2;
    cb_mask = 0xfeedface;
    expect_cb = 0xface;
    expect_zero = 0xf00d;
    expect_one = 0xfeed;
    runTest("Trunc", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0;
    expect_cb = 0;
    zero_mask = 0x600d;
    expect_zero = 0x600d;
    one_mask = 0xe6650102;
    expect_one = 0x102;
    runTest("Trunc", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);

    // as largest size is 8 bytes, a trunc to i64 really does nothing
    size = 8;
    cb_mask = 0;
    expect_cb = 0;
    zero_mask = 0xe665600df00d;
    expect_zero = zero_mask;
    one_mask = 0xe665;
    expect_one = one_mask;
    runTest("Trunc", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    // LLVM Mul
    // zero_mask is the one worried about - other 2 are trivial
    printf("===== TESTING LLVM MUL INSTRUCTION =====\n");
    opcode = llvm::Instruction::Mul;
    size = 4;    // doesn't really matter
    last_literal = 4;
    literals1 = 0;    // doesn't really matter
    cb_mask = 0xbadf00d;
    expect_cb = 0x2eb7c034;
    zero_mask = 0xbadf00d;
    expect_zero = 3;
    one_mask = cb_mask;
    expect_one = 0;
    runTest("Mul", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 5;
    expect_cb = 0xbadf00d;
    expect_zero = 0;
    runTest("Mul", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0xf0000000;
    expect_cb = 0xbadf00d0000000;
    expect_zero = 0xfffffff;
    runTest("Mul", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0xf0000001;
    expect_cb = 0xbadf00d;
    expect_zero = 0;
    runTest("Mul", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 0x12345678901;
    expect_cb = 0xbadf00d;
    expect_zero = 0;
    runTest("Mul", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0x12345678900;
    expect_cb = 0xbadf00d00;
    expect_zero = 0xff;
    runTest("Mul", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0x1000000000;
    cb_mask = 0x600df00d;
    expect_cb = make_128bit_apint(0x6, 0x00df00d000000000);
    zero_mask = cb_mask;
    expect_zero = 0xfffffffff;
    runTest("Mul", opcode, literals1, last_literal, size, cb_mask, zero_mask,
       one_mask, expect_cb, expect_zero, expect_one);
    
    // LLVM URem or SRem
    // only cb_mask has any bit twiddling - other 2 fixed to 0 for results
    printf("===== TESTING LLVM UREM INSTRUCTION =====\n");
    opcode = llvm::Instruction::URem;
    last_literal = 4;
    cb_mask = 0xfffffffffffffffe;
    expect_cb = 0x6;
    zero_mask = cb_mask;
    expect_zero = 0;
    one_mask = cb_mask;
    expect_one = 0;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0x3ade68b1;
    expect_cb = 0x3ffffffe;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);    
    
    last_literal = 0xffffffff;
    expect_cb = 0xfffffffe;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);  
    
    last_literal = 0x3e7fffffff3;
    expect_cb = 0x3fffffffffe;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0xfeedface600df00d;
    expect_cb = 0xfffffffffffffffe;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);    

    last_literal = 4;
    cb_mask = 0xbaadf00d;
    expect_cb = 0x5;
    zero_mask = cb_mask;
    expect_zero = 0;
    one_mask = cb_mask;
    expect_one = 0;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0x3ade68b1;
    expect_cb = 0x3aadf00d;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);    
    
    last_literal = 0xffffffff;
    expect_cb = 0xbaadf00d;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);  
    
    last_literal = 0x3e7fffffff3;
    expect_cb = 0xbaadf00d;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 0xfeedface600df00d;
    expect_cb = 0xbaadf00d;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xbadf00d;
    expect_cb = 0x5;
    zero_mask = cb_mask;
    expect_zero = 0;
    one_mask = cb_mask;
    expect_one = 0;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0x3ade68b1;
    expect_cb = 0xbadf00d;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);    
    
    last_literal = 0xffffffff;
    expect_cb = 0xbadf00d;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);  
    
    last_literal = 0x3e7fffffff3;
    expect_cb = 0xbadf00d;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 0xfeedface600df00d;
    expect_cb = 0xbadf00d;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0;
    expect_cb = 0;
    zero_mask = cb_mask;
    expect_zero = 0;
    one_mask = cb_mask;
    expect_one = 0;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0x3ade68b1;
    expect_cb = 0;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);    
    
    last_literal = 0xffffffff;
    expect_cb = 0;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);  
    
    last_literal = 0x3e7fffffff3;
    expect_cb = 0;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 0xfeedface600df00d;
    expect_cb = 0x0;
    runTest("URem", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    // LLVM UDiv or SDiv
    // only cb_mask is bit twiddled - other 2 results fixed to 0
    printf("===== TESTING LLVM SDIV INSTRUCTION =====\n");
    opcode = llvm::Instruction::SDiv;
    last_literal = 4;
    cb_mask = 0xfffffffffffffffe;
    expect_cb = 0x1fffffffffffffff;
    zero_mask = 0x600d;
    expect_zero = 0;
    one_mask = zero_mask;
    expect_one = 0;
    runTest("SDiv", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0x3ade68b1;
    expect_cb = 0x3ffffffff;
    runTest("SDiv", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0xffffffff;
    expect_cb = 0xffffffff;
    runTest("SDiv", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0x3e7fffffff3;
    expect_cb = 0x3fffff;
    runTest("SDiv", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 0x7eedface600df00d;
    expect_cb = 1;
    runTest("SDiv", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0xfeedface600df00d;
    expect_cb = 0;
    runTest("SDiv", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 4;
    cb_mask = 0xbaadf00d;
    expect_cb = 0x1755be01;
    runTest("SDiv", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0x3ade68b1;
    expect_cb = 0x2;
    runTest("SDiv", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0xffffffff;
    expect_cb = 0;
    runTest("SDiv", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xbadf00d;
    expect_cb = 0x175be01;
    runTest("SDiv", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0x3ade68b1;
    expect_cb = 0;
    runTest("SDiv", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0;
    expect_cb = 0;
    runTest("SDiv", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);    
    
    // LLVM And is not problematic
    // LLVM Or is not problematic
    
    // LLVM Shl
    // cb_mask and one_mask are calculated the same, but zero_mask is special
    printf("===== TESTING LLVM SHL INSTRUCTION =====\n");
    opcode = llvm::Instruction::Shl;
    last_literal = 0;
    cb_mask = 0;
    expect_cb = 0;
    zero_mask = 0;
    expect_zero = 0;
    one_mask = 0xaa;
    expect_one = 0xaa;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0xfeedface;
    expect_cb = 0xfeedface;
    zero_mask = 0xfade;
    expect_zero = 0xfade;
    one_mask = 0xe66600df00d;
    expect_one = 0xe66600df00d;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0xbadfaceba01c1234;
    expect_cb = 0xbadfaceba01c1234;
    zero_mask = 0x80000000;
    expect_zero = 0x80000000;
    one_mask = 0xe66600df00d;
    expect_one = 0xe66600df00d;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0xbadfaceba01c1234;
    expect_cb = 0xbadfaceba01c1234;
    zero_mask = 0x8000000000000;
    expect_zero = 0x8000000000000;
    one_mask = 0xe66600df00d;
    expect_one = 0xe66600df00d;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0xbadfaceba01c1234;
    expect_cb = 0xbadfaceba01c1234;
    zero_mask = 0x8000000000000000;
    expect_zero = 0x8000000000000000;
    one_mask = 0xe66600df00d;
    expect_one = 0xe66600df00d;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 2;
    cb_mask = 0;
    expect_cb = 0;
    zero_mask = 0;
    expect_zero = 3;
    one_mask = 0xaa;
    expect_one = 0x2a8;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0xfeedface;
    expect_cb = 0x3fbb7eb38;
    zero_mask = 0xfade;
    expect_zero = 0x3eb7b;
    one_mask = 0xe66600df00d;
    expect_one = 0x39998037c034;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0xbadfaceba01c1234;
    expect_cb = make_128bit_apint(0x2, 0xeb7eb3ae807048d0);
    zero_mask = 0x80000000;
    expect_zero = 0x200000003;
    one_mask = 0xe66600df00d;
    expect_one = 0x39998037c034;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0xbadfaceba01c1234;
    expect_cb = make_128bit_apint(0x2, 0xeb7eb3ae807048d0);
    zero_mask = 0x8000000000000;
    expect_zero = 0x20000000000003;
    one_mask = 0xe66600df00d;
    expect_one = 0x39998037c034;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0xbadfaceba01c1234;
    expect_cb = make_128bit_apint(0x2, 0xeb7eb3ae807048d0);
    zero_mask = 0x8000000000000000;
    expect_zero = make_128bit_apint(0x2, 0x3);
    one_mask = 0xe66600df00d;
    expect_one = 0x39998037c034;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 24;
    cb_mask = 0;
    expect_cb = 0;
    zero_mask = 0xfade;
    expect_zero = 0xfadeffffff;
    one_mask = 0xaa;
    expect_one = 0xaa000000;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0xfeedface;
    expect_cb = 0xfeedface000000;
    zero_mask = 0x80000000;
    expect_zero = 0x80000000ffffff;
    one_mask = 0xe66600df00d;
    expect_one = make_128bit_apint(0xe, 0x66600df00d000000);
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
            one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0xbadfaceba01c1234;
    expect_cb = make_128bit_apint(0xbadfac, 0xeba01c1234000000);
    zero_mask = 0x8000000000000;
    expect_zero = make_128bit_apint(0x800, 0xffffff);
    one_mask = 0xe66600df00d;
    expect_one = make_128bit_apint(0xe, 0x66600df00d000000);
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0xbadfaceba01c1234;
    expect_cb = make_128bit_apint(0xbadfac, 0xeba01c1234000000);
    zero_mask = 0x8000000000000000;
    expect_zero = make_128bit_apint(0x800000, 0xffffff);
    one_mask = 0xe66600df00d;
    expect_one = make_128bit_apint(0xe, 0x66600df00d000000);
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 32;
    cb_mask = 0;
    expect_cb = 0;
    zero_mask = 0xfade;
    expect_zero = 0xfadeffffffff;
    one_mask = 0xaa;
    expect_one = 0xaa00000000;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 52;
    cb_mask = 0;
    expect_cb = 0;
    zero_mask = 0xfade;
    expect_zero = make_128bit_apint(0xf, 0xadefffffffffffff);
    one_mask = 0xaa;
    expect_one = 0xaa0000000000000;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    cb_mask = 0xfeedface;
    expect_cb = make_128bit_apint(0xfeedf, 0xace0000000000000);
    zero_mask = 0x80000000;
    expect_zero = make_128bit_apint(0x80000, 0xfffffffffffff);
    one_mask = 0xe66600df00d;
    expect_one = make_128bit_apint(0xe66600df, 0xd0000000000000);
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    cb_mask = 0xbadfaceba01c1234;
    expect_cb = make_128bit_apint(0xbadfaceba01c1, 0x2340000000000000);
    zero_mask = 0x8000000000000;
    expect_zero = make_128bit_apint(0x8000000000, 0xfffffffffffff);
    one_mask = 0xe66600df00d;
    expect_one = make_128bit_apint(0xe66600df, 0xd0000000000000);
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 96;
    cb_mask = 0xbadfaceba01c1234;
    expect_cb = make_128bit_apint(0xa01c123400000000, 0x0);
    zero_mask = 0x8000000000000;
    expect_zero = make_128bit_apint(0xffffffff, 0xffffffffffffffff);
    one_mask = 0xcafebabe0;
    expect_one = make_128bit_apint(0x0, 0xafebabe0) << 96;
    runTest("Shl", opcode, literals1, last_literal, size, cb_mask, zero_mask,
            one_mask, expect_cb, expect_zero, expect_one);

    // TODO LLVM LShr
    // cb_mask and one_mask updates are the same, trivial operations
    // zero_mask is the only one that really needs tested
    printf("===== TESTING LLVM LSHR INSTRUCTION =====\n");
    opcode = llvm::Instruction::LShr;
    size = 8;
    last_literal = 0;
    cb_mask = 0;
    expect_cb = 0;
    zero_mask = 0;
    expect_zero = 0;
    one_mask = 0xaa;
    expect_one = 0xaa;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    expect_cb = 0;
    expect_zero = make_128bit_apint(0xffffffffffffffff, 0xf000000000000000);
    expect_one = 0xa;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0;
    cb_mask = 0xfeedface;
    expect_cb = 0xfeedface;
    zero_mask = 0x600d;
    expect_zero = 0x600d;
    one_mask = 0xe66600df00d;
    expect_one = 0xe66600df00d;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xbadfaceba01c1234;
    expect_cb = 0xbadfaceba01c123;
    expect_zero = make_128bit_apint(0xffffffffffffffff, 0xf000000000000600);
    expect_one = 0xe66600df00;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 32;
    cb_mask = 0;
    expect_cb = 0;
    expect_zero = make_128bit_apint(0xffffffffffffffff, 0xffffffff00000000);
    one_mask = 0xaa;
    expect_one = 0;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 40;
    cb_mask = 0;
    expect_cb = 0;
    expect_zero = make_128bit_apint(0xffffffffffffffff, 0xffffffffff000000);
    one_mask = 0xaa;
    expect_one = 0;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0;
    cb_mask = 0xbadfaceba01c1234;
    expect_cb = 0xbadfaceba01c1234;
    zero_mask = 0x600df00d;
    expect_zero = 0x600df00d;
    one_mask = 0xe66600df00d;
    expect_one = 0xe66600df00d;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xfeedface;
    expect_cb = 0xfeedfac;
    expect_zero = make_128bit_apint(0xffffffffffffffff, 0xf00000000600df00);
    expect_one = 0xe66600df00;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 32;
    expect_cb = 0;
    expect_zero = make_128bit_apint(0xffffffffffffffff, 0xffffffff00000000);
    one_mask = 0xe66600df00d;
    expect_one = 0xe66;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 40;
    cb_mask = 0;
    expect_cb = 0;
    expect_zero = make_128bit_apint(0xffffffffffffffff, 0xffffffffff000000);
    expect_one = 0xe;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 0;
    cb_mask = 0xbadfaceba01c1234;
    expect_cb = 0xbadfaceba01c1234;
    zero_mask = 0xae66f00d;
    expect_zero = 0xae66f00d;
    one_mask = 0xe66600df00d;
    expect_one = 0xe66600df00d;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xfeedface;
    expect_cb = 0xfeedfac;
    expect_zero = make_128bit_apint(~0ULL, 0xf00000000ae66f00);
    expect_one = 0xe66600df00;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 32;
    expect_cb = 0;
    expect_zero = make_128bit_apint(~0ULL, 0xffffffff00000000);
    one_mask = 0xbadfaceba01c1234;
    expect_one = 0xbadfaceb;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 40;
    cb_mask = 0;
    expect_cb = 0;
    expect_zero = make_128bit_apint(~0ULL, 0xffffffffff000000);
    expect_one = 0xbadfac;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 0;
    cb_mask = 0xfeed;
    expect_cb = 0xfeed;
    zero_mask = 0x600de66f00d;
    expect_zero = 0x600de66f00d;
    one_mask = 0xe66600df00d;
    expect_one = 0xe66600df00d;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xfeedface;
    expect_cb = 0xfeedfac;
    expect_zero = make_128bit_apint(~0ULL, 0xf00000600de66f00);
    expect_one = 0xe66600df00;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 32;
    expect_cb = 0;
    expect_zero = make_128bit_apint(~0ULL, 0xffffffff00000600);
    one_mask = 0xbadfaceba01c1234;
    expect_one = 0xbadfaceb;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 40;
    cb_mask = 0;
    expect_cb = 0;
    expect_zero = make_128bit_apint(~0ULL, 0xffffffffff000006);
    expect_one = 0xbadfac;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xbadc110;
    expect_cb = 0xbadc11;
    zero_mask = 0xaaaa555588881111;
    expect_zero = make_128bit_apint(~0ULL, 0xfaaaa55558888111);
    one_mask = 0xbad8111a49;
    expect_one = 0xbad8111a4;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xbadc110;
    expect_cb = 0xbadc11;
    zero_mask = 0xaa;
    expect_zero = make_128bit_apint(~0ULL, 0xf00000000000000a);
    one_mask = 0xbad8111a49;
    expect_one = 0xbad8111a4;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 2;
    cb_mask = 0x42;
    expect_cb = 0x10;
    zero_mask = 0x5;
    expect_zero = make_128bit_apint(~0ULL, 0xc000000000000001);
    one_mask = 0xfa;
    expect_one = 0x3e;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    size = 4;
    last_literal = 0;
    cb_mask = 0;
    expect_cb = 0;
    zero_mask = 0;
    expect_zero = 0;
    one_mask = 0xaa;
    expect_one = 0xaa;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    expect_cb = 0;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffff0000000);
    expect_one = 0xa;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0;
    cb_mask = 0xfeedface;
    expect_cb = 0xfeedface;
    zero_mask = 0x600d;
    expect_zero = 0x600d;
    one_mask = 0xe66600df00d;
    expect_one = 0xe66600df00d;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xbadfaceba01c1234;
    expect_cb = 0xbadfaceba01c123;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffff0000600);
    expect_one = 0xe66600df00;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0;
    cb_mask = 0xbadfaceba01c1234;
    expect_cb = 0xbadfaceba01c1234;
    zero_mask = 0x600df00d;
    expect_zero = 0x600df00d;
    one_mask = 0xe66600df00d;
    expect_one = 0xe66600df00d;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xfeedface;
    expect_cb = 0xfeedfac;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffff600df00);
    expect_one = 0xe66600df00;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 0;
    cb_mask = 0xbadfaceba01c1234;
    expect_cb = 0xbadfaceba01c1234;
    zero_mask = 0xae66f00d;
    expect_zero = 0xae66f00d;
    one_mask = 0xe66600df00d;
    expect_one = 0xe66600df00d;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xfeedface;
    expect_cb = 0xfeedfac;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffffae66f00);
    expect_one = 0xe66600df00;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xbadc110;
    expect_cb = 0xbadc11;
    zero_mask = 0xaa;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffff000000a);
    one_mask = 0xbad8111a49;
    expect_one = 0xbad8111a4;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 2;
    cb_mask = 0x42;
    expect_cb = 0x10;
    zero_mask = 0x5;
    expect_zero = make_128bit_apint(~0ULL, 0xffffffffc0000001);
    one_mask = 0xfa;
    expect_one = 0x3e;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    size = 2;
    last_literal = 0;
    cb_mask = 0;
    expect_cb = 0;
    zero_mask = 0;
    expect_zero = 0;
    one_mask = 0xaa;
    expect_one = 0xaa;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    expect_cb = 0;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffffffff000);
    expect_one = 0xa;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0;
    cb_mask = 0xfeedface;
    expect_cb = 0xfeedface;
    zero_mask = 0x600d;
    expect_zero = 0x600d;
    one_mask = 0xe66600df00d;
    expect_one = 0xe66600df00d;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xbadfaceba01c1234;
    expect_cb = 0xbadfaceba01c123;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffffffff600);
    expect_one = 0xe66600df00;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xbadc110;
    expect_cb = 0xbadc11;
    zero_mask = 0xaa;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffffffff00a);
    one_mask = 0xbad8111a49;
    expect_one = 0xbad8111a4;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 2;
    cb_mask = 0x42;
    expect_cb = 0x10;
    zero_mask = 0x5;
    expect_zero = make_128bit_apint(~0ULL, 0xffffffffffffc001);
    one_mask = 0xfa;
    expect_one = 0x3e;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    size = 1;
    last_literal = 0;
    cb_mask = 0;
    expect_cb = 0;
    zero_mask = 0;
    expect_zero = 0;
    one_mask = 0xaa;
    expect_one = 0xaa;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    expect_cb = 0;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffffffffff0);
    expect_one = 0xa;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    cb_mask = 0xbadc110;
    expect_cb = 0xbadc11;
    zero_mask = 0xaa;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffffffffffa);
    one_mask = 0xbad8111a49;
    expect_one = 0xbad8111a4;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 2;
    cb_mask = 0x42;
    expect_cb = 0x10;
    zero_mask = 0x5;
    expect_zero = make_128bit_apint(~0ULL, 0xffffffffffffffc1);
    one_mask = 0xfa;
    expect_one = 0x3e;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 4;
    cb_mask = make_128bit_apint(0xffffffffffffffff, 0x0);
    expect_cb = make_128bit_apint(0x0fffffffffffffff, 0xf000000000000000);
    zero_mask = 0xaa;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffffffffffa);
    one_mask = 0xbad8111a49;
    expect_one = 0xbad8111a4;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
            one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 96;
    size = 16;
    cb_mask = make_128bit_apint(0xf, 0x0);
    expect_cb = 0x0;
    zero_mask = 0xaa;
    expect_zero = make_128bit_apint(~0ULL, 0xffffffff00000000);
    one_mask = 0xbad8111a49;
    expect_one = 0x0;
    runTest("LShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
            one_mask, expect_cb, expect_zero, expect_one);

    // TODO LLVM AShr
    // cb_mask is trivial; one and zero masks have special twiddling
    printf("===== TESTING LLVM ASHR INSTRUCTION =====\n");
    opcode = llvm::Instruction::AShr;
    
    size = 1;
    last_literal = 0;
    cb_mask = 0;
    expect_cb = 0;
    zero_mask = 0;
    expect_zero = 0;
    one_mask = 0x90;
    expect_one = 0x90;
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    // watch it! in real life (and update_cb_switch.h), you'd never have both
    // the top bit 0 and top bit 1 at same time, so have to test sign extension
    // of zero_mask and sign extension of one_mask in separate tests
    last_literal = 4;
    expect_cb = 0;
    expect_zero = 0;
    expect_one = make_128bit_apint(~0ULL, 0xfffffffffffffff9);
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 0;
    cb_mask = 0x90;
    expect_cb = 0x90;
    zero_mask = 0x90;
    expect_zero = 0x90;
    one_mask = 0;
    expect_one = 0;
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    last_literal = 4;
    expect_cb = 0x9;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffffffffff9);
    one_mask = 0x56;
    expect_one = 0x5;
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    expect_cb = 0x9;
    zero_mask = 0x56;
    expect_zero = 0x5;
    one_mask = 0x90;
    expect_one = make_128bit_apint(~0ULL, 0xfffffffffffffff9);
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    size = 2;
    last_literal = 6;
    cb_mask = 0x600d;
    expect_cb = 0x180;
    zero_mask = 0x600d;
    expect_zero = 0x180;
    one_mask = 0xf00d;
    expect_one = make_128bit_apint(~0ULL, 0xffffffffffffffc0);
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    cb_mask = 0xf00d;
    expect_cb = 0x3c0;
    zero_mask = 0xf00d;
    expect_zero = make_128bit_apint(~0ULL, 0xffffffffffffffc0);
    one_mask = 0x600d;
    expect_one = 0x180;
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    size = 4;
    last_literal = 8;
    cb_mask = 0xe66f00d;
    expect_cb = 0xe66f0;
    zero_mask = 0xe66f00d;
    expect_zero = 0xe66f0;
    one_mask = 0xe665f00d;
    expect_one = make_128bit_apint(~0ULL, 0xffffffffffe665f0);
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    cb_mask = 0xe665f00d;
    expect_cb = 0xe665f0;
    zero_mask = 0xe665f00d;
    expect_zero = make_128bit_apint(~0ULL, 0xffffffffffe665f0);
    one_mask = 0xe66f00d;
    expect_one = 0xe66f0;
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    size = 8;
    last_literal = 40;
    cb_mask = 0x600df00dfeedface;
    expect_cb = 0x600df0;
    zero_mask = 0xfeedface600df00d;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffffffeedfa);
    one_mask = 0x600df00dfeedface;
    expect_one = 0x600df0;
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);
    
    cb_mask = 0xfeedface600df00d;
    expect_cb = 0xfeedfa;
    zero_mask = 0xfeedface600df00d;
    expect_zero = make_128bit_apint(~0ULL, 0xfffffffffffeedfa);
    one_mask = 0x600df00dfeedface;
    expect_one = 0x600df0;
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
        one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 96;
    size = 16;
    cb_mask = make_128bit_apint(0xfeedface600df00d, 0x0);
    expect_cb = 0xfeedface;
    zero_mask = 0xfeedface600df00d;
    expect_zero = 0;
    one_mask = make_128bit_apint(0x800df00dfeedface, 0x0);
    expect_one = make_128bit_apint(~0ULL, 0xffffffff800df00d);
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
            one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 96;
    size = 16;
    cb_mask = make_128bit_apint(0xfeedface600df00d, 0x0);
    expect_cb = 0xfeedface;
    zero_mask = 0xfeedface600df00d;
    expect_zero = 0;
    one_mask = make_128bit_apint(0x800df00dfeedface, 0x0);
    expect_one = make_128bit_apint(~0ULL, 0xffffffff800df00d);
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
            one_mask, expect_cb, expect_zero, expect_one);

    last_literal = 96;
    size = 16;
    cb_mask = make_128bit_apint(0xfeedface600df00d, 0x0);
    expect_cb = 0xfeedface;
    zero_mask = make_128bit_apint(0x800df00dfeedface, 0x0);
    expect_zero = make_128bit_apint(~0ULL, 0xffffffff800df00d);
    one_mask = 0xfeedface600df00d;
    expect_one = 0;
    runTest("AShr", opcode, literals1, last_literal, size, cb_mask, zero_mask,
            one_mask, expect_cb, expect_zero, expect_one);

    // LLVM FAdd and the others in that group are not problemeatic
    
    // LLVM GetElementPtr is not problematic
   
    return 0;
}

