#!/bin/sh
# Script to test if gcc "-fwhole-program" works properly.

mkdir -p out
TMPFILE1=out/tmp_testcompile1.c
TMPFILE1o=out/tmp_testcompile1.o
TMPFILE1_ld=out/tmp_testcompile1.lds
TMPFILE2=out/tmp_testcompile2.c
TMPFILE2o=out/tmp_testcompile2.o
TMPFILE3o=out/tmp_testcompile3.o

# Test if ld's alignment handling is correct.  This is a known problem
# with the linker that ships with Ubuntu 11.04.
cat - > $TMPFILE1 <<EOF
const char v1[] __attribute__((section(".text.v1"))) = "0123456789";
const char v2[] __attribute__((section(".text.v2"))) = "0123456789";
EOF
cat - > $TMPFILE1_ld <<EOF
SECTIONS
{
     .mysection 0x88f0 : {
. = 0x10 ;
*(.text.v1)
. = 0x20 ;
*(.text.v2)
. = 0x30 ;
     }
}
EOF
$CC -O -g -c $TMPFILE1 -o $TMPFILE1o > /dev/null 2>&1
$LD -T $TMPFILE1_ld $TMPFILE1o -o $TMPFILE2o > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "The version of LD on this system does not properly handle" > /dev/fd/2
    echo "alignments.  As a result, this project can not be built." > /dev/fd/2
    echo "" > /dev/fd/2
    echo "The problem may be the result of this LD bug report:" > /dev/fd/2
    echo " http://sourceware.org/bugzilla/show_bug.cgi?id=12726" > /dev/fd/2
    echo "" > /dev/fd/2
    echo "Please update to a working version of binutils and retry." > /dev/fd/2
    echo -1
    exit 0
fi

# Test for "-fwhole-program".  Older versions of gcc (pre v4.1) don't
# support the whole-program optimization - detect that.
$CC -fwhole-program -S -o /dev/null -xc /dev/null > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "  Working around no -fwhole-program" > /dev/fd/2
    echo 2
    exit 0
fi

# Test if "visible" variables and functions are marked global.  On
# OpenSuse 10.3 "visible" variables declared with "extern" first
# aren't marked as global in the resulting assembler.  On Ubuntu 7.10
# "visible" functions aren't marked as global in the resulting
# assembler.
cat - > $TMPFILE1 <<EOF
void __attribute__((externally_visible)) t1() { }
extern unsigned char v1;
unsigned char v1 __attribute__((section(".data16.foo.19"))) __attribute__((externally_visible));
EOF
$CC -Os -c -fwhole-program $TMPFILE1 -o $TMPFILE1o > /dev/null 2>&1
cat - > $TMPFILE2 <<EOF
void t1();
extern unsigned char v1;
int __attribute__((externally_visible)) main() { t1(); return v1; }
EOF
$CC -Os -c -fwhole-program $TMPFILE2 -o $TMPFILE2o > /dev/null 2>&1
$CC -nostdlib -Os $TMPFILE1o $TMPFILE2o -o $TMPFILE3o > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "  Working around non-functional -fwhole-program" > /dev/fd/2
    echo 2
    exit 0
fi

# Test if "-combine" works.  On Ubuntu 8.04 the compiler doesn't work
# correctly with combine and the "struct bregs" register due to the
# anonymous unions and structs.  On Fedora Core 12 the compiler throws
# an internal compiler error when multiple files access global
# variables with debugging enabled.
cat - > $TMPFILE1 <<EOF
// Look for anonymous union/struct failure
struct ts { union { int u1; struct { int u2; }; }; };
void func1(struct ts *r);

// Look for global variable failure.
struct s1_s { int v; } g1;
void __attribute__((externally_visible)) func2() {
    struct s1_s *l1 = &g1;
    l1->v=0;
}
EOF
cat - > $TMPFILE2 <<EOF
struct ts { union { int u1; struct { int u2; }; }; };
void func1(struct ts *r);

extern struct s1_s g1;
void func3() {
    &g1;
}
EOF
$CC -O -g -fwhole-program -combine -c $TMPFILE1 $TMPFILE2 -o $TMPFILE1o > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo 0
else
    echo "  Working around non-functional -combine" > /dev/fd/2
    echo 1
fi

# Also, on several compilers, -combine fails if code is emitted with a
# reference to an extern variable that is later found to be externally
# visible - the compiler does not mark those variables as global.
# This is being worked around by ordering the compile objects to avoid
# this case.

# Also, the Ubuntu 8.04 compiler has a bug causing corruption when the
# "ebp" register is clobberred in an "asm" statement.  The code has
# been modified to not clobber "ebp" - no test is available yet.

rm -f $TMPFILE1 $TMPFILE1o $TMPFILE1_ld $TMPFILE2 $TMPFILE2o $TMPFILE3o
