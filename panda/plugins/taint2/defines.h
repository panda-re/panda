/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
 PANDAENDCOMMENT */

#ifndef __TAINT2_DEFINES_H__
#define __TAINT2_DEFINES_H__

#define EXCEPTIONSTRING "3735928559"  // 0xDEADBEEF read from dynamic log
#define OPNAMELENGTH 15
#define FUNCNAMELENGTH 50
#define FUNCTIONFRAMES 10 // handle 10 frames for now, should be sufficient
#define MAXREGSIZE 16 // Maximum LLVM register size is 8 bytes
#define MAXFRAMESIZE 5000 // maximum number of LLVM values a function can use.

#endif
