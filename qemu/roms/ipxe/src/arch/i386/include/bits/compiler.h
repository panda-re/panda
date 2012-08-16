#ifndef _BITS_COMPILER_H
#define _BITS_COMPILER_H

FILE_LICENCE ( GPL2_OR_LATER );

#ifndef ASSEMBLY

/** Declare a function with standard calling conventions */
#define __asmcall __attribute__ (( cdecl, regparm(0) ))

/**
 * Declare a function with libgcc implicit linkage
 *
 * It seems as though gcc expects its implicit arithmetic functions to
 * be cdecl, even if -mrtd is specified.  This is somewhat
 * inconsistent; for example, if -mregparm=3 is used then the implicit
 * functions do become regparm(3).
 *
 * The implicit calls to memcpy() and memset() which gcc can generate
 * do not seem to have this inconsistency; -mregparm and -mrtd affect
 * them in the same way as any other function.
 */
#define __libgcc __attribute__ (( cdecl ))

#endif /* ASSEMBLY */

#endif /* _BITS_COMPILER_H */
