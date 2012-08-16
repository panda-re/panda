#include <string.h>

/*
 * This file exists for testing the compilation of memcpy() with the
 * various constant-length optimisations.
 *
 */

#define __regparm __attribute__ (( regparm(3) ))

void __regparm memcpy_0 ( void *dest, void *src ) { memcpy ( dest, src, 0 ); }
void __regparm memcpy_1 ( void *dest, void *src ) { memcpy ( dest, src, 1 ); }
void __regparm memcpy_2 ( void *dest, void *src ) { memcpy ( dest, src, 2 ); }
void __regparm memcpy_3 ( void *dest, void *src ) { memcpy ( dest, src, 3 ); }
void __regparm memcpy_4 ( void *dest, void *src ) { memcpy ( dest, src, 4 ); }
void __regparm memcpy_5 ( void *dest, void *src ) { memcpy ( dest, src, 5 ); }
void __regparm memcpy_6 ( void *dest, void *src ) { memcpy ( dest, src, 6 ); }
void __regparm memcpy_7 ( void *dest, void *src ) { memcpy ( dest, src, 7 ); }
void __regparm memcpy_8 ( void *dest, void *src ) { memcpy ( dest, src, 8 ); }
void __regparm memcpy_9 ( void *dest, void *src ) { memcpy ( dest, src, 9 ); }
void __regparm memcpy_10 ( void *dest, void *src ) { memcpy ( dest, src, 10 ); }
void __regparm memcpy_11 ( void *dest, void *src ) { memcpy ( dest, src, 11 ); }
void __regparm memcpy_12 ( void *dest, void *src ) { memcpy ( dest, src, 12 ); }
void __regparm memcpy_13 ( void *dest, void *src ) { memcpy ( dest, src, 13 ); }
void __regparm memcpy_14 ( void *dest, void *src ) { memcpy ( dest, src, 14 ); }
void __regparm memcpy_15 ( void *dest, void *src ) { memcpy ( dest, src, 15 ); }
void __regparm memcpy_16 ( void *dest, void *src ) { memcpy ( dest, src, 16 ); }
void __regparm memcpy_17 ( void *dest, void *src ) { memcpy ( dest, src, 17 ); }
void __regparm memcpy_18 ( void *dest, void *src ) { memcpy ( dest, src, 18 ); }
void __regparm memcpy_19 ( void *dest, void *src ) { memcpy ( dest, src, 19 ); }
void __regparm memcpy_20 ( void *dest, void *src ) { memcpy ( dest, src, 20 ); }
void __regparm memcpy_21 ( void *dest, void *src ) { memcpy ( dest, src, 21 ); }
void __regparm memcpy_22 ( void *dest, void *src ) { memcpy ( dest, src, 22 ); }
void __regparm memcpy_23 ( void *dest, void *src ) { memcpy ( dest, src, 23 ); }
void __regparm memcpy_24 ( void *dest, void *src ) { memcpy ( dest, src, 24 ); }
void __regparm memcpy_25 ( void *dest, void *src ) { memcpy ( dest, src, 25 ); }
void __regparm memcpy_26 ( void *dest, void *src ) { memcpy ( dest, src, 26 ); }
void __regparm memcpy_27 ( void *dest, void *src ) { memcpy ( dest, src, 27 ); }
void __regparm memcpy_28 ( void *dest, void *src ) { memcpy ( dest, src, 28 ); }
