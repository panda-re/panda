#ifndef _STRINGS_H
#define _STRINGS_H

FILE_LICENCE ( GPL2_OR_LATER );

#include <limits.h>
#include <string.h>

static inline __attribute__ (( always_inline )) int
__constant_flsl ( unsigned long x ) {
	int r = 0;

#if ULONG_MAX > 0xffffffff
	if ( x & 0xffffffff00000000UL ) {
		x >>= 32;
		r += 32;
	}
#endif
	if ( x & 0xffff0000UL ) {
		x >>= 16;
		r += 16;
	}
	if ( x & 0xff00 ) {
		x >>= 8;
		r += 8;
	}
	if ( x & 0xf0 ) {
		x >>= 4;
		r += 4;
	}
	if ( x & 0xc ) {
		x >>= 2;
		r += 2;
	}
	if ( x & 0x2 ) {
		x >>= 1;
		r += 1;
	}
	if ( x & 0x1 ) {
		r += 1;
	}
	return r;
}

/* We don't actually have these functions yet */
extern int __flsl ( long x );

#define flsl( x ) \
	( __builtin_constant_p ( x ) ? __constant_flsl ( x ) : __flsl ( x ) )

#define fls( x ) flsl ( x )

extern int strcasecmp ( const char *s1, const char *s2 );

static inline __attribute__ (( always_inline )) void
bcopy ( const void *src, void *dest, size_t n ) {
	memmove ( dest, src, n );
}

static inline __attribute__ (( always_inline )) void
bzero ( void *s, size_t n ) {
	memset ( s, 0, n );
}

#endif /* _STRINGS_H */
