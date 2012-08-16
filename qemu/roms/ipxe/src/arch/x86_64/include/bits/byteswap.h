#ifndef _BITS_BYTESWAP_H
#define _BITS_BYTESWAP_H

static inline __attribute__ (( always_inline, const )) uint16_t
__bswap_variable_16 ( uint16_t x ) {
	__asm__ ( "xchgb %b0,%h0" : "=Q" ( x ) : "0" ( x ) );
	return x;
}

static inline __attribute__ (( always_inline, const )) uint32_t
__bswap_variable_32 ( uint32_t x ) {
	__asm__ ( "bswapl %k0" : "=r" ( x ) : "0" ( x ) );
	return x;
}

static inline __attribute__ (( always_inline, const )) uint64_t
__bswap_variable_64 ( uint64_t x ) {
	__asm__ ( "bswapq %q0" : "=r" ( x ) : "0" ( x ) );
	return x;
}

#endif /* _BITS_BYTESWAP_H */
