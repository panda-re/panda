#ifndef ETHERBOOT_BITS_BYTESWAP_H
#define ETHERBOOT_BITS_BYTESWAP_H

FILE_LICENCE ( GPL2_OR_LATER );

static inline __attribute__ ((always_inline, const)) uint16_t
__bswap_variable_16(uint16_t x)
{
	__asm__("xchgb %b0,%h0\n\t"
		: "=q" (x)
		: "0" (x));
	return x;
}

static inline __attribute__ ((always_inline, const)) uint32_t
__bswap_variable_32(uint32_t x)
{
	__asm__("xchgb %b0,%h0\n\t"
		"rorl $16,%0\n\t"
		"xchgb %b0,%h0"
		: "=q" (x)
		: "0" (x));
	return x;
}

static inline __attribute__ ((always_inline, const)) uint64_t
__bswap_variable_64(uint64_t x)
{
	union {
		uint64_t qword;
		uint32_t dword[2]; 
	} u;

	u.qword = x;
	u.dword[0] = __bswap_variable_32(u.dword[0]);
	u.dword[1] = __bswap_variable_32(u.dword[1]);
	__asm__("xchgl %0,%1"
		: "=r" ( u.dword[0] ), "=r" ( u.dword[1] )
		: "0" ( u.dword[0] ), "1" ( u.dword[1] ) );
	return u.qword;
}

#endif /* ETHERBOOT_BITS_BYTESWAP_H */
