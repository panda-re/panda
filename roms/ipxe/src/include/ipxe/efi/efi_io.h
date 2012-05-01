#ifndef _IPXE_EFI_IO_H
#define _IPXE_EFI_IO_H

/** @file
 *
 * iPXE I/O API for EFI
 *
 * EFI runs with flat physical addressing, so the various mappings
 * between virtual addresses, I/O addresses and bus addresses are all
 * no-ops.  I/O is handled using the EFI_CPU_IO_PROTOCOL.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#ifdef IOAPI_EFI
#define IOAPI_PREFIX_efi
#else
#define IOAPI_PREFIX_efi __efi_
#endif

extern unsigned long long efi_ioread ( volatile void *io_addr,
				       size_t size );
extern void efi_iowrite ( unsigned long long data, volatile void *io_addr,
			  size_t size );
extern void efi_ioreads ( volatile void *io_addr, void *data,
			  size_t size, unsigned int count );
extern void efi_iowrites ( volatile void *io_addr, const void *data,
			  size_t size, unsigned int count );

/*
 * Physical<->Bus and Bus<->I/O address mappings
 *
 * EFI runs with flat physical addressing, so these are all no-ops.
 *
 */

static inline __always_inline unsigned long
IOAPI_INLINE ( efi, phys_to_bus ) ( unsigned long phys_addr ) {
	return phys_addr;
}

static inline __always_inline unsigned long
IOAPI_INLINE ( efi, bus_to_phys ) ( unsigned long bus_addr ) {
	return bus_addr;
}

static inline __always_inline void *
IOAPI_INLINE ( efi, ioremap ) ( unsigned long bus_addr, size_t len __unused ) {
	return ( ( void * ) bus_addr );
}

static inline __always_inline void
IOAPI_INLINE ( efi, iounmap ) ( volatile const void *io_addr __unused ) {
	/* Nothing to do */
}

static inline __always_inline unsigned long
IOAPI_INLINE ( efi, io_to_bus ) ( volatile const void *io_addr ) {
	return ( ( unsigned long ) io_addr );
}

/*
 * I/O functions
 *
 */

static inline __always_inline uint8_t
IOAPI_INLINE ( efi, readb ) ( volatile uint8_t *io_addr ) {
	return efi_ioread ( io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline uint16_t
IOAPI_INLINE ( efi, readw ) ( volatile uint16_t *io_addr ) {
	return efi_ioread ( io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline uint32_t
IOAPI_INLINE ( efi, readl ) ( volatile uint32_t *io_addr ) {
	return efi_ioread ( io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline uint64_t
IOAPI_INLINE ( efi, readq ) ( volatile uint64_t *io_addr ) {
	return efi_ioread ( io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline void
IOAPI_INLINE ( efi, writeb ) ( uint8_t data, volatile uint8_t *io_addr ) {
	efi_iowrite ( data, io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline void
IOAPI_INLINE ( efi, writew ) ( uint16_t data, volatile uint16_t *io_addr ) {
	efi_iowrite ( data, io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline void
IOAPI_INLINE ( efi, writel ) ( uint32_t data, volatile uint32_t *io_addr ) {
	efi_iowrite ( data, io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline void
IOAPI_INLINE ( efi, writeq ) ( uint64_t data, volatile uint64_t *io_addr ) {
	efi_iowrite ( data, io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline uint8_t
IOAPI_INLINE ( efi, inb ) ( volatile uint8_t *io_addr ) {
	return efi_ioread ( io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline uint16_t
IOAPI_INLINE ( efi, inw ) ( volatile uint16_t *io_addr ) {
	return efi_ioread ( io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline uint32_t
IOAPI_INLINE ( efi, inl ) ( volatile uint32_t *io_addr ) {
	return efi_ioread ( io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline void
IOAPI_INLINE ( efi, outb ) ( uint8_t data, volatile uint8_t *io_addr ) {
	efi_iowrite ( data, io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline void
IOAPI_INLINE ( efi, outw ) ( uint16_t data, volatile uint16_t *io_addr ) {
	efi_iowrite ( data, io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline void
IOAPI_INLINE ( efi, outl ) ( uint32_t data, volatile uint32_t *io_addr ) {
	efi_iowrite ( data, io_addr, sizeof ( *io_addr ) );
}

static inline __always_inline void
IOAPI_INLINE ( efi, insb ) ( volatile uint8_t *io_addr, uint8_t *data,
			     unsigned int count ) {
	efi_ioreads ( io_addr, data, sizeof ( *io_addr ), count );
}

static inline __always_inline void
IOAPI_INLINE ( efi, insw ) ( volatile uint16_t *io_addr, uint16_t *data,
			     unsigned int count ) {
	efi_ioreads ( io_addr, data, sizeof ( *io_addr ), count );
}

static inline __always_inline void
IOAPI_INLINE ( efi, insl ) ( volatile uint32_t *io_addr, uint32_t *data,
			     unsigned int count ) {
	efi_ioreads ( io_addr, data, sizeof ( *io_addr ), count );
}

static inline __always_inline void
IOAPI_INLINE ( efi, outsb ) ( volatile uint8_t *io_addr, const uint8_t *data,
			      unsigned int count ) {
	efi_iowrites ( io_addr, data, sizeof ( *io_addr ), count );
}

static inline __always_inline void
IOAPI_INLINE ( efi, outsw ) ( volatile uint16_t *io_addr, const uint16_t *data,
			      unsigned int count ) {
	efi_iowrites ( io_addr, data, sizeof ( *io_addr ), count );
}

static inline __always_inline void
IOAPI_INLINE ( efi, outsl ) ( volatile uint32_t *io_addr, const uint32_t *data,
			      unsigned int count ) {
	efi_iowrites ( io_addr, data, sizeof ( *io_addr ), count );
}

static inline __always_inline void
IOAPI_INLINE ( efi, mb ) ( void ) {
	/* Do nothing; EFI readl()/writel() calls already act as
	 * memory barriers.
	 */
}

#endif /* _IPXE_EFI_IO_H */
