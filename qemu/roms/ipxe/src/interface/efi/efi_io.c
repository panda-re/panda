/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <assert.h>
#include <ipxe/io.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/CpuIo.h>
#include <ipxe/efi/efi_io.h>

/** @file
 *
 * iPXE I/O API for EFI
 *
 */

/** CPU I/O protocol */
static EFI_CPU_IO_PROTOCOL *cpu_io;
EFI_REQUIRE_PROTOCOL ( EFI_CPU_IO_PROTOCOL, &cpu_io );

/** Maximum address that can be used for port I/O */
#define MAX_PORT_ADDRESS 0xffff

/**
 * Determine whether or not address is a port I/O address
 *
 * @v io_addr		I/O address
 * @v is_port		I/O address is a port I/O address
 */
#define IS_PORT_ADDRESS(io_addr) \
	( ( ( intptr_t ) (io_addr) ) <= MAX_PORT_ADDRESS )

/**
 * Determine EFI CPU I/O width code
 *
 * @v size		Size of value
 * @ret width		EFI width code
 *
 * Someone at Intel clearly gets paid by the number of lines of code
 * they write.  No-one should ever be able to make I/O this
 * convoluted.  The EFI_CPU_IO_PROTOCOL_WIDTH enum is my favourite
 * idiocy.
 */
static EFI_CPU_IO_PROTOCOL_WIDTH efi_width ( size_t size ) {
	switch ( size ) {
	case 1 :	return EfiCpuIoWidthFifoUint8;
	case 2 :	return EfiCpuIoWidthFifoUint16;
	case 4 :	return EfiCpuIoWidthFifoUint32;
	case 8 :	return EfiCpuIoWidthFifoUint64;
	default :
		assert ( 0 );
		/* I wonder what this will actually do... */
		return EfiCpuIoWidthMaximum;
	}
}

/**
 * Read from device
 *
 * @v io_addr		I/O address
 * @v size		Size of value
 * @ret data		Value read
 */
unsigned long long efi_ioread ( volatile void *io_addr, size_t size ) {
	EFI_CPU_IO_PROTOCOL_IO_MEM read;
	unsigned long long data = 0;
	EFI_STATUS efirc;

	read = ( IS_PORT_ADDRESS ( io_addr ) ?
		 cpu_io->Io.Read : cpu_io->Mem.Read );

	if ( ( efirc = read ( cpu_io, efi_width ( size ),
			      ( intptr_t ) io_addr, 1,
			      ( void * ) &data ) ) != 0 ) {
		DBG ( "EFI I/O read at %p failed: %s\n",
		      io_addr, efi_strerror ( efirc ) );
		return -1ULL;
	}

	return data;
}

/**
 * Write to device
 *
 * @v data		Value to write
 * @v io_addr		I/O address
 * @v size		Size of value
 */
void efi_iowrite ( unsigned long long data, volatile void *io_addr,
		   size_t size ) {
	EFI_CPU_IO_PROTOCOL_IO_MEM write;
	EFI_STATUS efirc;

	write = ( IS_PORT_ADDRESS ( io_addr ) ?
		  cpu_io->Io.Write : cpu_io->Mem.Write );

	if ( ( efirc = write ( cpu_io, efi_width ( size ),
			       ( intptr_t ) io_addr, 1,
			       ( void * ) &data ) ) != 0 ) {
		DBG ( "EFI I/O write at %p failed: %s\n",
		      io_addr, efi_strerror ( efirc ) );
	}
}

/**
 * String read from device
 *
 * @v io_addr		I/O address
 * @v data		Data buffer
 * @v size		Size of values
 * @v count		Number of values to read
 */
void efi_ioreads ( volatile void *io_addr, void *data,
		   size_t size, unsigned int count ) {
	EFI_CPU_IO_PROTOCOL_IO_MEM read;
	EFI_STATUS efirc;

	read = ( IS_PORT_ADDRESS ( io_addr ) ?
		 cpu_io->Io.Read : cpu_io->Mem.Read );

	if ( ( efirc = read ( cpu_io, efi_width ( size ),
			      ( intptr_t ) io_addr, count,
			      ( void * ) data ) ) != 0 ) {
		DBG ( "EFI I/O string read at %p failed: %s\n",
		      io_addr, efi_strerror ( efirc ) );
	}
}

/**
 * String write to device
 *
 * @v io_addr		I/O address
 * @v data		Data buffer
 * @v size		Size of values
 * @v count		Number of values to write
 */
void efi_iowrites ( volatile void *io_addr, const void *data,
		    size_t size, unsigned int count ) {
	EFI_CPU_IO_PROTOCOL_IO_MEM write;
	EFI_STATUS efirc;

	write = ( IS_PORT_ADDRESS ( io_addr ) ?
		 cpu_io->Io.Write : cpu_io->Mem.Write );

	if ( ( efirc = write ( cpu_io, efi_width ( size ),
			       ( intptr_t ) io_addr, count,
			       ( void * ) data ) ) != 0 ) {
		DBG ( "EFI I/O write at %p failed: %s\n",
		      io_addr, efi_strerror ( efirc ) );
	}
}

/**
 * Wait for I/O-mapped operation to complete
 *
 */
static void efi_iodelay ( void ) {
	/* Write to non-existent port.  Probably x86-only. */
	outb ( 0, 0x80 );
}

/**
 * Get memory map
 *
 * Can't be done on EFI so return an empty map
 *
 * @v memmap		Memory map to fill in
 */
static void efi_get_memmap ( struct memory_map *memmap ) {
	memmap->count = 0;
}

PROVIDE_IOAPI_INLINE ( efi, phys_to_bus );
PROVIDE_IOAPI_INLINE ( efi, bus_to_phys );
PROVIDE_IOAPI_INLINE ( efi, ioremap );
PROVIDE_IOAPI_INLINE ( efi, iounmap );
PROVIDE_IOAPI_INLINE ( efi, io_to_bus );
PROVIDE_IOAPI_INLINE ( efi, readb );
PROVIDE_IOAPI_INLINE ( efi, readw );
PROVIDE_IOAPI_INLINE ( efi, readl );
PROVIDE_IOAPI_INLINE ( efi, readq );
PROVIDE_IOAPI_INLINE ( efi, writeb );
PROVIDE_IOAPI_INLINE ( efi, writew );
PROVIDE_IOAPI_INLINE ( efi, writel );
PROVIDE_IOAPI_INLINE ( efi, writeq );
PROVIDE_IOAPI_INLINE ( efi, inb );
PROVIDE_IOAPI_INLINE ( efi, inw );
PROVIDE_IOAPI_INLINE ( efi, inl );
PROVIDE_IOAPI_INLINE ( efi, outb );
PROVIDE_IOAPI_INLINE ( efi, outw );
PROVIDE_IOAPI_INLINE ( efi, outl );
PROVIDE_IOAPI_INLINE ( efi, insb );
PROVIDE_IOAPI_INLINE ( efi, insw );
PROVIDE_IOAPI_INLINE ( efi, insl );
PROVIDE_IOAPI_INLINE ( efi, outsb );
PROVIDE_IOAPI_INLINE ( efi, outsw );
PROVIDE_IOAPI_INLINE ( efi, outsl );
PROVIDE_IOAPI ( efi, iodelay, efi_iodelay );
PROVIDE_IOAPI_INLINE ( efi, mb );
PROVIDE_IOAPI ( efi, get_memmap, efi_get_memmap );
