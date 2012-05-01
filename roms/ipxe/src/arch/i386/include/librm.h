#ifndef LIBRM_H
#define LIBRM_H

FILE_LICENCE ( GPL2_OR_LATER );

/* Segment selectors as used in our protected-mode GDTs.
 *
 * Don't change these unless you really know what you're doing.
 */

#define VIRTUAL_CS 0x08
#define VIRTUAL_DS 0x10
#define PHYSICAL_CS 0x18
#define PHYSICAL_DS 0x20
#define REAL_CS 0x28
#define REAL_DS 0x30
#if 0
#define LONG_CS 0x38
#define LONG_DS 0x40
#endif

#ifndef ASSEMBLY

#ifdef UACCESS_LIBRM
#define UACCESS_PREFIX_librm
#else
#define UACCESS_PREFIX_librm __librm_
#endif

/* Variables in librm.S */
extern unsigned long virt_offset;

/**
 * Convert physical address to user pointer
 *
 * @v phys_addr		Physical address
 * @ret userptr		User pointer
 */
static inline __always_inline userptr_t
UACCESS_INLINE ( librm, phys_to_user ) ( unsigned long phys_addr ) {
	return ( phys_addr - virt_offset );
}

/**
 * Convert user buffer to physical address
 *
 * @v userptr		User pointer
 * @v offset		Offset from user pointer
 * @ret phys_addr	Physical address
 */
static inline __always_inline unsigned long
UACCESS_INLINE ( librm, user_to_phys ) ( userptr_t userptr, off_t offset ) {
	return ( userptr + offset + virt_offset );
}

static inline __always_inline userptr_t
UACCESS_INLINE ( librm, virt_to_user ) ( volatile const void *addr ) {
	return trivial_virt_to_user ( addr );
}

static inline __always_inline void *
UACCESS_INLINE ( librm, user_to_virt ) ( userptr_t userptr, off_t offset ) {
	return trivial_user_to_virt ( userptr, offset );
}

static inline __always_inline userptr_t
UACCESS_INLINE ( librm, userptr_add ) ( userptr_t userptr, off_t offset ) {
	return trivial_userptr_add ( userptr, offset );
}

static inline __always_inline void
UACCESS_INLINE ( librm, memcpy_user ) ( userptr_t dest, off_t dest_off,
					userptr_t src, off_t src_off,
					size_t len ) {
	trivial_memcpy_user ( dest, dest_off, src, src_off, len );
}

static inline __always_inline void
UACCESS_INLINE ( librm, memmove_user ) ( userptr_t dest, off_t dest_off,
					 userptr_t src, off_t src_off,
					 size_t len ) {
	trivial_memmove_user ( dest, dest_off, src, src_off, len );
}

static inline __always_inline void
UACCESS_INLINE ( librm, memset_user ) ( userptr_t buffer, off_t offset,
					int c, size_t len ) {
	trivial_memset_user ( buffer, offset, c, len );
}

static inline __always_inline size_t
UACCESS_INLINE ( librm, strlen_user ) ( userptr_t buffer, off_t offset ) {
	return trivial_strlen_user ( buffer, offset );
}

static inline __always_inline off_t
UACCESS_INLINE ( librm, memchr_user ) ( userptr_t buffer, off_t offset,
					int c, size_t len ) {
	return trivial_memchr_user ( buffer, offset, c, len );
}


/******************************************************************************
 *
 * Access to variables in .data16 and .text16
 *
 */

extern char *data16;
extern char *text16;

#define __data16( variable )						\
	__attribute__ (( section ( ".data16" ) ))			\
	_data16_ ## variable __asm__ ( #variable )

#define __data16_array( variable, array )				\
	__attribute__ (( section ( ".data16" ) ))			\
	_data16_ ## variable array __asm__ ( #variable )

#define __bss16( variable )						\
	__attribute__ (( section ( ".bss16" ) ))			\
	_data16_ ## variable __asm__ ( #variable )

#define __bss16_array( variable, array )				\
	__attribute__ (( section ( ".bss16" ) ))			\
	_data16_ ## variable array __asm__ ( #variable )

#define __text16( variable )						\
	__attribute__ (( section ( ".text16.data" ) ))			\
	_text16_ ## variable __asm__ ( #variable )

#define __text16_array( variable, array )				\
	__attribute__ (( section ( ".text16.data" ) ))			\
	_text16_ ## variable array __asm__ ( #variable )

#define __use_data16( variable )					\
	( * ( ( typeof ( _data16_ ## variable ) * )			\
	      & ( data16 [ ( size_t ) & ( _data16_ ## variable ) ] ) ) )

#define __use_text16( variable )					\
	( * ( ( typeof ( _text16_ ## variable ) * )			\
	      & ( text16 [ ( size_t ) & ( _text16_ ## variable ) ] ) ) )

#define __from_data16( pointer )					\
	( ( unsigned int )						\
	  ( ( ( void * ) (pointer) ) - ( ( void * ) data16 ) ) )

#define __from_text16( pointer )					\
	( ( unsigned int )						\
	  ( ( ( void * ) (pointer) ) - ( ( void * ) text16 ) ) )

/* Variables in librm.S, present in the normal data segment */
extern uint16_t rm_sp;
extern uint16_t rm_ss;
extern uint16_t __data16 ( rm_cs );
#define rm_cs __use_data16 ( rm_cs )
extern uint16_t __text16 ( rm_ds );
#define rm_ds __use_text16 ( rm_ds )

/**
 * Convert segment:offset address to user buffer
 *
 * @v segment		Real-mode segment
 * @v offset		Real-mode offset
 * @ret buffer		User buffer
 */
static inline __always_inline userptr_t
real_to_user ( unsigned int segment, unsigned int offset ) {
	return ( phys_to_user ( ( segment << 4 ) + offset ) );
}

extern uint16_t copy_user_to_rm_stack ( userptr_t data, size_t size );
extern void remove_user_from_rm_stack ( userptr_t data, size_t size );

/* TEXT16_CODE: declare a fragment of code that resides in .text16 */
#define TEXT16_CODE( asm_code_str )			\
	".section \".text16\", \"ax\", @progbits\n\t"	\
	".code16\n\t"					\
	asm_code_str "\n\t"				\
	".code32\n\t"					\
	".previous\n\t"

/* REAL_CODE: declare a fragment of code that executes in real mode */
#define REAL_CODE( asm_code_str )			\
	"pushl $1f\n\t"					\
	"call real_call\n\t"				\
	"addl $4, %%esp\n\t"				\
	TEXT16_CODE ( "\n1:\n\t"			\
		      asm_code_str			\
		      "\n\t"				\
		      "ret\n\t" )

/* PHYS_CODE: declare a fragment of code that executes in flat physical mode */
#define PHYS_CODE( asm_code_str )			\
	"call _virt_to_phys\n\t"			\
	asm_code_str					\
	"call _phys_to_virt\n\t"

#endif /* ASSEMBLY */

#endif /* LIBRM_H */
