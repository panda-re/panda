/*
 * librm: a library for interfacing to real-mode code
 *
 * Michael Brown <mbrown@fensystems.co.uk>
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <realmode.h>

/*
 * This file provides functions for managing librm.
 *
 */

/**
 * Allocate space on the real-mode stack and copy data there from a
 * user buffer
 *
 * @v data			User buffer
 * @v size			Size of stack data
 * @ret sp			New value of real-mode stack pointer
 */
uint16_t copy_user_to_rm_stack ( userptr_t data, size_t size ) {
	userptr_t rm_stack;
	rm_sp -= size;
	rm_stack = real_to_user ( rm_ss, rm_sp );
	memcpy_user ( rm_stack, 0, data, 0, size );
	return rm_sp;
};

/**
 * Deallocate space on the real-mode stack, optionally copying back
 * data to a user buffer.
 *
 * @v data			User buffer
 * @v size			Size of stack data
 */
void remove_user_from_rm_stack ( userptr_t data, size_t size ) {
	if ( data ) {
		userptr_t rm_stack = real_to_user ( rm_ss, rm_sp );
		memcpy_user ( rm_stack, 0, data, 0, size );
	}
	rm_sp += size;
};

PROVIDE_UACCESS_INLINE ( librm, phys_to_user );
PROVIDE_UACCESS_INLINE ( librm, user_to_phys );
PROVIDE_UACCESS_INLINE ( librm, virt_to_user );
PROVIDE_UACCESS_INLINE ( librm, user_to_virt );
PROVIDE_UACCESS_INLINE ( librm, userptr_add );
PROVIDE_UACCESS_INLINE ( librm, memcpy_user );
PROVIDE_UACCESS_INLINE ( librm, memmove_user );
PROVIDE_UACCESS_INLINE ( librm, memset_user );
PROVIDE_UACCESS_INLINE ( librm, strlen_user );
PROVIDE_UACCESS_INLINE ( librm, memchr_user );
