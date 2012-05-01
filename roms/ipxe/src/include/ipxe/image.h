#ifndef _IPXE_IMAGE_H
#define _IPXE_IMAGE_H

/**
 * @file
 *
 * Executable images
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/tables.h>
#include <ipxe/list.h>
#include <ipxe/uaccess.h>
#include <ipxe/refcnt.h>

struct uri;
struct image_type;

/** An executable image */
struct image {
	/** Reference count */
	struct refcnt refcnt;

	/** List of registered images */
	struct list_head list;

	/** URI of image */
	struct uri *uri;
	/** Name */
	char name[16];
	/** Flags */
	unsigned int flags;

	/** Command line to pass to image */
	char *cmdline;
	/** Raw file image */
	userptr_t data;
	/** Length of raw file image */
	size_t len;

	/** Image type, if known */
	struct image_type *type;

	/** Replacement image
	 *
	 * An image wishing to replace itself with another image (in a
	 * style similar to a Unix exec() call) should return from its
	 * exec() method with the replacement image set to point to
	 * the new image.
	 *
	 * If an image unregisters itself as a result of being
	 * executed, it must make sure that its replacement image (if
	 * any) is registered, otherwise the replacement is likely to
	 * be freed before it can be executed.
	 */
	struct image *replacement;
};

/** Image is registered */
#define IMAGE_REGISTERED 0x00001

/** Image is selected for execution */
#define IMAGE_SELECTED 0x0002

/** An executable image type */
struct image_type {
	/** Name of this image type */
	char *name;
	/** Probe image
	 *
	 * @v image		Executable image
	 * @ret rc		Return status code
	 *
	 * Return success if the image is of this image type.
	 */
	int ( * probe ) ( struct image *image );
	/**
	 * Execute image
	 *
	 * @v image		Executable image
	 * @ret rc		Return status code
	 */
	int ( * exec ) ( struct image *image );
};

/**
 * Multiboot image probe priority
 *
 * Multiboot images are also valid executables in another format
 * (e.g. ELF), so we must perform the multiboot probe first.
 */
#define PROBE_MULTIBOOT	01

/**
 * Normal image probe priority
 */
#define PROBE_NORMAL 02

/**
 * PXE image probe priority
 *
 * PXE images have no signature checks, so will claim all image files.
 * They must therefore be tried last in the probe order list.
 */
#define PROBE_PXE 03

/** Executable image type table */
#define IMAGE_TYPES __table ( struct image_type, "image_types" )

/** An executable image type */
#define __image_type( probe_order ) __table_entry ( IMAGE_TYPES, probe_order )

extern struct list_head images;
extern struct image *current_image;

/** Iterate over all registered images */
#define for_each_image( image ) \
	list_for_each_entry ( (image), &images, list )

/**
 * Test for existence of images
 *
 * @ret existence	Some images exist
 */
static inline int have_images ( void ) {
	return ( ! list_empty ( &images ) );
}

/**
 * Retrieve first image
 *
 * @ret image		Image, or NULL
 */
static inline struct image * first_image ( void ) {
	return list_first_entry ( &images, struct image, list );
}

extern struct image * alloc_image ( void );
extern void image_set_uri ( struct image *image, struct uri *uri );
extern int image_set_cmdline ( struct image *image, const char *cmdline );
extern int register_image ( struct image *image );
extern void unregister_image ( struct image *image );
struct image * find_image ( const char *name );
extern int image_probe ( struct image *image );
extern int image_exec ( struct image *image );
extern int image_replace ( struct image *replacement );
extern int image_select ( struct image *image );
extern struct image * image_find_selected ( void );

/**
 * Increment reference count on an image
 *
 * @v image		Image
 * @ret image		Image
 */
static inline struct image * image_get ( struct image *image ) {
	ref_get ( &image->refcnt );
	return image;
}

/**
 * Decrement reference count on an image
 *
 * @v image		Image
 */
static inline void image_put ( struct image *image ) {
	ref_put ( &image->refcnt );
}

/**
 * Set image name
 *
 * @v image		Image
 * @v name		New image name
 * @ret rc		Return status code
 */
static inline int image_set_name ( struct image *image, const char *name ) {
	strncpy ( image->name, name, ( sizeof ( image->name ) - 1 ) );
	return 0;
}

#endif /* _IPXE_IMAGE_H */
