#ifndef _USR_IMGMGMT_H
#define _USR_IMGMGMT_H

/** @file
 *
 * Image management
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/image.h>

extern int register_and_put_image ( struct image *image );
extern int register_and_probe_image ( struct image *image );
extern int register_and_select_image ( struct image *image );
extern int register_and_boot_image ( struct image *image );
extern int register_and_replace_image ( struct image *image );
extern int imgdownload ( struct uri *uri, const char *name, const char *cmdline,
			 int ( * action ) ( struct image *image ) );
extern int imgdownload_string ( const char *uri_string, const char *name,
				const char *cmdline,
				int ( * action ) ( struct image *image ) );
extern void imgstat ( struct image *image );
extern void imgfree ( struct image *image );

/**
 * Select an image for execution
 *
 * @v image		Image
 * @ret rc		Return status code
 */
static inline int imgselect ( struct image *image ) {
	return image_select ( image );
}

/**
 * Find the previously-selected image
 *
 * @ret image		Image, or NULL
 */
static inline struct image * imgautoselect ( void ) {
	return image_find_selected();
}

/**
 * Execute an image
 *
 * @v image		Image
 * @ret rc		Return status code
 */
static inline int imgexec ( struct image *image ) {
	return image_exec ( image );
}

#endif /* _USR_IMGMGMT_H */
