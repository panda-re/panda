/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <ipxe/list.h>
#include <ipxe/umalloc.h>
#include <ipxe/uri.h>
#include <ipxe/image.h>

/** @file
 *
 * Executable images
 *
 */

/** List of registered images */
struct list_head images = LIST_HEAD_INIT ( images );

/** Currently-executing image */
struct image *current_image;

/**
 * Free executable image
 *
 * @v refcnt		Reference counter
 */
static void free_image ( struct refcnt *refcnt ) {
	struct image *image = container_of ( refcnt, struct image, refcnt );

	free ( image->cmdline );
	uri_put ( image->uri );
	ufree ( image->data );
	image_put ( image->replacement );
	free ( image );
	DBGC ( image, "IMAGE %s freed\n", image->name );
}

/**
 * Allocate executable image
 *
 * @ret image		Executable image
 */
struct image * alloc_image ( void ) {
	struct image *image;

	image = zalloc ( sizeof ( *image ) );
	if ( image ) {
		ref_init ( &image->refcnt, free_image );
	}
	return image;
}

/**
 * Set image URI
 *
 * @v image		Image
 * @v URI		New image URI
 *
 * If no name is set, the name will be updated to the base name of the
 * URI path (if any).
 */
void image_set_uri ( struct image *image, struct uri *uri ) {
	const char *path = uri->path;

	/* Replace URI reference */
	uri_put ( image->uri );
	image->uri = uri_get ( uri );

	/* Set name if none already specified */
	if ( path && ( ! image->name[0] ) )
		image_set_name ( image, basename ( ( char * ) path ) );
}

/**
 * Set image command line
 *
 * @v image		Image
 * @v cmdline		New image command line, or NULL
 * @ret rc		Return status code
 */
int image_set_cmdline ( struct image *image, const char *cmdline ) {

	free ( image->cmdline );
	image->cmdline = NULL;
	if ( cmdline ) {
		image->cmdline = strdup ( cmdline );
		if ( ! image->cmdline )
			return -ENOMEM;
	}
	return 0;
}

/**
 * Register executable image
 *
 * @v image		Executable image
 * @ret rc		Return status code
 */
int register_image ( struct image *image ) {
	static unsigned int imgindex = 0;

	/* Create image name if it doesn't already have one */
	if ( ! image->name[0] ) {
		snprintf ( image->name, sizeof ( image->name ), "img%d",
			   imgindex++ );
	}

	/* Avoid ending up with multiple "selected" images on
	 * re-registration
	 */
	if ( image_find_selected() )
		image->flags &= ~IMAGE_SELECTED;

	/* Add to image list */
	image_get ( image );
	image->flags |= IMAGE_REGISTERED;
	list_add_tail ( &image->list, &images );
	DBGC ( image, "IMAGE %s at [%lx,%lx) registered\n",
	       image->name, user_to_phys ( image->data, 0 ),
	       user_to_phys ( image->data, image->len ) );

	return 0;
}

/**
 * Unregister executable image
 *
 * @v image		Executable image
 */
void unregister_image ( struct image *image ) {

	DBGC ( image, "IMAGE %s unregistered\n", image->name );
	list_del ( &image->list );
	image->flags &= ~IMAGE_REGISTERED;
	image_put ( image );
}

/**
 * Find image by name
 *
 * @v name		Image name
 * @ret image		Executable image, or NULL
 */
struct image * find_image ( const char *name ) {
	struct image *image;

	list_for_each_entry ( image, &images, list ) {
		if ( strcmp ( image->name, name ) == 0 )
			return image;
	}

	return NULL;
}

/**
 * Determine image type
 *
 * @v image		Executable image
 * @ret rc		Return status code
 */
int image_probe ( struct image *image ) {
	struct image_type *type;
	int rc;

	/* Succeed if we already have a type */
	if ( image->type )
		return 0;

	/* Try each type in turn */
	for_each_table_entry ( type, IMAGE_TYPES ) {
		if ( ( rc = type->probe ( image ) ) == 0 ) {
			image->type = type;
			DBGC ( image, "IMAGE %s is %s\n",
			       image->name, type->name );
			return 0;
		}
		DBGC ( image, "IMAGE %s is not %s: %s\n", image->name,
		       type->name, strerror ( rc ) );
	}

	DBGC ( image, "IMAGE %s format not recognised\n", image->name );
	return -ENOEXEC;
}

/**
 * Execute image
 *
 * @v image		Executable image
 * @ret rc		Return status code
 *
 * The image must already be registered.  Note that executing an image
 * may cause it to unregister itself.  The caller must therefore
 * assume that the image pointer becomes invalid.
 */
int image_exec ( struct image *image ) {
	struct image *saved_current_image;
	struct image *replacement;
	struct uri *old_cwuri;
	int rc;

	/* Sanity check */
	assert ( image->flags & IMAGE_REGISTERED );

	/* Check that this image can be executed */
	if ( ( rc = image_probe ( image ) ) != 0 )
		return rc;

	/* Switch current working directory to be that of the image itself */
	old_cwuri = uri_get ( cwuri );
	churi ( image->uri );

	/* Preserve record of any currently-running image */
	saved_current_image = current_image;

	/* Take out a temporary reference to the image.  This allows
	 * the image to unregister itself if necessary, without
	 * automatically freeing itself.
	 */
	current_image = image_get ( image );

	/* Try executing the image */
	if ( ( rc = image->type->exec ( image ) ) != 0 ) {
		DBGC ( image, "IMAGE %s could not execute: %s\n",
		       image->name, strerror ( rc ) );
		/* Do not return yet; we still have clean-up to do */
	}

	/* Pick up replacement image before we drop the original
	 * image's temporary reference.  The replacement image must
	 * already be registered, so we don't need to hold a temporary
	 * reference (which would complicate the tail-recursion).
	 */
	replacement = image->replacement;
	if ( replacement )
		assert ( replacement->flags & IMAGE_REGISTERED );

	/* Drop temporary reference to the original image */
	image_put ( image );

	/* Restore previous currently-running image */
	current_image = saved_current_image;

	/* Reset current working directory */
	churi ( old_cwuri );
	uri_put ( old_cwuri );

	/* Tail-recurse into replacement image, if one exists */
	if ( replacement ) {
		DBGC ( image, "IMAGE %s replacing self with IMAGE %s\n",
		       image->name, replacement->name );
		if ( ( rc = image_exec ( replacement ) ) != 0 )
			return rc;
	}

	return rc;
}

/**
 * Set replacement image
 *
 * @v replacement	Replacement image
 * @ret rc		Return status code
 *
 * The replacement image must already be registered, and must remain
 * registered until the currently-executing image returns.
 */
int image_replace ( struct image *replacement ) {
	struct image *image = current_image;
	int rc;

	/* Sanity check */
	assert ( replacement->flags & IMAGE_REGISTERED );

	/* Fail unless there is a currently-executing image */
	if ( ! image ) {
		rc = -ENOTTY;
		DBGC ( replacement, "IMAGE %s cannot replace non-existent "
		       "image: %s\n", replacement->name, strerror ( rc ) );
		return rc;
	}

	/* Clear any existing replacement */
	image_put ( image->replacement );

	/* Set replacement */
	image->replacement = image_get ( replacement );
	DBGC ( image, "IMAGE %s will replace self with IMAGE %s\n",
	       image->name, replacement->name );

	return 0;
}

/**
 * Select image for execution
 *
 * @v image		Executable image
 * @ret rc		Return status code
 */
int image_select ( struct image *image ) {
	struct image *tmp;
	int rc;

	/* Unselect all other images */
	for_each_image ( tmp )
		tmp->flags &= ~IMAGE_SELECTED;

	/* Check that this image can be executed */
	if ( ( rc = image_probe ( image ) ) != 0 )
		return rc;

	/* Mark image as selected */
	image->flags |= IMAGE_SELECTED;

	return 0;
}

/**
 * Find selected image
 *
 * @ret image		Executable image, or NULL
 */
struct image * image_find_selected ( void ) {
	struct image *image;

	for_each_image ( image ) {
		if ( image->flags & IMAGE_SELECTED )
			return image;
	}
	return NULL;
}
