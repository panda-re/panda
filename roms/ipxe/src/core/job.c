/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <string.h>
#include <errno.h>
#include <ipxe/job.h>

/** @file
 *
 * Job control interfaces
 *
 */

/**
 * Get job progress
 *
 * @v intf		Object interface
 * @v progress		Progress data to fill in
 */
void job_progress ( struct interface *intf, struct job_progress *progress ) {
	struct interface *dest;
	job_progress_TYPE ( void * ) *op =
		intf_get_dest_op ( intf, job_progress, &dest );
	void *object = intf_object ( dest );

	DBGC ( INTF_COL ( intf ), "INTF " INTF_INTF_FMT " job_progress\n",
	       INTF_INTF_DBG ( intf, dest ) );

	if ( op ) {
		op ( object, progress );
	} else {
		/* Default is to mark progress as zero */
		memset ( progress, 0, sizeof ( *progress ) );
	}

	intf_put ( dest );
}
