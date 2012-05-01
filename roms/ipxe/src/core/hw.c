#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/refcnt.h>
#include <ipxe/process.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>

/** @file
 *
 * "Hello World" data source
 *
 */

struct hw {
	struct refcnt refcnt;
	struct interface xfer;
	struct process process;
};

static const char hw_msg[] = "Hello world!\n";

static void hw_finished ( struct hw *hw, int rc ) {
	intf_shutdown ( &hw->xfer, rc );
	process_del ( &hw->process );
}

static struct interface_operation hw_xfer_operations[] = {
	INTF_OP ( intf_close, struct hw *, hw_finished ),
};

static struct interface_descriptor hw_xfer_desc =
	INTF_DESC ( struct hw, xfer, hw_xfer_operations );

static void hw_step ( struct process *process ) {
	struct hw *hw = container_of ( process, struct hw, process );
	int rc;

	if ( xfer_window ( &hw->xfer ) ) {
		rc = xfer_deliver_raw ( &hw->xfer, hw_msg, sizeof ( hw_msg ) );
		hw_finished ( hw, rc );
	}
}

static int hw_open ( struct interface *xfer, struct uri *uri __unused ) {
	struct hw *hw;

	/* Allocate and initialise structure */
	hw = zalloc ( sizeof ( *hw ) );
	if ( ! hw )
		return -ENOMEM;
	ref_init ( &hw->refcnt, NULL );
	intf_init ( &hw->xfer, &hw_xfer_desc, &hw->refcnt );
	process_init ( &hw->process, hw_step, &hw->refcnt );

	/* Attach parent interface, mortalise self, and return */
	intf_plug_plug ( &hw->xfer, xfer );
	ref_put ( &hw->refcnt );
	return 0;
}

struct uri_opener hw_uri_opener __uri_opener = {
	.scheme = "hw",
	.open = hw_open,
};
