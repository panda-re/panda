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

#ifndef _IFMGMT_CMD_H
#define _IFMGMT_CMD_H

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/parseopt.h>

struct net_device;

struct ifcommon_options {};

extern struct option_descriptor ifcommon_opts[0];

extern int ifcommon_exec (  int argc, char **argv,
			    struct command_descriptor *cmd,
			    int ( * payload ) ( struct net_device * ),
			    int stop_on_first_success );

#endif /* _IFMGMT_CMD_H */
