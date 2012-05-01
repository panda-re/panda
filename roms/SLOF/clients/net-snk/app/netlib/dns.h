/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/


#ifndef _DNS_H_
#define _DNS_H_

#include <stdint.h>

/* Initialize the environment for DNS client. */
extern int8_t dns_init(uint32_t dns_server_ip);

/* For given URL retrieves IPv4 from DNS-server. */
extern int8_t dns_get_ip(int8_t * domain_name, uint32_t * domain_ip);

/* Handles DNS-packets, which are detected by receive_ether. */
extern int32_t handle_dns(uint8_t * packet, int32_t packetsize);

#endif
