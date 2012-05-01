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

#include <netlib/tftp.h>
#include <netlib/dhcp.h>
#include <netlib/ethernet.h>
#include <netlib/ipv4.h>
#include <rtas.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

int netflash(int argc, char * argv[])
{
	char buf[256];
	int rc;
	int manage_mode = 0;
	static int len = 0x800000; //max flash size
	char * buffer = NULL;
	short arp_failed = 0;
	filename_ip_t fn_ip;
	int fd_device;
	tftp_err_t tftp_err;
	char * ptr;
	uint8_t own_mac[6];

	printf("\n Flasher 1.4 \n");
	memset(&fn_ip, 0, sizeof(filename_ip_t));

	if (argc == 3 && argv[2][0] == '-' && argv[2][1] == 'c' && argv[2][2] == 0)
		manage_mode = 1;
	else if (argc == 3 && 
		argv[2][0] == '-' && argv[2][1] == 'r' && argv[2][2] == 0)
		manage_mode = 1;
	else if (argc == 4 &&
		argv[2][0] == '-' && argv[2][1] == 'f' && argv[2][2] == 0)
	{
		manage_mode = 0;
		buffer = (char *)strtol(argv[1],0,16);
		if ((long)buffer == -1) {
			printf("   Bad buffer address. Exiting...\n");
			return -1;
		}
	}
	else
	{
		printf("   Usage: netflash [options] [<filename>]\n");
		printf("   Options:\n");
		printf("            -f     <filename> flash temporary image\n");
		printf("            -c     commit temporary image\n");
		printf("            -r     reject temporary image\n");
		printf("   Bad arguments. Exiting...\n\n");
		return -1;
	}

	if (manage_mode == 1) {
		if (argv[2][1] == 99)
			return rtas_ibm_manage_flash(1);
		else
			return rtas_ibm_manage_flash(0);
	}

	/* Get mac_addr from device */
	printf("  Reading MAC address from device: ");
	fd_device = socket(0, 0, 0, (char *) own_mac);
	if (fd_device == -1) {
		printf("\nE3000: Could not read MAC address\n");
		return -100;
	}
	else if (fd_device == -2) {
		printf("\nE3006: Could not initialize network device\n");
		return -101;
	}

	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
	       own_mac[0], own_mac[1], own_mac[2],
	       own_mac[3], own_mac[4], own_mac[5]);

	// init ethernet layer
	set_mac_address(own_mac);

	// identify the BOOTP/DHCP server via broadcasts
	// don't do this, when using DHCP !!!
	//  fn_ip.server_ip = 0xFFFFFFFF;
	//  memset(fn_ip.server_mac, 0xff, 6);

	/* Get ip address for our mac address */
	printf("  Requesting IP address via DHCP: ");
	arp_failed = dhcp(0, &fn_ip, 30);

	if(arp_failed >= 0) {
		// reinit network stack
		set_ipv4_address(fn_ip.own_ip);
	}

	if (arp_failed == -1) {
		printf("\n  DHCP: Could not get ip address\n");
		return 1;
	}

	if (arp_failed == -2) {
		sprintf
		    (buf,"\n  ARP request to TFTP server (%d.%d.%d.%d) failed",
		     ((fn_ip.server_ip >> 24) & 0xFF), ((fn_ip.server_ip >> 16) & 0xFF),
		     ((fn_ip.server_ip >>  8) & 0xFF), ( fn_ip.server_ip        & 0xFF));
		return 1;
	}

	printf("%d.%d.%d.%d\n",
		((fn_ip.own_ip >> 24) & 0xFF), ((fn_ip.own_ip >> 16) & 0xFF), 
		((fn_ip.own_ip >>  8) & 0xFF), (fn_ip.own_ip & 0xFF));

	/* Load file via TFTP into buffer provided by OpenFirmware */

	for(ptr = argv[3]; *ptr != 0; ++ptr)
		if(*ptr == '\\')
			*ptr = '/';

	printf("  Requesting file \"%s\" via TFTP\n",argv[3]);

	strcpy((char *) fn_ip.filename,argv[3]);

	rc = tftp(&fn_ip, (unsigned char*) buffer, len, 20, &tftp_err, 0, 512, 4);

	dhcp_send_release();

	if (rc > 0)
	{
		printf ("  TFTP: Received %s (%d KBytes)\n", fn_ip.filename, rc/1024);
		printf ("  Now flashing:\n");
		rc = rtas_ibm_update_flash_64((long long)buffer, rc);
		return rc;
	}
	else if (rc == -1)
	{
		printf ("  Tftp: Could not load file %s\n", fn_ip.filename);
		return 1;
	}
	else if (rc == -2)
	{
		printf ("  Tftp: Buffer to small for %s\n", fn_ip.filename);
		return 1;
	}
	else if (rc <= -10 && rc >= -15)
	{
		printf("\n  ICMP ERROR: Destination unreachable: ");
		switch(rc) {
			case -ICMP_NET_UNREACHABLE-10:
				printf("net unreachable");
				break;
			case -ICMP_HOST_UNREACHABLE-10:
				printf("host unreachable");
				break;
			case -ICMP_PROTOCOL_UNREACHABLE-10:
				printf("protocol unreachable");
				break;
			case -ICMP_PORT_UNREACHABLE-10:
				printf("port unreachable");
				break;
			case -ICMP_FRAGMENTATION_NEEDED-10:
				printf("fragmentation needed and DF set");
				break;
			case -ICMP_SOURCE_ROUTE_FAILED-10:
				printf("source route failed");
				break;
			default:
				printf(" UNKNOWN: this should not happen!");
				break;
		}
		printf("\n");
		return 1;
	}
	else if(rc < 0)
		printf(" UNKNOWN: rc = %d!", rc);

	return 0;
}
