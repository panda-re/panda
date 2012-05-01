#ifndef CONFIG_GENERAL_H
#define CONFIG_GENERAL_H

/** @file
 *
 * General configuration
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <config/defaults.h>

/*
 * Branding
 *
 * Vendors may use these strings to add their own branding to iPXE.
 * PRODUCT_NAME is displayed prior to any iPXE branding in startup
 * messages, and PRODUCT_SHORT_NAME is used where a brief product
 * label is required (e.g. in BIOS boot selection menus).
 *
 * To minimise end-user confusion, it's probably a good idea to either
 * make PRODUCT_SHORT_NAME a substring of PRODUCT_NAME or leave it as
 * "iPXE".
 *
 */
#define PRODUCT_NAME ""
#define PRODUCT_SHORT_NAME "iPXE"

/*
 * Timer configuration
 *
 */
#define BANNER_TIMEOUT	20	/* Tenths of a second for which the shell
				   banner should appear */

/*
 * Network protocols
 *
 */

#define	NET_PROTO_IPV4		/* IPv4 protocol */
#undef	NET_PROTO_FCOE		/* Fibre Channel over Ethernet protocol */

/*
 * PXE support
 *
 */
//#undef	PXE_STACK		/* PXE stack in iPXE - you want this! */
//#undef	PXE_MENU		/* PXE menu booting */

/*
 * Download protocols
 *
 */

#define	DOWNLOAD_PROTO_TFTP	/* Trivial File Transfer Protocol */
#define	DOWNLOAD_PROTO_HTTP	/* Hypertext Transfer Protocol */
#undef	DOWNLOAD_PROTO_HTTPS	/* Secure Hypertext Transfer Protocol */
#undef	DOWNLOAD_PROTO_FTP	/* File Transfer Protocol */
#undef	DOWNLOAD_PROTO_TFTM	/* Multicast Trivial File Transfer Protocol */
#undef	DOWNLOAD_PROTO_SLAM	/* Scalable Local Area Multicast */

/*
 * SAN boot protocols
 *
 */

//#undef	SANBOOT_PROTO_ISCSI	/* iSCSI protocol */
//#undef	SANBOOT_PROTO_AOE	/* AoE protocol */
//#undef	SANBOOT_PROTO_IB_SRP	/* Infiniband SCSI RDMA protocol */
//#undef	SANBOOT_PROTO_FCP	/* Fibre Channel protocol */

/*
 * 802.11 cryptosystems and handshaking protocols
 *
 */
#define	CRYPTO_80211_WEP	/* WEP encryption (deprecated and insecure!) */
#define	CRYPTO_80211_WPA	/* WPA Personal, authenticating with passphrase */
#define	CRYPTO_80211_WPA2	/* Add support for stronger WPA cryptography */

/*
 * Name resolution modules
 *
 */

#define	DNS_RESOLVER		/* DNS resolver */

/*
 * Image types
 *
 * Etherboot supports various image formats.  Select whichever ones
 * you want to use.
 *
 */
//#define	IMAGE_NBI		/* NBI image support */
//#define	IMAGE_ELF		/* ELF image support */
//#define	IMAGE_FREEBSD		/* FreeBSD kernel image support */
//#define	IMAGE_MULTIBOOT		/* MultiBoot image support */
//#define	IMAGE_AOUT		/* a.out image support */
//#define	IMAGE_WINCE		/* WinCE image support */
//#define	IMAGE_PXE		/* PXE image support */
//#define	IMAGE_SCRIPT		/* iPXE script image support */
//#define	IMAGE_BZIMAGE		/* Linux bzImage image support */
//#define	IMAGE_COMBOOT		/* SYSLINUX COMBOOT image support */
//#define	IMAGE_EFI		/* EFI image support */

/*
 * Command-line commands to include
 *
 */
#define	AUTOBOOT_CMD		/* Automatic booting */
#define	NVO_CMD			/* Non-volatile option storage commands */
#define	CONFIG_CMD		/* Option configuration console */
#define	IFMGMT_CMD		/* Interface management commands */
#define	IWMGMT_CMD		/* Wireless interface management commands */
#define FCMGMT_CMD		/* Fibre Channel management commands */
#define	ROUTE_CMD		/* Routing table management commands */
#define IMAGE_CMD		/* Image management commands */
#define DHCP_CMD		/* DHCP management commands */
#define SANBOOT_CMD		/* SAN boot commands */
#define LOGIN_CMD		/* Login command */
#undef	TIME_CMD		/* Time commands */
#undef	DIGEST_CMD		/* Image crypto digest commands */
#undef	LOTEST_CMD		/* Loopback testing commands */
#undef	VLAN_CMD		/* VLAN commands */
#undef	PXE_CMD			/* PXE commands */
#undef	REBOOT_CMD		/* Reboot command */

/*
 * Error message tables to include
 *
 */
#undef	ERRMSG_80211		/* All 802.11 error descriptions (~3.3kb) */

/*
 * Obscure configuration options
 *
 * You probably don't need to touch these.
 *
 */

#define	NETDEV_DISCARD_RATE 0	/* Drop every N packets (0=>no drop) */
#undef	BUILD_SERIAL		/* Include an automatic build serial
				 * number.  Add "bs" to the list of
				 * make targets.  For example:
				 * "make bin/rtl8139.dsk bs" */
#undef	BUILD_ID		/* Include a custom build ID string,
				 * e.g "test-foo" */
#undef	NULL_TRAP		/* Attempt to catch NULL function calls */
#undef	GDBSERIAL		/* Remote GDB debugging over serial */
#undef	GDBUDP			/* Remote GDB debugging over UDP
				 * (both may be set) */

#include <config/local/general.h>

#endif /* CONFIG_GENERAL_H */
