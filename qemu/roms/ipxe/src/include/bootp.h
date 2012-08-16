#ifndef	_BOOTP_H
#define	_BOOTP_H

#ifdef	ALTERNATE_DHCP_PORTS_1067_1068
#undef	NON_STANDARD_BOOTP_SERVER
#define	NON_STANDARD_BOOTP_SERVER	1067
#undef	NON_STANDARD_BOOTP_CLIENT
#define	NON_STANDARD_BOOTP_CLIENT	1068
#endif

#ifdef	NON_STANDARD_BOOTP_SERVER
#define	BOOTP_SERVER	NON_STANDARD_BOOTP_SERVER
#else
#define BOOTP_SERVER	67
#endif
#ifdef	NON_STANDARD_BOOTP_CLIENT
#define	BOOTP_CLIENT	NON_STANDARD_BOOTP_CLIENT
#else
#define BOOTP_CLIENT	68
#endif
#define PROXYDHCP_SERVER	4011 /* For PXE */

#define BOOTP_REQUEST	1
#define BOOTP_REPLY	2

#define TAG_LEN(p)		(*((p)+1))
#define RFC1533_COOKIE		99, 130, 83, 99
#define RFC1533_PAD		0
#define RFC1533_NETMASK		1
#define RFC1533_TIMEOFFSET	2
#define RFC1533_GATEWAY		3
#define RFC1533_TIMESERVER	4
#define RFC1533_IEN116NS	5
#define RFC1533_DNS		6
#define RFC1533_LOGSERVER	7
#define RFC1533_COOKIESERVER	8
#define RFC1533_LPRSERVER	9
#define RFC1533_IMPRESSSERVER	10
#define RFC1533_RESOURCESERVER	11
#define RFC1533_HOSTNAME	12
#define RFC1533_BOOTFILESIZE	13
#define RFC1533_MERITDUMPFILE	14
#define RFC1533_DOMAINNAME	15
#define RFC1533_SWAPSERVER	16
#define RFC1533_ROOTPATH	17
#define RFC1533_EXTENSIONPATH	18
#define RFC1533_IPFORWARDING	19
#define RFC1533_IPSOURCEROUTING	20
#define RFC1533_IPPOLICYFILTER	21
#define RFC1533_IPMAXREASSEMBLY	22
#define RFC1533_IPTTL		23
#define RFC1533_IPMTU		24
#define RFC1533_IPMTUPLATEAU	25
#define RFC1533_INTMTU		26
#define RFC1533_INTLOCALSUBNETS	27
#define RFC1533_INTBROADCAST	28
#define RFC1533_INTICMPDISCOVER	29
#define RFC1533_INTICMPRESPOND	30
#define RFC1533_INTROUTEDISCOVER 31
#define RFC1533_INTROUTESOLICIT	32
#define RFC1533_INTSTATICROUTES	33
#define RFC1533_LLTRAILERENCAP	34
#define RFC1533_LLARPCACHETMO	35
#define RFC1533_LLETHERNETENCAP	36
#define RFC1533_TCPTTL		37
#define RFC1533_TCPKEEPALIVETMO	38
#define RFC1533_TCPKEEPALIVEGB	39
#define RFC1533_NISDOMAIN	40
#define RFC1533_NISSERVER	41
#define RFC1533_NTPSERVER	42
#define RFC1533_VENDOR		43
#define RFC1533_NBNS		44
#define RFC1533_NBDD		45
#define RFC1533_NBNT		46
#define RFC1533_NBSCOPE		47
#define RFC1533_XFS		48
#define RFC1533_XDM		49
#ifndef	NO_DHCP_SUPPORT
#define RFC2132_REQ_ADDR	50
#define RFC2132_MSG_TYPE	53
#define RFC2132_SRV_ID		54
#define RFC2132_PARAM_LIST	55
#define RFC2132_MAX_SIZE	57
#define	RFC2132_VENDOR_CLASS_ID	60
#define RFC2132_CLIENT_ID       61
#define	RFC2132_TFTP_SERVER_NAME 66
#define	RFC2132_BOOTFILE_NAME	67
#define RFC3004_USER_CLASS      77

#ifdef PXE_DHCP_STRICT
/*
 * The following options are acknowledged in RFC3679 because they are
 * widely used by PXE implementations, but have never been properly
 * allocated. Despite other PXE options being correctly packed in a
 * vendor encapsulated field, these are exposed. Sigh.  Note that the
 * client UUID (option 97) is also noted in the PXE spec as using
 * option 61.
 */
#define RFC3679_PXE_CLIENT_ARCH 93
#define RFC3679_PXE_CLIENT_NDI  94
#define RFC3679_PXE_CLIENT_UUID 97

/* The lengths are fixed. */
#define RFC3679_PXE_CLIENT_ARCH_LENGTH 2
#define RFC3679_PXE_CLIENT_NDI_LENGTH 3
#define RFC3679_PXE_CLIENT_UUID_LENGTH 17

/*
 * Values of RFC3679_PXE_CLIENT_ARCH can apparently be one of the
 * following, according to the PXE spec. The spec only actually
 * described the 2nd octet, not the first. Duh... assume 0.
 */
#define RFC3679_PXE_CLIENT_ARCH_IAX86PC   0,0
#define RFC3679_PXE_CLIENT_ARCH_NECPC98   0,1
#define RFC3679_PXE_CLIENT_ARCH_IA64PC    0,2
#define RFC3679_PXE_CLIENT_ARCH_DECALPHA  0,3
#define RFC3679_PXE_CLIENT_ARCH_ARCX86    0,4
#define RFC3679_PXE_CLIENT_ARCH_INTELLEAN 0,5

/* 
 * Only one valid value of NDI type (must be 1) and UNDI version (must
 * be 2.1)
 */
#define RFC3679_PXE_CLIENT_NDI_21 1,2,1

/*
 * UUID - type must be 1 and then 16 octets of UID, as with the client ID.
 * The value is a default for testing only
 */
#define RFC3679_PXE_CLIENT_UUID_TYPE 0
#warning "UUID is a default for testing ONLY!"
#define RFC3679_PXE_CLIENT_UUID_DEFAULT \
        RFC3679_PXE_CLIENT_UUID_TYPE, \
        0xDE,0xAD,0xBE,0xEF, \
        0xDE,0xAD,0xBE,0xEF, \
        0xDE,0xAD,0xBE,0xEF, \
        0xDE,0xAD,0xBE,0xEF
/*
 * The Vendor Class ID. Note that the Arch and UNDI version numbers
 * are fixed and must be same as the ARCH and NDI above.
 */
#define RFC2132_VENDOR_CLASS_ID_PXE_LENGTH 32
#define RFC2132_VENDOR_CLASS_ID_PXE \
        'P','X','E','C','l','i','e','n','t',':', \
        'A','r','c','h',':','0','0','0','0','0',':', \
        'U','N','D','I',':','0','0','2','0','0','1'

/*
 * The following vendor options are required in the PXE spec to pull
 * options for the *next* image. The PXE spec doesn't help us with
 * this (like explaining why).
 */
#define RFC1533_VENDOR_PXE_OPT128 128
#define RFC1533_VENDOR_PXE_OPT129 129
#define RFC1533_VENDOR_PXE_OPT130 130
#define RFC1533_VENDOR_PXE_OPT131 131
#define RFC1533_VENDOR_PXE_OPT132 132
#define RFC1533_VENDOR_PXE_OPT133 133
#define RFC1533_VENDOR_PXE_OPT134 134
#define RFC1533_VENDOR_PXE_OPT135 135

#endif /* PXE_DHCP_STRICT */

#define DHCPDISCOVER		1
#define DHCPOFFER		2
#define DHCPREQUEST		3
#define DHCPACK			5
#endif	/* NO_DHCP_SUPPORT */

#define RFC1533_VENDOR_MAJOR	0
#define RFC1533_VENDOR_MINOR	0

#define RFC1533_VENDOR_MAGIC	128
#define RFC1533_VENDOR_ADDPARM	129
#define	RFC1533_VENDOR_ETHDEV	130
/* We should really apply for an official Etherboot encap option */
#define RFC1533_VENDOR_ETHERBOOT_ENCAP 150
/* I'll leave it to FREEBSD to decide if they want to renumber */
#ifdef	IMAGE_FREEBSD
#define RFC1533_VENDOR_HOWTO    132
#define RFC1533_VENDOR_KERNEL_ENV    133
#endif
#define RFC1533_VENDOR_NIC_DEV_ID 175
#define RFC1533_VENDOR_ARCH     177

#define RFC1533_END		255

#define BOOTP_VENDOR_LEN	64
#ifndef	NO_DHCP_SUPPORT
#define DHCP_OPT_LEN		312
#endif	/* NO_DHCP_SUPPORT */

/* Format of a bootp packet */
struct bootp_t {
	uint8_t  bp_op;
	uint8_t  bp_htype;
	uint8_t  bp_hlen;
	uint8_t  bp_hops;
	uint32_t bp_xid;
	uint16_t bp_secs;
	uint16_t unused;
	in_addr bp_ciaddr;
	in_addr bp_yiaddr;
	in_addr bp_siaddr;
	in_addr bp_giaddr;
	uint8_t  bp_hwaddr[16];
	uint8_t  bp_sname[64];
	char     bp_file[128];
#ifdef	NO_DHCP_SUPPORT
	uint8_t  bp_vend[BOOTP_VENDOR_LEN];
#else
	uint8_t  bp_vend[DHCP_OPT_LEN];
#endif	/* NO_DHCP_SUPPORT */
};

/* Format of a bootp IP packet */
struct bootpip_t
{
	struct iphdr ip;
	struct udphdr udp;
	struct bootp_t bp;
};

/* Format of bootp packet with extensions */
struct bootpd_t {
	struct bootp_t bootp_reply;
	uint8_t bootp_extension[MAX_BOOTP_EXTLEN];
};

#endif	/* _BOOTP_H */
