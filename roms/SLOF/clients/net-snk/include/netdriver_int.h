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

#ifndef _NETDRIVER_INT_H
#define _NETDRIVER_INT_H
#include <stddef.h>
#include <unistd.h> /* ssize_t */
#include <fileio.h>

#if defined(__GNUC__) && !defined(UNUSED)
# define UNUSED __attribute__((unused))
#else
# define UNUSED
#endif

typedef struct {
	unsigned int addr;
	unsigned int size;
	int type;
} bar_t;


typedef struct {
	unsigned long long puid;
	unsigned int bus;
	unsigned int devfn;
	unsigned int vendor_id;
	unsigned int device_id;
	unsigned int revision_id;
	unsigned int class_code;
	bar_t bars[6];
	unsigned int interrupt_line;
} pci_config_t;

typedef struct {
	unsigned int reg;
	char	     compat[64];
} vio_config_t;

#define MOD_TYPE_NETWORK 0
#define MOD_TYPE_OTHER   1

typedef int (*mod_init_t)  (void);
typedef int (*mod_term_t)  (void);
typedef int (*mod_socket_t)(snk_fileio_t *, int dom, int type, int proto);
typedef int (*mod_open_t)  (snk_fileio_t *, const char *, int);
typedef int (*mod_read_t)  (char *, int);
typedef int (*mod_write_t) (char *, int);
typedef int (*mod_ioctl_t) (int, void *);

typedef struct {
	int version;
	int type;
	int running;
	void *link_addr;
	mod_init_t   init;
	mod_term_t   term;
	mod_socket_t socket;
	mod_open_t   open;
	mod_read_t   read;
	mod_write_t  write;
	mod_ioctl_t  ioctl;

	char mac_addr[6];
} snk_module_t;

#define MODULES_MAX 10
extern snk_module_t *snk_modules[MODULES_MAX];

typedef int (*print_t) (const char *, ...);
typedef void (*us_delay_t) (unsigned int);
typedef void (*ms_delay_t) (unsigned int);
typedef int (*pci_config_read_t) (long long puid, int size,
				  int bus, int devfn, int offset);
typedef int (*pci_config_write_t) (long long puid, int size,
				   int bus, int devfn, int offset, int value);
typedef void *(*malloc_aligned_t) (size_t, int);
typedef void *(*malloc_t) (size_t);
typedef void (*free_t)    (void *);
typedef int (*strcmp_t)   (const char *, const char *);
typedef int (*snk_call_t) (int, char **);
typedef unsigned int (*io_read_t) (void *, size_t);
typedef int (*io_write_t) (void *, unsigned int, size_t);
typedef unsigned int (*romfs_lookup_t) (const char *name, void **addr);
typedef void (*translate_addr_t) (unsigned long *);

typedef int (*k_open_t) (const char *, int);
typedef int (*k_close_t) (int);
typedef ssize_t (*k_read_t) (int, void *, size_t);
typedef ssize_t (*k_write_t) (int, const void *, size_t);
typedef int (*k_ioctl_t) (int, int, void *);

typedef void (*modules_remove_t) (int);
typedef snk_module_t *(*modules_load_t) (int);

typedef struct {
	int version;
	print_t print;
	us_delay_t us_delay;
	ms_delay_t ms_delay;
	pci_config_read_t pci_config_read;
	pci_config_write_t pci_config_write;
	malloc_t k_malloc;
	malloc_aligned_t k_malloc_aligned;
	free_t k_free;
	strcmp_t strcmp;
	snk_call_t snk_call;
	io_read_t io_read;
	io_write_t io_write;
	romfs_lookup_t k_romfs_lookup;
	translate_addr_t translate_addr;
	union {
		pci_config_t pci_conf;
		vio_config_t vio_conf;
	};
	k_open_t k_open;
	k_close_t k_close;
	k_read_t k_read;
	k_write_t k_write;
	k_ioctl_t k_ioctl;
	modules_remove_t modules_remove;
	modules_load_t modules_load;
} snk_kernel_t;

/* Entry of module */
snk_module_t *module_init(snk_kernel_t * snk_kernel_int,
                          pci_config_t * pciconf);


/*
 * Constants for different kinds of IOCTL requests
 */

#define SIOCETHTOOL  0x1000

/*
 * special structure and constants for IOCTL requests of type ETHTOOL
 */

#define ETHTOOL_GMAC         0x03
#define ETHTOOL_SMAC         0x04
#define ETHTOOL_VERSION      0x05

typedef struct {
	int idx;
	char address[6];
} ioctl_ethtool_mac_t;

typedef struct {
	unsigned int length;
	char *text;
} ioctl_ethtool_version_t;


/*
 * default structure and constants for IOCTL requests
 */

#define IF_NAME_SIZE 0xFF

typedef struct {
	char if_name[IF_NAME_SIZE];
	int subcmd;
	union {
		ioctl_ethtool_mac_t mac;
		ioctl_ethtool_version_t version;
	} data;
} ioctl_net_data_t;

/* paflof */
enum {
	PAFLOF_GDEPTH,
	PAFLOF_GIO_BEHAVIOR,
	PAFLOF_GSTATUS,
	PAFLOF_POP,
	PAFLOF_PUSH,
};
/*  - clint */
enum {
	CLINT_EXECUTE
};

#endif				/* _NETDRIVER_INT_H */
