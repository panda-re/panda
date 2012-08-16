/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <byteswap.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/in.h>
#include <ipxe/vsprintf.h>
#include <ipxe/dhcp.h>
#include <ipxe/uuid.h>
#include <ipxe/uri.h>
#include <ipxe/settings.h>

/** @file
 *
 * Configuration settings
 *
 */

/******************************************************************************
 *
 * Generic settings blocks
 *
 ******************************************************************************
 */

/**
 * A generic setting
 *
 */
struct generic_setting {
	/** List of generic settings */
	struct list_head list;
	/** Setting */
	struct setting setting;
	/** Size of setting name */
	size_t name_len;
	/** Size of setting data */
	size_t data_len;
};

/**
 * Get generic setting name
 *
 * @v generic		Generic setting
 * @ret name		Generic setting name
 */
static inline void * generic_setting_name ( struct generic_setting *generic ) {
	return ( ( ( void * ) generic ) + sizeof ( *generic ) );
}

/**
 * Get generic setting data
 *
 * @v generic		Generic setting
 * @ret data		Generic setting data
 */
static inline void * generic_setting_data ( struct generic_setting *generic ) {
	return ( ( ( void * ) generic ) + sizeof ( *generic ) +
		 generic->name_len );
}

/**
 * Find generic setting
 *
 * @v generics		Generic settings block
 * @v setting		Setting to find
 * @ret generic		Generic setting, or NULL
 */
static struct generic_setting *
find_generic_setting ( struct generic_settings *generics,
		       struct setting *setting ) {
	struct generic_setting *generic;

	list_for_each_entry ( generic, &generics->list, list ) {
		if ( setting_cmp ( &generic->setting, setting ) == 0 )
			return generic;
	}
	return NULL;
}

/**
 * Store value of generic setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v data		Setting data, or NULL to clear setting
 * @v len		Length of setting data
 * @ret rc		Return status code
 */
int generic_settings_store ( struct settings *settings,
			     struct setting *setting,
			     const void *data, size_t len ) {
	struct generic_settings *generics =
		container_of ( settings, struct generic_settings, settings );
	struct generic_setting *old;
	struct generic_setting *new = NULL;
	size_t name_len;

	/* Identify existing generic setting, if any */
	old = find_generic_setting ( generics, setting );

	/* Create new generic setting, if required */
	if ( len ) {
		/* Allocate new generic setting */
		name_len = ( strlen ( setting->name ) + 1 );
		new = zalloc ( sizeof ( *new ) + name_len + len );
		if ( ! new )
			return -ENOMEM;

		/* Populate new generic setting */
		new->name_len = name_len;
		new->data_len = len;
		memcpy ( &new->setting, setting, sizeof ( new->setting ) );
		new->setting.name = generic_setting_name ( new );
		memcpy ( generic_setting_name ( new ),
			 setting->name, name_len );
		memcpy ( generic_setting_data ( new ), data, len );
	}

	/* Delete existing generic setting, if any */
	if ( old ) {
		list_del ( &old->list );
		free ( old );
	}

	/* Add new setting to list, if any */
	if ( new )
		list_add ( &new->list, &generics->list );

	return 0;
}

/**
 * Fetch value of generic setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
int generic_settings_fetch ( struct settings *settings,
			     struct setting *setting,
			     void *data, size_t len ) {
	struct generic_settings *generics =
		container_of ( settings, struct generic_settings, settings );
	struct generic_setting *generic;

	/* Find generic setting */
	generic = find_generic_setting ( generics, setting );
	if ( ! generic )
		return -ENOENT;

	/* Copy out generic setting data */
	if ( len > generic->data_len )
		len = generic->data_len;
	memcpy ( data, generic_setting_data ( generic ), len );
	return generic->data_len;
}

/**
 * Clear generic settings block
 *
 * @v settings		Settings block
 */
void generic_settings_clear ( struct settings *settings ) {
	struct generic_settings *generics =
		container_of ( settings, struct generic_settings, settings );
	struct generic_setting *generic;
	struct generic_setting *tmp;

	list_for_each_entry_safe ( generic, tmp, &generics->list, list ) {
		list_del ( &generic->list );
		free ( generic );
	}
	assert ( list_empty ( &generics->list ) );
}

/** Generic settings operations */
struct settings_operations generic_settings_operations = {
	.store = generic_settings_store,
	.fetch = generic_settings_fetch,
	.clear = generic_settings_clear,
};

/******************************************************************************
 *
 * Registered settings blocks
 *
 ******************************************************************************
 */

/** Root generic settings block */
struct generic_settings generic_settings_root = {
	.settings = {
		.refcnt = NULL,
		.name = "",
		.siblings =
		    LIST_HEAD_INIT ( generic_settings_root.settings.siblings ),
		.children =
		    LIST_HEAD_INIT ( generic_settings_root.settings.children ),
		.op = &generic_settings_operations,
	},
	.list = LIST_HEAD_INIT ( generic_settings_root.list ),
};

/** Root settings block */
#define settings_root generic_settings_root.settings

/** Autovivified settings block */
struct autovivified_settings {
	/** Reference count */
	struct refcnt refcnt;
	/** Generic settings block */
	struct generic_settings generic;
};

/**
 * Free autovivified settings block
 *
 * @v refcnt		Reference count
 */
static void autovivified_settings_free ( struct refcnt *refcnt ) {
	struct autovivified_settings *autovivified =
		container_of ( refcnt, struct autovivified_settings, refcnt );

	generic_settings_clear ( &autovivified->generic.settings );
	free ( autovivified );
}

/**
 * Find child named settings block
 *
 * @v parent		Parent settings block
 * @v name		Name within this parent
 * @ret settings	Settings block, or NULL
 */
static struct settings * find_child_settings ( struct settings *parent,
					       const char *name ) {
	struct settings *settings;

	/* Treat empty name as meaning "this block" */
	if ( ! *name )
		return parent;

	/* Look for child with matching name */
	list_for_each_entry ( settings, &parent->children, siblings ) {
		if ( strcmp ( settings->name, name ) == 0 )
			return settings;
	}

	return NULL;
}

/**
 * Find or create child named settings block
 *
 * @v parent		Parent settings block
 * @v name		Name within this parent
 * @ret settings	Settings block, or NULL
 */
static struct settings * autovivify_child_settings ( struct settings *parent,
						     const char *name ) {
	struct {
		struct autovivified_settings autovivified;
		char name[ strlen ( name ) + 1 /* NUL */ ];
	} *new_child;
	struct settings *settings;

	/* Return existing settings, if existent */
	if ( ( settings = find_child_settings ( parent, name ) ) != NULL )
		return settings;

	/* Create new generic settings block */
	new_child = zalloc ( sizeof ( *new_child ) );
	if ( ! new_child ) {
		DBGC ( parent, "Settings %p could not create child %s\n",
		       parent, name );
		return NULL;
	}
	memcpy ( new_child->name, name, sizeof ( new_child->name ) );
	ref_init ( &new_child->autovivified.refcnt,
		   autovivified_settings_free );
	generic_settings_init ( &new_child->autovivified.generic,
				&new_child->autovivified.refcnt );
	settings = &new_child->autovivified.generic.settings;
	register_settings ( settings, parent, new_child->name );
	return settings;
}

/**
 * Return settings block name
 *
 * @v settings		Settings block
 * @ret name		Settings block name
 */
const char * settings_name ( struct settings *settings ) {
	static char buf[16];
	char tmp[ sizeof ( buf ) ];

	for ( buf[2] = buf[0] = 0 ; settings ; settings = settings->parent ) {
		memcpy ( tmp, buf, sizeof ( tmp ) );
		snprintf ( buf, sizeof ( buf ), ".%s%s", settings->name, tmp );
	}
	return ( buf + 2 );
}

/**
 * Parse settings block name
 *
 * @v name		Name
 * @v get_child		Function to find or create child settings block
 * @ret settings	Settings block, or NULL
 */
static struct settings *
parse_settings_name ( const char *name,
		      struct settings * ( * get_child ) ( struct settings *,
							  const char * ) ) {
	struct settings *settings = &settings_root;
	char name_copy[ strlen ( name ) + 1 ];
	char *subname;
	char *remainder;

	/* Create modifiable copy of name */
	memcpy ( name_copy, name, sizeof ( name_copy ) );
	remainder = name_copy;

	/* Parse each name component in turn */
	while ( remainder ) {
		struct net_device *netdev;

		subname = remainder;
		remainder = strchr ( subname, '.' );
		if ( remainder )
			*(remainder++) = '\0';

		/* Special case "netX" root settings block */
		if ( ( subname == name_copy ) && ! strcmp ( subname, "netX" ) &&
		     ( ( netdev = last_opened_netdev() ) != NULL ) )
			settings = get_child ( settings, netdev->name );
		else
			settings = get_child ( settings, subname );

		if ( ! settings )
			break;
	}

	return settings;
}

/**
 * Find named settings block
 *
 * @v name		Name
 * @ret settings	Settings block, or NULL
 */
struct settings * find_settings ( const char *name ) {

	return parse_settings_name ( name, find_child_settings );
}

/**
 * Apply all settings
 *
 * @ret rc		Return status code
 */
static int apply_settings ( void ) {
	struct settings_applicator *applicator;
	int rc;

	/* Call all settings applicators */
	for_each_table_entry ( applicator, SETTINGS_APPLICATORS ) {
		if ( ( rc = applicator->apply() ) != 0 ) {
			DBG ( "Could not apply settings using applicator "
			      "%p: %s\n", applicator, strerror ( rc ) );
			return rc;
		}
	}

	return 0;
}

/**
 * Reprioritise settings
 *
 * @v settings		Settings block
 *
 * Reorders the settings block amongst its siblings according to its
 * priority.
 */
static void reprioritise_settings ( struct settings *settings ) {
	struct settings *parent = settings->parent;
	long priority;
	struct settings *tmp;
	long tmp_priority;

	/* Stop when we reach the top of the tree */
	if ( ! parent )
		return;

	/* Read priority, if present */
	priority = fetch_intz_setting ( settings, &priority_setting );

	/* Remove from siblings list */
	list_del ( &settings->siblings );

	/* Reinsert after any existing blocks which have a higher priority */
	list_for_each_entry ( tmp, &parent->children, siblings ) {
		tmp_priority = fetch_intz_setting ( tmp, &priority_setting );
		if ( priority > tmp_priority )
			break;
	}
	list_add_tail ( &settings->siblings, &tmp->siblings );

	/* Recurse up the tree */
	reprioritise_settings ( parent );
}

/**
 * Register settings block
 *
 * @v settings		Settings block
 * @v parent		Parent settings block, or NULL
 * @v name		Settings block name
 * @ret rc		Return status code
 */
int register_settings ( struct settings *settings, struct settings *parent,
			const char *name ) {
	struct settings *old_settings;

	/* NULL parent => add to settings root */
	assert ( settings != NULL );
	if ( parent == NULL )
		parent = &settings_root;

	/* Apply settings block name */
	settings->name = name;

	/* Remove any existing settings with the same name */
	if ( ( old_settings = find_child_settings ( parent, settings->name ) ))
		unregister_settings ( old_settings );

	/* Add to list of settings */
	ref_get ( settings->refcnt );
	ref_get ( parent->refcnt );
	settings->parent = parent;
	list_add_tail ( &settings->siblings, &parent->children );
	DBGC ( settings, "Settings %p (\"%s\") registered\n",
	       settings, settings_name ( settings ) );

	/* Fix up settings priority */
	reprioritise_settings ( settings );

	/* Apply potentially-updated settings */
	apply_settings();

	return 0;
}

/**
 * Unregister settings block
 *
 * @v settings		Settings block
 */
void unregister_settings ( struct settings *settings ) {
	struct settings *child;
	struct settings *tmp;

	/* Unregister child settings */
	list_for_each_entry_safe ( child, tmp, &settings->children, siblings ) {
		unregister_settings ( child );
	}

	DBGC ( settings, "Settings %p (\"%s\") unregistered\n",
	       settings, settings_name ( settings ) );

	/* Remove from list of settings */
	ref_put ( settings->parent->refcnt );
	settings->parent = NULL;
	list_del ( &settings->siblings );
	ref_put ( settings->refcnt );

	/* Apply potentially-updated settings */
	apply_settings();
}

/******************************************************************************
 *
 * Core settings routines
 *
 ******************************************************************************
 */

/**
 * Check applicability of setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
int setting_applies ( struct settings *settings, struct setting *setting ) {

	return ( settings->op->applies ?
		 settings->op->applies ( settings, setting ) : 1 );
}

/**
 * Store value of setting
 *
 * @v settings		Settings block, or NULL
 * @v setting		Setting to store
 * @v data		Setting data, or NULL to clear setting
 * @v len		Length of setting data
 * @ret rc		Return status code
 */
int store_setting ( struct settings *settings, struct setting *setting,
		    const void *data, size_t len ) {
	int rc;

	/* NULL settings implies storing into the global settings root */
	if ( ! settings )
		settings = &settings_root;

	/* Fail if tag does not apply to this settings block */
	if ( ! setting_applies ( settings, setting ) )
		return -ENOTTY;

	/* Sanity check */
	if ( ! settings->op->store )
		return -ENOTSUP;

	/* Store setting */
	if ( ( rc = settings->op->store ( settings, setting,
					  data, len ) ) != 0 )
		return rc;

	/* Reprioritise settings if necessary */
	if ( setting_cmp ( setting, &priority_setting ) == 0 )
		reprioritise_settings ( settings );

	/* If these settings are registered, apply potentially-updated
	 * settings
	 */
	for ( ; settings ; settings = settings->parent ) {
		if ( settings == &settings_root ) {
			if ( ( rc = apply_settings() ) != 0 )
				return rc;
			break;
		}
	}

	return 0;
}

/**
 * Fetch value and origin of setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v origin		Origin of setting to fill in
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 *
 * The actual length of the setting will be returned even if
 * the buffer was too small.
 */
static int fetch_setting_and_origin ( struct settings *settings,
				      struct setting *setting,
				      struct settings **origin,
				      void *data, size_t len ) {
	struct settings *child;
	int ret;

	/* Avoid returning uninitialised data on error */
	memset ( data, 0, len );
	if ( origin )
		*origin = NULL;

	/* NULL settings implies starting at the global settings root */
	if ( ! settings )
		settings = &settings_root;

	/* Sanity check */
	if ( ! settings->op->fetch )
		return -ENOTSUP;

	/* Try this block first, if applicable */
	if ( setting_applies ( settings, setting ) &&
	     ( ( ret = settings->op->fetch ( settings, setting,
					     data, len ) ) >= 0 ) ) {
		if ( origin )
			*origin = settings;
		return ret;
	}

	/* Recurse into each child block in turn */
	list_for_each_entry ( child, &settings->children, siblings ) {
		if ( ( ret = fetch_setting_and_origin ( child, setting, origin,
							data, len ) ) >= 0 )
			return ret;
	}

	return -ENOENT;
}

/**
 * Fetch value of setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 *
 * The actual length of the setting will be returned even if
 * the buffer was too small.
 */
int fetch_setting ( struct settings *settings, struct setting *setting,
		    void *data, size_t len ) {
	return fetch_setting_and_origin ( settings, setting, NULL, data, len );
}

/**
 * Fetch origin of setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @ret origin		Origin of setting, or NULL if not found
 *
 * This function can also be used as an existence check for the
 * setting.
 */
struct settings * fetch_setting_origin ( struct settings *settings,
					 struct setting *setting ) {
	struct settings *origin;

	fetch_setting_and_origin ( settings, setting, &origin, NULL, 0 );
	return origin;
}

/**
 * Fetch length of setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @ret len		Length of setting data, or negative error
 *
 * This function can also be used as an existence check for the
 * setting.
 */
int fetch_setting_len ( struct settings *settings, struct setting *setting ) {
	return fetch_setting ( settings, setting, NULL, 0 );
}

/**
 * Fetch value of string setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting string data
 * @v len		Length of buffer
 * @ret len		Length of string setting, or negative error
 *
 * The resulting string is guaranteed to be correctly NUL-terminated.
 * The returned length will be the length of the underlying setting
 * data.
 */
int fetch_string_setting ( struct settings *settings, struct setting *setting,
			   char *data, size_t len ) {
	memset ( data, 0, len );
	return fetch_setting ( settings, setting, data,
			       ( ( len > 0 ) ? ( len - 1 ) : 0 ) );
}

/**
 * Fetch value of string setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v data		Buffer to allocate and fill with setting string data
 * @ret len		Length of string setting, or negative error
 *
 * The resulting string is guaranteed to be correctly NUL-terminated.
 * The returned length will be the length of the underlying setting
 * data.  The caller is responsible for eventually freeing the
 * allocated buffer.
 *
 * To allow the caller to distinguish between a non-existent setting
 * and an error in allocating memory for the copy, this function will
 * return success (and a NULL buffer pointer) for a non-existent
 * setting.
 */
int fetch_string_setting_copy ( struct settings *settings,
				struct setting *setting,
				char **data ) {
	int len;
	int check_len = 0;

	/* Avoid returning uninitialised data on error */
	*data = NULL;

	/* Fetch setting length, and return success if non-existent */
	len = fetch_setting_len ( settings, setting );
	if ( len < 0 )
		return 0;

	/* Allocate string buffer */
	*data = malloc ( len + 1 );
	if ( ! *data )
		return -ENOMEM;

	/* Fetch setting */
	check_len = fetch_string_setting ( settings, setting, *data,
					   ( len + 1 ) );
	assert ( check_len == len );
	return len;
}

/**
 * Fetch value of IPv4 address setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v inp		IPv4 addresses to fill in
 * @v count		Maximum number of IPv4 addresses
 * @ret len		Length of setting, or negative error
 */
int fetch_ipv4_array_setting ( struct settings *settings,
			       struct setting *setting,
			       struct in_addr *inp, unsigned int count ) {
	int len;

	len = fetch_setting ( settings, setting, inp,
			      ( sizeof ( *inp ) * count ) );
	if ( len < 0 )
		return len;
	if ( ( len % sizeof ( *inp ) ) != 0 )
		return -ERANGE;
	return len;
}

/**
 * Fetch value of IPv4 address setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v inp		IPv4 address to fill in
 * @ret len		Length of setting, or negative error
 */
int fetch_ipv4_setting ( struct settings *settings, struct setting *setting,
			 struct in_addr *inp ) {
	return fetch_ipv4_array_setting ( settings, setting, inp, 1 );
}

/**
 * Fetch value of signed integer setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v value		Integer value to fill in
 * @ret len		Length of setting, or negative error
 */
int fetch_int_setting ( struct settings *settings, struct setting *setting,
			long *value ) {
	union {
		uint8_t u8[ sizeof ( long ) ];
		int8_t s8[ sizeof ( long ) ];
	} buf;
	int len;
	int i;

	/* Avoid returning uninitialised data on error */
	*value = 0;

	/* Fetch raw (network-ordered, variable-length) setting */
	len = fetch_setting ( settings, setting, &buf, sizeof ( buf ) );
	if ( len < 0 )
		return len;
	if ( len > ( int ) sizeof ( buf ) )
		return -ERANGE;

	/* Convert to host-ordered signed long */
	*value = ( ( buf.s8[0] >= 0 ) ? 0 : -1L );
	for ( i = 0 ; i < len ; i++ ) {
		*value = ( ( *value << 8 ) | buf.u8[i] );
	}

	return len;
}

/**
 * Fetch value of unsigned integer setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v value		Integer value to fill in
 * @ret len		Length of setting, or negative error
 */
int fetch_uint_setting ( struct settings *settings, struct setting *setting,
			 unsigned long *value ) {
	long svalue;
	int len;

	/* Avoid returning uninitialised data on error */
	*value = 0;

	/* Fetch as a signed long */
	len = fetch_int_setting ( settings, setting, &svalue );
	if ( len < 0 )
		return len;

	/* Mask off sign-extended bits */
	assert ( len <= ( int ) sizeof ( long ) );
	*value = ( svalue & ( -1UL >> ( 8 * ( sizeof ( long ) - len ) ) ) );

	return len;
}

/**
 * Fetch value of signed integer setting, or zero
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @ret value		Setting value, or zero
 */
long fetch_intz_setting ( struct settings *settings, struct setting *setting ){
	long value;

	fetch_int_setting ( settings, setting, &value );
	return value;
}

/**
 * Fetch value of unsigned integer setting, or zero
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @ret value		Setting value, or zero
 */
unsigned long fetch_uintz_setting ( struct settings *settings,
				    struct setting *setting ) {
	unsigned long value;

	fetch_uint_setting ( settings, setting, &value );
	return value;
}

/**
 * Fetch value of UUID setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v uuid		UUID to fill in
 * @ret len		Length of setting, or negative error
 */
int fetch_uuid_setting ( struct settings *settings, struct setting *setting,
			 union uuid *uuid ) {
	int len;

	len = fetch_setting ( settings, setting, uuid, sizeof ( *uuid ) );
	if ( len < 0 )
		return len;
	if ( len != sizeof ( *uuid ) )
		return -ERANGE;
	return len;
}

/**
 * Clear settings block
 *
 * @v settings		Settings block
 */
void clear_settings ( struct settings *settings ) {
	if ( settings->op->clear )
		settings->op->clear ( settings );
}

/**
 * Compare two settings
 *
 * @v a			Setting to compare
 * @v b			Setting to compare
 * @ret 0		Settings are the same
 * @ret non-zero	Settings are not the same
 */
int setting_cmp ( struct setting *a, struct setting *b ) {

	/* If the settings have tags, compare them */
	if ( a->tag && ( a->tag == b->tag ) )
		return 0;

	/* Otherwise, if the settings have names, compare them */
	if ( a->name && b->name && a->name[0] )
		return strcmp ( a->name, b->name );

	/* Otherwise, return a non-match */
	return ( ! 0 );
}

/******************************************************************************
 *
 * Formatted setting routines
 *
 ******************************************************************************
 */

/**
 * Store value of typed setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v type		Settings type
 * @v value		Formatted setting data, or NULL
 * @ret rc		Return status code
 */
int storef_setting ( struct settings *settings, struct setting *setting,
		     const char *value ) {

	/* NULL value implies deletion.  Avoid imposing the burden of
	 * checking for NULL values on each typed setting's storef()
	 * method.
	 */
	if ( ! value )
		return delete_setting ( settings, setting );
		
	return setting->type->storef ( settings, setting, value );
}

/**
 * Find named setting
 *
 * @v name		Name
 * @ret setting		Named setting, or NULL
 */
struct setting * find_setting ( const char *name ) {
	struct setting *setting;

	for_each_table_entry ( setting, SETTINGS ) {
		if ( strcmp ( name, setting->name ) == 0 )
			return setting;
	}
	return NULL;
}

/**
 * Parse setting name as tag number
 *
 * @v settings		Settings block
 * @v name		Name
 * @ret tag		Tag number, or 0 if not a valid number
 */
static unsigned int parse_setting_tag ( struct settings *settings,
					const char *name ) {
	char *tmp = ( ( char * ) name );
	unsigned int tag = 0;

	while ( 1 ) {
		tag = ( ( tag << 8 ) | strtoul ( tmp, &tmp, 0 ) );
		if ( *tmp == 0 )
			return ( tag | settings->tag_magic );
		if ( *tmp != '.' )
			return 0;
		tmp++;
	}
}

/**
 * Find setting type
 *
 * @v name		Name
 * @ret type		Setting type, or NULL
 */
static struct setting_type * find_setting_type ( const char *name ) {
	struct setting_type *type;

	for_each_table_entry ( type, SETTING_TYPES ) {
		if ( strcmp ( name, type->name ) == 0 )
			return type;
	}
	return NULL;
}

/**
 * Parse setting name
 *
 * @v name		Name of setting
 * @v get_child		Function to find or create child settings block
 * @v settings		Settings block to fill in
 * @v setting		Setting to fill in
 * @v tmp_name		Buffer for copy of setting name
 * @ret rc		Return status code
 *
 * Interprets a name of the form
 * "[settings_name/]tag_name[:type_name]" and fills in the appropriate
 * fields.
 *
 * The @c tmp_name buffer must be large enough to hold a copy of the
 * setting name.
 */
static int
parse_setting_name ( const char *name,
		     struct settings * ( * get_child ) ( struct settings *,
							 const char * ),
		     struct settings **settings, struct setting *setting,
		     char *tmp_name ) {
	char *settings_name;
	char *setting_name;
	char *type_name;
	struct setting *named_setting;

	/* Set defaults */
	*settings = &settings_root;
	memset ( setting, 0, sizeof ( *setting ) );
	setting->name = "";
	setting->type = &setting_type_string;

	/* Split name into "[settings_name/]setting_name[:type_name]" */
	strcpy ( tmp_name, name );
	if ( ( setting_name = strchr ( tmp_name, '/' ) ) != NULL ) {
		*(setting_name++) = 0;
		settings_name = tmp_name;
	} else {
		setting_name = tmp_name;
		settings_name = NULL;
	}
	if ( ( type_name = strchr ( setting_name, ':' ) ) != NULL )
		*(type_name++) = 0;

	/* Identify settings block, if specified */
	if ( settings_name ) {
		*settings = parse_settings_name ( settings_name, get_child );
		if ( *settings == NULL ) {
			DBG ( "Unrecognised settings block \"%s\" in \"%s\"\n",
			      settings_name, name );
			return -ENODEV;
		}
	}

	/* Identify setting */
	setting->tag = parse_setting_tag ( *settings, setting_name );
	setting->name = setting_name;
	for_each_table_entry ( named_setting, SETTINGS ) {
		/* Matches a defined named setting; use that setting */
		if ( setting_cmp ( named_setting, setting ) == 0 ) {
			memcpy ( setting, named_setting, sizeof ( *setting ) );
			break;
		}
	}

	/* Identify setting type, if specified */
	if ( type_name ) {
		setting->type = find_setting_type ( type_name );
		if ( setting->type == NULL ) {
			DBG ( "Invalid setting type \"%s\" in \"%s\"\n",
			      type_name, name );
			return -ENOTSUP;
		}
	}

	return 0;
}

/**
 * Return full setting name
 *
 * @v settings		Settings block, or NULL
 * @v setting		Setting
 * @v buf		Buffer
 * @v len		Length of buffer
 * @ret len		Length of setting name, or negative error
 */
int setting_name ( struct settings *settings, struct setting *setting,
		   char *buf, size_t len ) {
	const char *name;

	if ( ! settings )
		settings = &settings_root;

	name = settings_name ( settings );
	return snprintf ( buf, len, "%s%s%s:%s", name, ( name[0] ? "/" : "" ),
			  setting->name, setting->type->name );
}

/**
 * Parse and store value of named setting
 *
 * @v name		Name of setting
 * @v value		Formatted setting data, or NULL
 * @ret rc		Return status code
 */
int storef_named_setting ( const char *name, const char *value ) {
	struct settings *settings;
	struct setting setting;
	char tmp_name[ strlen ( name ) + 1 ];
	int rc;

	/* Parse setting name */
	if ( ( rc = parse_setting_name ( name, autovivify_child_settings,
					 &settings, &setting, tmp_name )) != 0)
		return rc;

	/* Store setting */
	if ( ( rc = storef_setting ( settings, &setting, value ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Fetch and format value of named setting
 *
 * @v name		Name of setting
 * @v name_buf		Buffer to contain canonicalised name
 * @v name_len		Length of canonicalised name buffer
 * @v value_buf		Buffer to contain formatted value
 * @v value_len		Length of formatted value buffer
 * @ret len		Length of formatted value, or negative error
 */
int fetchf_named_setting ( const char *name,
			   char *name_buf, size_t name_len,
			   char *value_buf, size_t value_len ) {
	struct settings *settings;
	struct setting setting;
	struct settings *origin;
	char tmp_name[ strlen ( name ) + 1 ];
	int len;
	int rc;

	/* Parse setting name */
	if ( ( rc = parse_setting_name ( name, find_child_settings,
					 &settings, &setting, tmp_name )) != 0)
		return rc;

	/* Fetch setting */
	if ( ( len = fetchf_setting ( settings, &setting, value_buf,
				     value_len ) ) < 0 )
		return len;

	/* Construct setting name */
	origin = fetch_setting_origin ( settings, &setting );
	assert ( origin != NULL );
	setting_name ( origin, &setting, name_buf, name_len );

	return len;
}

/******************************************************************************
 *
 * Setting types
 *
 ******************************************************************************
 */

/**
 * Parse and store value of string setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v value		Formatted setting data
 * @ret rc		Return status code
 */
static int storef_string ( struct settings *settings, struct setting *setting,
			   const char *value ) {
	return store_setting ( settings, setting, value, strlen ( value ) );
}

/**
 * Fetch and format value of string setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int fetchf_string ( struct settings *settings, struct setting *setting,
			   char *buf, size_t len ) {
	return fetch_string_setting ( settings, setting, buf, len );
}

/** A string setting type */
struct setting_type setting_type_string __setting_type = {
	.name = "string",
	.storef = storef_string,
	.fetchf = fetchf_string,
};

/**
 * Parse and store value of URI-encoded string setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v value		Formatted setting data
 * @ret rc		Return status code
 */
static int storef_uristring ( struct settings *settings,
			      struct setting *setting,
			      const char *value ) {
	char buf[ strlen ( value ) + 1 ]; /* Decoding never expands string */
	size_t len;

	len = uri_decode ( value, buf, sizeof ( buf ) );
	return store_setting ( settings, setting, buf, len );
}

/**
 * Fetch and format value of URI-encoded string setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int fetchf_uristring ( struct settings *settings,
			      struct setting *setting,
			      char *buf, size_t len ) {
	ssize_t raw_len;

	/* We need to always retrieve the full raw string to know the
	 * length of the encoded string.
	 */
	raw_len = fetch_setting ( settings, setting, NULL, 0 );
	if ( raw_len < 0 )
		return raw_len;

	{
		char raw_buf[ raw_len + 1 ];
       
		fetch_string_setting ( settings, setting, raw_buf,
				       sizeof ( raw_buf ) );
		return uri_encode ( raw_buf, buf, len, URI_FRAGMENT );
	}
}

/** A URI-encoded string setting type */
struct setting_type setting_type_uristring __setting_type = {
	.name = "uristring",
	.storef = storef_uristring,
	.fetchf = fetchf_uristring,
};

/**
 * Parse and store value of IPv4 address setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v value		Formatted setting data
 * @ret rc		Return status code
 */
static int storef_ipv4 ( struct settings *settings, struct setting *setting,
			 const char *value ) {
	struct in_addr ipv4;

	if ( inet_aton ( value, &ipv4 ) == 0 )
		return -EINVAL;
	return store_setting ( settings, setting, &ipv4, sizeof ( ipv4 ) );
}

/**
 * Fetch and format value of IPv4 address setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int fetchf_ipv4 ( struct settings *settings, struct setting *setting,
			 char *buf, size_t len ) {
	struct in_addr ipv4;
	int raw_len;

	if ( ( raw_len = fetch_ipv4_setting ( settings, setting, &ipv4 ) ) < 0)
		return raw_len;
	return snprintf ( buf, len, "%s", inet_ntoa ( ipv4 ) );
}

/** An IPv4 address setting type */
struct setting_type setting_type_ipv4 __setting_type = {
	.name = "ipv4",
	.storef = storef_ipv4,
	.fetchf = fetchf_ipv4,
};

/**
 * Parse and store value of integer setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v value		Formatted setting data
 * @v size		Integer size, in bytes
 * @ret rc		Return status code
 */
static int storef_int ( struct settings *settings, struct setting *setting,
			const char *value, unsigned int size ) {
	union {
		uint32_t num;
		uint8_t bytes[4];
	} u;
	char *endp;

	u.num = htonl ( strtoul ( value, &endp, 0 ) );
	if ( *endp )
		return -EINVAL;
	return store_setting ( settings, setting, 
			       &u.bytes[ sizeof ( u ) - size ], size );
}

/**
 * Parse and store value of 8-bit integer setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v value		Formatted setting data
 * @v size		Integer size, in bytes
 * @ret rc		Return status code
 */
static int storef_int8 ( struct settings *settings, struct setting *setting,
			 const char *value ) {
	return storef_int ( settings, setting, value, 1 );
}

/**
 * Parse and store value of 16-bit integer setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v value		Formatted setting data
 * @v size		Integer size, in bytes
 * @ret rc		Return status code
 */
static int storef_int16 ( struct settings *settings, struct setting *setting,
			  const char *value ) {
	return storef_int ( settings, setting, value, 2 );
}

/**
 * Parse and store value of 32-bit integer setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v value		Formatted setting data
 * @v size		Integer size, in bytes
 * @ret rc		Return status code
 */
static int storef_int32 ( struct settings *settings, struct setting *setting,
			  const char *value ) {
	return storef_int ( settings, setting, value, 4 );
}

/**
 * Fetch and format value of signed integer setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int fetchf_int ( struct settings *settings, struct setting *setting,
			char *buf, size_t len ) {
	long value;
	int rc;

	if ( ( rc = fetch_int_setting ( settings, setting, &value ) ) < 0 )
		return rc;
	return snprintf ( buf, len, "%ld", value );
}

/**
 * Fetch and format value of unsigned integer setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int fetchf_uint ( struct settings *settings, struct setting *setting,
			 char *buf, size_t len ) {
	unsigned long value;
	int rc;

	if ( ( rc = fetch_uint_setting ( settings, setting, &value ) ) < 0 )
		return rc;
	return snprintf ( buf, len, "%#lx", value );
}

/** A signed 8-bit integer setting type */
struct setting_type setting_type_int8 __setting_type = {
	.name = "int8",
	.storef = storef_int8,
	.fetchf = fetchf_int,
};

/** A signed 16-bit integer setting type */
struct setting_type setting_type_int16 __setting_type = {
	.name = "int16",
	.storef = storef_int16,
	.fetchf = fetchf_int,
};

/** A signed 32-bit integer setting type */
struct setting_type setting_type_int32 __setting_type = {
	.name = "int32",
	.storef = storef_int32,
	.fetchf = fetchf_int,
};

/** An unsigned 8-bit integer setting type */
struct setting_type setting_type_uint8 __setting_type = {
	.name = "uint8",
	.storef = storef_int8,
	.fetchf = fetchf_uint,
};

/** An unsigned 16-bit integer setting type */
struct setting_type setting_type_uint16 __setting_type = {
	.name = "uint16",
	.storef = storef_int16,
	.fetchf = fetchf_uint,
};

/** An unsigned 32-bit integer setting type */
struct setting_type setting_type_uint32 __setting_type = {
	.name = "uint32",
	.storef = storef_int32,
	.fetchf = fetchf_uint,
};

/**
 * Parse and store value of hex string setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v value		Formatted setting data
 * @ret rc		Return status code
 */
static int storef_hex ( struct settings *settings, struct setting *setting,
			const char *value ) {
	char *ptr = ( char * ) value;
	uint8_t bytes[ strlen ( value ) ]; /* cannot exceed strlen(value) */
	unsigned int len = 0;

	while ( 1 ) {
		bytes[len++] = strtoul ( ptr, &ptr, 16 );
		switch ( *ptr ) {
		case '\0' :
			return store_setting ( settings, setting, bytes, len );
		case ':' :
		case '-' :
			ptr++;
			break;
		default :
			return -EINVAL;
		}
	}
}

/**
 * Fetch and format value of hex string setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @v delimiter		Byte delimiter
 * @ret len		Length of formatted value, or negative error
 */
static int fetchf_hex ( struct settings *settings, struct setting *setting,
			char *buf, size_t len, const char *delimiter ) {
	int raw_len;
	int check_len;
	int used = 0;
	int i;

	raw_len = fetch_setting_len ( settings, setting );
	if ( raw_len < 0 )
		return raw_len;

	{
		uint8_t raw[raw_len];

		check_len = fetch_setting ( settings, setting, raw,
					    sizeof ( raw ) );
		if ( check_len < 0 )
			return check_len;
		assert ( check_len == raw_len );
		
		if ( len )
			buf[0] = 0; /* Ensure that a terminating NUL exists */
		for ( i = 0 ; i < raw_len ; i++ ) {
			used += ssnprintf ( ( buf + used ), ( len - used ),
					    "%s%02x", ( used ? delimiter : "" ),
					    raw[i] );
		}
		return used;
	}
}

/**
 * Fetch and format value of hex string setting (using colon delimiter)
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int fetchf_hex_colon ( struct settings *settings,
			      struct setting *setting,
			      char *buf, size_t len ) {
	return fetchf_hex ( settings, setting, buf, len, ":" );
}

/**
 * Fetch and format value of hex string setting (using hyphen delimiter)
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int fetchf_hex_hyphen ( struct settings *settings,
			       struct setting *setting,
			       char *buf, size_t len ) {
	return fetchf_hex ( settings, setting, buf, len, "-" );
}

/** A hex-string setting (colon-delimited) */
struct setting_type setting_type_hex __setting_type = {
	.name = "hex",
	.storef = storef_hex,
	.fetchf = fetchf_hex_colon,
};

/** A hex-string setting (hyphen-delimited) */
struct setting_type setting_type_hexhyp __setting_type = {
	.name = "hexhyp",
	.storef = storef_hex,
	.fetchf = fetchf_hex_hyphen,
};

/**
 * Parse and store value of UUID setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v value		Formatted setting data
 * @ret rc		Return status code
 */
static int storef_uuid ( struct settings *settings __unused,
			 struct setting *setting __unused,
			 const char *value __unused ) {
	return -ENOTSUP;
}

/**
 * Fetch and format value of UUID setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int fetchf_uuid ( struct settings *settings, struct setting *setting,
			 char *buf, size_t len ) {
	union uuid uuid;
	int raw_len;

	if ( ( raw_len = fetch_uuid_setting ( settings, setting, &uuid ) ) < 0)
		return raw_len;
	return snprintf ( buf, len, "%s", uuid_ntoa ( &uuid ) );
}

/** UUID setting type */
struct setting_type setting_type_uuid __setting_type = {
	.name = "uuid",
	.storef = storef_uuid,
	.fetchf = fetchf_uuid,
};

/******************************************************************************
 *
 * Setting expansion
 *
 ******************************************************************************
 */

/**
 * Expand variables within string
 *
 * @v string		String
 * @ret expstr		Expanded string
 *
 * The expanded string is allocated with malloc() and the caller must
 * eventually free() it.
 */
char * expand_settings ( const char *string ) {
	char *expstr;
	char *start;
	char *end;
	char *head;
	char *name;
	char *tail;
	int setting_len;
	int new_len;
	char *tmp;

	/* Obtain temporary modifiable copy of string */
	expstr = strdup ( string );
	if ( ! expstr )
		return NULL;

	/* Expand while expansions remain */
	while ( 1 ) {

		head = expstr;

		/* Locate setting to be expanded */
		start = NULL;
		end = NULL;
		for ( tmp = expstr ; *tmp ; tmp++ ) {
			if ( ( tmp[0] == '$' ) && ( tmp[1] == '{' ) )
				start = tmp;
			if ( start && ( tmp[0] == '}' ) ) {
				end = tmp;
				break;
			}
		}
		if ( ! end )
			break;
		*start = '\0';
		name = ( start + 2 );
		*end = '\0';
		tail = ( end + 1 );

		/* Determine setting length */
		setting_len = fetchf_named_setting ( name, NULL, 0, NULL, 0 );
		if ( setting_len < 0 )
			setting_len = 0; /* Treat error as empty setting */

		/* Read setting into temporary buffer */
		{
			char setting_buf[ setting_len + 1 ];

			setting_buf[0] = '\0';
			fetchf_named_setting ( name, NULL, 0, setting_buf,
					       sizeof ( setting_buf ) );

			/* Construct expanded string and discard old string */
			tmp = expstr;
			new_len = asprintf ( &expstr, "%s%s%s",
					     head, setting_buf, tail );
			free ( tmp );
			if ( new_len < 0 )
				return NULL;
		}
	}

	return expstr;
}

/******************************************************************************
 *
 * Settings
 *
 ******************************************************************************
 */

/** Hostname setting */
struct setting hostname_setting __setting ( SETTING_HOST ) = {
	.name = "hostname",
	.description = "Host name",
	.tag = DHCP_HOST_NAME,
	.type = &setting_type_string,
};

/** Filename setting */
struct setting filename_setting __setting ( SETTING_BOOT ) = {
	.name = "filename",
	.description = "Boot filename",
	.tag = DHCP_BOOTFILE_NAME,
	.type = &setting_type_string,
};

/** Root path setting */
struct setting root_path_setting __setting ( SETTING_SANBOOT ) = {
	.name = "root-path",
	.description = "SAN root path",
	.tag = DHCP_ROOT_PATH,
	.type = &setting_type_string,
};

/** Username setting */
struct setting username_setting __setting ( SETTING_AUTH ) = {
	.name = "username",
	.description = "User name",
	.tag = DHCP_EB_USERNAME,
	.type = &setting_type_string,
};

/** Password setting */
struct setting password_setting __setting ( SETTING_AUTH ) = {
	.name = "password",
	.description = "Password",
	.tag = DHCP_EB_PASSWORD,
	.type = &setting_type_string,
};

/** Priority setting */
struct setting priority_setting __setting ( SETTING_MISC ) = {
	.name = "priority",
	.description = "Settings priority",
	.tag = DHCP_EB_PRIORITY,
	.type = &setting_type_int8,
};
