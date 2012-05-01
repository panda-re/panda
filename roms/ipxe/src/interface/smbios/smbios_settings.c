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
#include <string.h>
#include <errno.h>
#include <ipxe/settings.h>
#include <ipxe/init.h>
#include <ipxe/uuid.h>
#include <ipxe/smbios.h>

/** SMBIOS settings tag magic number */
#define SMBIOS_TAG_MAGIC 0x5B /* "SmBios" */

/**
 * Construct SMBIOS empty tag
 *
 * @ret tag		SMBIOS setting tag
 */
#define SMBIOS_EMPTY_TAG ( SMBIOS_TAG_MAGIC << 24 )

/**
 * Construct SMBIOS raw-data tag
 *
 * @v _type		SMBIOS structure type number
 * @v _structure	SMBIOS structure data type
 * @v _field		Field within SMBIOS structure data type
 * @ret tag		SMBIOS setting tag
 */
#define SMBIOS_RAW_TAG( _type, _structure, _field )		\
	( ( SMBIOS_TAG_MAGIC << 24 ) |				\
	  ( (_type) << 16 ) |					\
	  ( offsetof ( _structure, _field ) << 8 ) |		\
	  ( sizeof ( ( ( _structure * ) 0 )->_field ) ) )

/**
 * Construct SMBIOS string tag
 *
 * @v _type		SMBIOS structure type number
 * @v _structure	SMBIOS structure data type
 * @v _field		Field within SMBIOS structure data type
 * @ret tag		SMBIOS setting tag
 */
#define SMBIOS_STRING_TAG( _type, _structure, _field )		\
	( ( SMBIOS_TAG_MAGIC << 24 ) |				\
	  ( (_type) << 16 ) |					\
	  ( offsetof ( _structure, _field ) << 8 ) )

/**
 * Check applicability of SMBIOS setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
static int smbios_applies ( struct settings *settings __unused,
			    struct setting *setting ) {
	unsigned int tag_magic;

	/* Check tag magic */
	tag_magic = ( setting->tag >> 24 );
	return ( tag_magic == SMBIOS_TAG_MAGIC );
}

/**
 * Fetch value of SMBIOS setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int smbios_fetch ( struct settings *settings __unused,
			  struct setting *setting,
			  void *data, size_t len ) {
	struct smbios_structure structure;
	unsigned int tag_magic;
	unsigned int tag_type;
	unsigned int tag_offset;
	unsigned int tag_len;
	int rc;

	/* Split tag into type, offset and length */
	tag_magic = ( setting->tag >> 24 );
	tag_type = ( ( setting->tag >> 16 ) & 0xff );
	tag_offset = ( ( setting->tag >> 8 ) & 0xff );
	tag_len = ( setting->tag & 0xff );
	assert ( tag_magic == SMBIOS_TAG_MAGIC );

	/* Find SMBIOS structure */
	if ( ( rc = find_smbios_structure ( tag_type, &structure ) ) != 0 )
		return rc;

	{
		uint8_t buf[structure.header.len];

		/* Read SMBIOS structure */
		if ( ( rc = read_smbios_structure ( &structure, buf,
						    sizeof ( buf ) ) ) != 0 )
			return rc;

		if ( tag_len == 0 ) {
			/* String */
			return read_smbios_string ( &structure,
						    buf[tag_offset],
						    data, len );
		} else {
			/* Raw data */
			if ( len > tag_len )
				len = tag_len;
			memcpy ( data, &buf[tag_offset], len );
			return tag_len;
		}
	}
}

/** SMBIOS settings operations */
static struct settings_operations smbios_settings_operations = {
	.applies = smbios_applies,
	.fetch = smbios_fetch,
};

/** SMBIOS settings */
static struct settings smbios_settings = {
	.refcnt = NULL,
	.tag_magic = SMBIOS_EMPTY_TAG,
	.siblings = LIST_HEAD_INIT ( smbios_settings.siblings ),
	.children = LIST_HEAD_INIT ( smbios_settings.children ),
	.op = &smbios_settings_operations,
};

/** Initialise SMBIOS settings */
static void smbios_init ( void ) {
	int rc;

	if ( ( rc = register_settings ( &smbios_settings, NULL,
					"smbios" ) ) != 0 ) {
		DBG ( "SMBIOS could not register settings: %s\n",
		      strerror ( rc ) );
		return;
	}
}

/** SMBIOS settings initialiser */
struct init_fn smbios_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = smbios_init,
};

/** UUID setting obtained via SMBIOS */
struct setting uuid_setting __setting ( SETTING_HOST ) = {
	.name = "uuid",
	.description = "UUID",
	.tag = SMBIOS_RAW_TAG ( SMBIOS_TYPE_SYSTEM_INFORMATION,
				struct smbios_system_information, uuid ),
	.type = &setting_type_uuid,
};

/** Other SMBIOS named settings */
struct setting smbios_named_settings[] __setting ( SETTING_HOST_EXTRA ) = {
	{
		.name = "manufacturer",
		.description = "Manufacturer",
		.tag = SMBIOS_STRING_TAG ( SMBIOS_TYPE_SYSTEM_INFORMATION,
					   struct smbios_system_information,
					   manufacturer ),
		.type = &setting_type_string,
	},
	{
		.name = "product",
		.description = "Product name",
		.tag = SMBIOS_STRING_TAG ( SMBIOS_TYPE_SYSTEM_INFORMATION,
					   struct smbios_system_information,
					   product ),
		.type = &setting_type_string,
	},
	{
		.name = "serial",
		.description = "Serial number",
		.tag = SMBIOS_STRING_TAG ( SMBIOS_TYPE_SYSTEM_INFORMATION,
					   struct smbios_system_information,
					   serial ),
		.type = &setting_type_string,
	},
	{
		.name = "asset",
		.description = "Asset tag",
		.tag = SMBIOS_STRING_TAG ( SMBIOS_TYPE_ENCLOSURE_INFORMATION,
					   struct smbios_enclosure_information,
					   asset_tag ),
		.type = &setting_type_string,
	},
};
