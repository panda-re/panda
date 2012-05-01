#ifndef _IPXE_PARSEOPT_H
#define _IPXE_PARSEOPT_H

/** @file
 *
 * Command line option parsing
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stddef.h>

struct net_device;
struct image;

/** A command-line option descriptor */
struct option_descriptor {
	/** Long option name, if any */
	const char *longopt;
	/** Short option name */
	char shortopt;
	/** Argument requirement (as for @c struct @c option) */
	uint8_t has_arg;
	/** Offset of field within options structure */
	uint16_t offset;
	/** Parse option
	 *
	 * @v text		Option text
	 * @v value		Option value to fill in
	 * @ret rc		Return status code
	 */
	int ( * parse ) ( const char *text, void *value );
};

/**
 * Construct option parser
 *
 * @v _struct		Options structure type
 * @v _field		Field within options structure
 * @v _parse		Field type-specific option parser
 * @ret _parse		Generic option parser
 */
#define OPTION_PARSER( _struct, _field, _parse )			      \
	( ( int ( * ) ( const char *text, void *value ) )		      \
	  ( ( ( ( typeof ( _parse ) * ) NULL ) ==			      \
	      ( ( int ( * ) ( const char *text,				      \
			      typeof ( ( ( _struct * ) NULL )->_field ) * ) ) \
		NULL ) ) ? _parse : _parse ) )

/**
 * Construct option descriptor
 *
 * @v _longopt		Long option name, if any
 * @v _shortopt		Short option name, if any
 * @v _has_arg		Argument requirement
 * @v _struct		Options structure type
 * @v _field		Field within options structure
 * @v _parse		Field type-specific option parser
 * @ret _option		Option descriptor
 */
#define OPTION_DESC( _longopt, _shortopt, _has_arg, _struct, _field, _parse ) \
	{								      \
		.longopt = _longopt,					      \
		.shortopt = _shortopt,					      \
		.has_arg = _has_arg,					      \
		.offset = offsetof ( _struct, _field ),			      \
		.parse = OPTION_PARSER ( _struct, _field, _parse ),	      \
	}

/** A command descriptor */
struct command_descriptor {
	/** Option descriptors */
	struct option_descriptor *options;
	/** Number of option descriptors */
	uint8_t num_options;
	/** Length of option structure */
	uint8_t len;
	/** Minimum number of non-option arguments */
	uint8_t min_args;
	/** Maximum number of non-option arguments */
	uint8_t max_args;
	/** Command usage
	 *
	 * This excludes the literal "Usage:" and the command name,
	 * which will be prepended automatically.
	 */
	const char *usage;
};

/** No maximum number of arguments */
#define MAX_ARGUMENTS 0xff

/**
 * Construct command descriptor
 *
 * @v _struct		Options structure type
 * @v _options		Option descriptor array
 * @v _check_args	Remaining argument checker
 * @v _usage		Command usage
 * @ret _command	Command descriptor
 */
#define COMMAND_DESC( _struct, _options, _min_args, _max_args, _usage )	      \
	{								      \
		.options = ( ( ( ( typeof ( _options[0] ) * ) NULL ) ==	      \
			       ( ( struct option_descriptor * ) NULL ) ) ?    \
			     _options : _options ),			      \
		.num_options = ( sizeof ( _options ) /			      \
				 sizeof ( _options[0] ) ),		      \
		.len = sizeof ( _struct ),				      \
		.min_args = _min_args,					      \
		.max_args = _max_args,					      \
		.usage = _usage,					      \
	 }

extern int parse_string ( const char *text, const char **value );
extern int parse_integer ( const char *text, unsigned int *value );
extern int parse_netdev ( const char *text, struct net_device **netdev );
extern int parse_image ( const char *text, struct image **image );
extern int parse_flag ( const char *text __unused, int *flag );
extern void print_usage ( struct command_descriptor *cmd, char **argv );
extern int parse_options ( int argc, char **argv,
			   struct command_descriptor *cmd, void *opts );

#endif /* _IPXE_PARSEOPT_H */
