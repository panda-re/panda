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

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * Uniform Resource Identifiers
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <ctype.h>
#include <ipxe/vsprintf.h>
#include <ipxe/uri.h>

/**
 * Dump URI for debugging
 *
 * @v uri		URI
 */
static void dump_uri ( struct uri *uri ) {
	if ( ! uri )
		return;
	if ( uri->scheme )
		DBG ( " scheme \"%s\"", uri->scheme );
	if ( uri->opaque )
		DBG ( " opaque \"%s\"", uri->opaque );
	if ( uri->user )
		DBG ( " user \"%s\"", uri->user );
	if ( uri->password )
		DBG ( " password \"%s\"", uri->password );
	if ( uri->host )
		DBG ( " host \"%s\"", uri->host );
	if ( uri->port )
		DBG ( " port \"%s\"", uri->port );
	if ( uri->path )
		DBG ( " path \"%s\"", uri->path );
	if ( uri->query )
		DBG ( " query \"%s\"", uri->query );
	if ( uri->fragment )
		DBG ( " fragment \"%s\"", uri->fragment );
}

/**
 * Parse URI
 *
 * @v uri_string	URI as a string
 * @ret uri		URI
 *
 * Splits a URI into its component parts.  The return URI structure is
 * dynamically allocated and must eventually be freed by calling
 * uri_put().
 */
struct uri * parse_uri ( const char *uri_string ) {
	struct uri *uri;
	char *raw;
	char *tmp;
	char *path;
	char *authority;
	int i;
	size_t raw_len;

	/* Allocate space for URI struct and a copy of the string */
	raw_len = ( strlen ( uri_string ) + 1 /* NUL */ );
	uri = zalloc ( sizeof ( *uri ) + raw_len );
	if ( ! uri )
		return NULL;
	raw = ( ( ( char * ) uri ) + sizeof ( *uri ) );

	/* Copy in the raw string */
	memcpy ( raw, uri_string, raw_len );

	/* Start by chopping off the fragment, if it exists */
	if ( ( tmp = strchr ( raw, '#' ) ) ) {
		*(tmp++) = '\0';
		uri->fragment = tmp;
	}

	/* Identify absolute/relative URI.  We ignore schemes that are
	 * apparently only a single character long, since otherwise we
	 * misinterpret a DOS-style path name ("C:\path\to\file") as a
	 * URI with scheme="C",opaque="\path\to\file".
	 */
	if ( ( tmp = strchr ( raw, ':' ) ) && ( tmp > ( raw + 1 ) ) ) {
		/* Absolute URI: identify hierarchical/opaque */
		uri->scheme = raw;
		*(tmp++) = '\0';
		if ( *tmp == '/' ) {
			/* Absolute URI with hierarchical part */
			path = tmp;
		} else {
			/* Absolute URI with opaque part */
			uri->opaque = tmp;
			path = NULL;
		}
	} else {
		/* Relative URI */
		path = raw;
	}

	/* If we don't have a path (i.e. we have an absolute URI with
	 * an opaque portion, we're already finished processing
	 */
	if ( ! path )
		goto done;

	/* Chop off the query, if it exists */
	if ( ( tmp = strchr ( path, '?' ) ) ) {
		*(tmp++) = '\0';
		uri->query = tmp;
	}

	/* Identify net/absolute/relative path */
	if ( strncmp ( path, "//", 2 ) == 0 ) {
		/* Net path.  If this is terminated by the first '/'
		 * of an absolute path, then we have no space for a
		 * terminator after the authority field, so shuffle
		 * the authority down by one byte, overwriting one of
		 * the two slashes.
		 */
		authority = ( path + 2 );
		if ( ( tmp = strchr ( authority, '/' ) ) ) {
			/* Shuffle down */
			uri->path = tmp;
			memmove ( ( authority - 1 ), authority,
				  ( tmp - authority ) );
			authority--;
			*(--tmp) = '\0';
		}
	} else {
		/* Absolute/relative path */
		uri->path = path;
		authority = NULL;
	}

	/* If we don't have an authority (i.e. we have a non-net
	 * path), we're already finished processing
	 */
	if ( ! authority )
		goto done;

	/* Split authority into user[:password] and host[:port] portions */
	if ( ( tmp = strchr ( authority, '@' ) ) ) {
		/* Has user[:password] */
		*(tmp++) = '\0';
		uri->host = tmp;
		uri->user = authority;
		if ( ( tmp = strchr ( authority, ':' ) ) ) {
			/* Has password */
			*(tmp++) = '\0';
			uri->password = tmp;
		}
	} else {
		/* No user:password */
		uri->host = authority;
	}

	/* Split host into host[:port] */
	if ( ( tmp = strchr ( uri->host, ':' ) ) ) {
		*(tmp++) = '\0';
		uri->port = tmp;
	}

	/* Decode fields that should be decoded */
	for ( i = URI_FIRST_FIELD; i <= URI_LAST_FIELD; i++ ) {
		const char *field = uri_get_field ( uri, i );
		if ( field && ( URI_ENCODED & ( 1 << i ) ) )
			uri_decode ( field, ( char * ) field,
				     strlen ( field ) + 1 /* NUL */ );
	}

 done:
	DBG ( "URI \"%s\" split into", uri_string );
	dump_uri ( uri );
	DBG ( "\n" );

	return uri;
}

/**
 * Get port from URI
 *
 * @v uri		URI, or NULL
 * @v default_port	Default port to use if none specified in URI
 * @ret port		Port
 */
unsigned int uri_port ( struct uri *uri, unsigned int default_port ) {
	if ( ( ! uri ) || ( ! uri->port ) )
		return default_port;
	return ( strtoul ( uri->port, NULL, 0 ) );
}

/**
 * Unparse URI
 *
 * @v buf		Buffer to fill with URI string
 * @v size		Size of buffer
 * @v uri		URI to write into buffer, or NULL
 * @v fields		Bitmask of fields to include in URI string, or URI_ALL
 * @ret len		Length of URI string
 */
int unparse_uri ( char *buf, size_t size, struct uri *uri,
		  unsigned int fields ) {
	/* List of characters that typically go before certain fields */
	static char separators[] = { /* scheme */ 0, /* opaque */ ':',
				     /* user */ 0, /* password */ ':',
				     /* host */ '@', /* port */ ':',
				     /* path */ 0, /* query */ '?',
				     /* fragment */ '#' };
	int used = 0;
	int i;

	DBG ( "URI unparsing" );
	dump_uri ( uri );
	DBG ( "\n" );

	/* Ensure buffer is NUL-terminated */
	if ( size )
		buf[0] = '\0';

	/* Special-case NULL URI */
	if ( ! uri )
		return 0;

	/* Iterate through requested fields */
	for ( i = URI_FIRST_FIELD; i <= URI_LAST_FIELD; i++ ) {
		const char *field = uri_get_field ( uri, i );
		char sep = separators[i];

		/* Ensure `fields' only contains bits for fields that exist */
		if ( ! field )
			fields &= ~( 1 << i );

		/* Store this field if we were asked to */
		if ( fields & ( 1 << i ) ) {
			/* Print :// if we're non-opaque and had a scheme */
			if ( ( fields & URI_SCHEME_BIT ) &&
			     ( i > URI_OPAQUE ) ) {
				used += ssnprintf ( buf + used, size - used,
						    "://" );
				/* Only print :// once */
				fields &= ~URI_SCHEME_BIT;
			}

			/* Only print separator if an earlier field exists */
			if ( sep && ( fields & ( ( 1 << i ) - 1 ) ) )
				used += ssnprintf ( buf + used, size - used,
						    "%c", sep );

			/* Print contents of field, possibly encoded */
			if ( URI_ENCODED & ( 1 << i ) )
				used += uri_encode ( field, buf + used,
						     size - used, i );
			else
				used += ssnprintf ( buf + used, size - used,
						    "%s", field );
		}
	}

	return used;
}

/**
 * Duplicate URI
 *
 * @v uri		URI
 * @ret uri		Duplicate URI
 *
 * Creates a modifiable copy of a URI.
 */
struct uri * uri_dup ( struct uri *uri ) {
	size_t len = ( unparse_uri ( NULL, 0, uri, URI_ALL ) + 1 );
	char buf[len];

	unparse_uri ( buf, len, uri, URI_ALL );
	return parse_uri ( buf );
}

/**
 * Resolve base+relative path
 *
 * @v base_uri		Base path
 * @v relative_uri	Relative path
 * @ret resolved_uri	Resolved path
 *
 * Takes a base path (e.g. "/var/lib/tftpboot/vmlinuz" and a relative
 * path (e.g. "initrd.gz") and produces a new path
 * (e.g. "/var/lib/tftpboot/initrd.gz").  Note that any non-directory
 * portion of the base path will automatically be stripped; this
 * matches the semantics used when resolving the path component of
 * URIs.
 */
char * resolve_path ( const char *base_path,
		      const char *relative_path ) {
	size_t base_len = ( strlen ( base_path ) + 1 );
	char base_path_copy[base_len];
	char *base_tmp = base_path_copy;
	char *resolved;

	/* If relative path is absolute, just re-use it */
	if ( relative_path[0] == '/' )
		return strdup ( relative_path );

	/* Create modifiable copy of path for dirname() */
	memcpy ( base_tmp, base_path, base_len );
	base_tmp = dirname ( base_tmp );

	/* Process "./" and "../" elements */
	while ( *relative_path == '.' ) {
		relative_path++;
		if ( *relative_path == 0 ) {
			/* Do nothing */
		} else if ( *relative_path == '/' ) {
			relative_path++;
		} else if ( *relative_path == '.' ) {
			relative_path++;
			if ( *relative_path == 0 ) {
				base_tmp = dirname ( base_tmp );
			} else if ( *relative_path == '/' ) {
				base_tmp = dirname ( base_tmp );
				relative_path++;
			} else {
				relative_path -= 2;
				break;
			}
		} else {
			relative_path--;
			break;
		}
	}

	/* Create and return new path */
	if ( asprintf ( &resolved, "%s%s%s", base_tmp,
			( ( base_tmp[ strlen ( base_tmp ) - 1 ] == '/' ) ?
			  "" : "/" ), relative_path ) < 0 )
		return NULL;

	return resolved;
}

/**
 * Resolve base+relative URI
 *
 * @v base_uri		Base URI, or NULL
 * @v relative_uri	Relative URI
 * @ret resolved_uri	Resolved URI
 *
 * Takes a base URI (e.g. "http://ipxe.org/kernels/vmlinuz" and a
 * relative URI (e.g. "../initrds/initrd.gz") and produces a new URI
 * (e.g. "http://ipxe.org/initrds/initrd.gz").
 */
struct uri * resolve_uri ( struct uri *base_uri,
			   struct uri *relative_uri ) {
	struct uri tmp_uri;
	char *tmp_path = NULL;
	struct uri *new_uri;

	/* If relative URI is absolute, just re-use it */
	if ( uri_is_absolute ( relative_uri ) || ( ! base_uri ) )
		return uri_get ( relative_uri );

	/* Mangle URI */
	memcpy ( &tmp_uri, base_uri, sizeof ( tmp_uri ) );
	if ( relative_uri->path ) {
		tmp_path = resolve_path ( ( base_uri->path ?
					    base_uri->path : "/" ),
					  relative_uri->path );
		tmp_uri.path = tmp_path;
		tmp_uri.query = relative_uri->query;
		tmp_uri.fragment = relative_uri->fragment;
	} else if ( relative_uri->query ) {
		tmp_uri.query = relative_uri->query;
		tmp_uri.fragment = relative_uri->fragment;
	} else if ( relative_uri->fragment ) {
		tmp_uri.fragment = relative_uri->fragment;
	}

	/* Create demangled URI */
	new_uri = uri_dup ( &tmp_uri );
	free ( tmp_path );
	return new_uri;
}

/**
 * Test for unreserved URI characters
 *
 * @v c			Character to test
 * @v field		Field of URI in which character lies
 * @ret is_unreserved	Character is an unreserved character
 */
static int is_unreserved_uri_char ( int c, int field ) {
	/* According to RFC3986, the unreserved character set is
	 *
	 * A-Z a-z 0-9 - _ . ~
	 *
	 * but we also pass & ; = in queries, / in paths,
	 * and everything in opaques
	 */
	int ok = ( isupper ( c ) || islower ( c ) || isdigit ( c ) ||
		    ( c == '-' ) || ( c == '_' ) ||
		    ( c == '.' ) || ( c == '~' ) );

	if ( field == URI_QUERY )
		ok = ok || ( c == ';' ) || ( c == '&' ) || ( c == '=' );

	if ( field == URI_PATH )
		ok = ok || ( c == '/' );

	if ( field == URI_OPAQUE )
		ok = 1;

	return ok;
}

/**
 * URI-encode string
 *
 * @v raw_string	String to be URI-encoded
 * @v buf		Buffer to contain encoded string
 * @v len		Length of buffer
 * @v field		Field of URI in which string lies
 * @ret len		Length of encoded string (excluding NUL)
 */
size_t uri_encode ( const char *raw_string, char *buf, ssize_t len,
		    int field ) {
	ssize_t remaining = len;
	size_t used;
	unsigned char c;

	if ( len > 0 )
		buf[0] = '\0';

	while ( ( c = *(raw_string++) ) ) {
		if ( is_unreserved_uri_char ( c, field ) ) {
			used = ssnprintf ( buf, remaining, "%c", c );
		} else {
			used = ssnprintf ( buf, remaining, "%%%02X", c );
		}
		buf += used;
		remaining -= used;
	}

	return ( len - remaining );
}

/**
 * Decode URI-encoded string
 *
 * @v encoded_string	URI-encoded string
 * @v buf		Buffer to contain decoded string
 * @v len		Length of buffer
 * @ret len		Length of decoded string (excluding NUL)
 *
 * This function may be used in-place, with @a buf the same as
 * @a encoded_string.
 */
size_t uri_decode ( const char *encoded_string, char *buf, ssize_t len ) {
	ssize_t remaining;
	char hexbuf[3];
	char *hexbuf_end;
	unsigned char c;

	for ( remaining = len; *encoded_string; remaining-- ) {
		if ( *encoded_string == '%' ) {
			encoded_string++;
			snprintf ( hexbuf, sizeof ( hexbuf ), "%s",
				   encoded_string );
			c = strtoul ( hexbuf, &hexbuf_end, 16 );
			encoded_string += ( hexbuf_end - hexbuf );
		} else {
			c = *(encoded_string++);
		}
		if ( remaining > 1 )
			*buf++ = c;
	}

	if ( len )
		*buf = 0;

	return ( len - remaining );
}
