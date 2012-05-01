/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>

#define eprintf(...) fprintf ( stderr, __VA_ARGS__ )

/** Command-line options */
struct options {
};

/** Error usage information */
struct einfo {
	uint32_t size;
	uint32_t error;
	uint32_t desc;
	uint32_t file;
	uint32_t line;
} __attribute__ (( packed ));

/**
 * Process einfo file
 *
 * @v infile		Filename
 * @v opts		Command-line options
 */
static void einfo ( const char *infile, struct options *opts ) {
	int fd;
	struct stat stat;
	size_t len;
	void *start;
	struct einfo *einfo;

	/* Open einfo file */
	if ( ( fd = open ( infile, O_RDONLY ) ) < 0 ) {
		eprintf ( "Cannot open \"%s\": %s\n",
			  infile, strerror ( errno ) );
		exit ( 1 );
	}

	/* Get file size */
	if ( fstat ( fd, &stat ) < 0 ) {
		eprintf ( "Cannot stat \"%s\": %s\n",
			  infile, strerror ( errno ) );
		exit ( 1 );
	}
	len = stat.st_size;

	if ( len ) {

		/* Map file */
		if ( ( start = mmap ( NULL, len, PROT_READ, MAP_SHARED,
				      fd, 0 ) ) == MAP_FAILED ) {
			eprintf ( "Cannot mmap \"%s\": %s\n",
				  infile, strerror ( errno ) );
			exit ( 1 );
		}

		/* Iterate over einfo records */
		for ( einfo = start ; ( ( void * ) einfo ) < ( start + len ) ;
		      einfo = ( ( ( void * ) einfo ) + einfo->size ) ) {
			printf ( "%08x\t%s\t%d\t%s\n", einfo->error,
				 ( ( ( void * ) einfo ) + einfo->file ),
				 einfo->line,
				 ( ( ( void * ) einfo ) + einfo->desc ) );
		}

	}

	/* Unmap and close file */
	munmap ( start, len );
	close ( fd );
}

/**
 * Print help
 *
 * @v program_name	Program name
 */
static void print_help ( const char *program_name ) {
	eprintf ( "Syntax: %s file1.einfo [file2.einfo...]\n",
		  program_name );
}

/**
 * Parse command-line options
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v opts		Options structure to populate
 */
static int parse_options ( const int argc, char **argv,
			   struct options *opts ) {
	char *end;
	int c;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{ "help", 0, NULL, 'h' },
			{ 0, 0, 0, 0 }
		};

		if ( ( c = getopt_long ( argc, argv, "s:h",
					 long_options,
					 &option_index ) ) == -1 ) {
			break;
		}

		switch ( c ) {
		case 'h':
			print_help ( argv[0] );
			exit ( 0 );
		case '?':
		default:
			exit ( 2 );
		}
	}
	return optind;
}

int main ( int argc, char **argv ) {
	struct options opts = {
	};
	unsigned int infile_index;
	const char *infile;

	/* Parse command-line arguments */
	infile_index = parse_options ( argc, argv, &opts );
	if ( argc <= infile_index ) {
		print_help ( argv[0] );
		exit ( 2 );
	}

	/* Process each einfo file */
	for ( ; infile_index < argc ; infile_index++ ) {
		infile = argv[infile_index];
		einfo ( infile, &opts );
	}

	return 0;
}
