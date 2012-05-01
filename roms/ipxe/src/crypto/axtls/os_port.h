/**
 * @file os_port.h
 *
 * Trick the axtls code into building within our build environment.
 */

#ifndef HEADER_OS_PORT_H
#define HEADER_OS_PORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <byteswap.h>

#define STDCALL
#define EXP_FUNC
#define TTY_FLUSH()

/** We can't actually abort, since we are effectively a kernel... */
#define abort() assert ( 0 )

/** crypto_misc.c has a bad #ifdef */
static inline void close ( int fd __unused ) {
	/* Do nothing */
}

typedef void FILE;

static inline FILE * fopen ( const char *filename __unused,
			     const char *mode __unused ) {
	return NULL;
}

static inline int fseek ( FILE *stream __unused, long offset __unused,
			  int whence __unused ) {
	return -1;
}

static inline long ftell ( FILE *stream __unused ) {
	return -1;
}

static inline size_t fread ( void *ptr __unused, size_t size __unused,
			     size_t nmemb __unused, FILE *stream __unused ) {
	return -1;
}

static inline int fclose ( FILE *stream __unused ) {
	return -1;
}

#define CONFIG_SSL_CERT_VERIFICATION 1
#define CONFIG_SSL_MAX_CERTS 1
#define CONFIG_X509_MAX_CA_CERTS 1
#define CONFIG_SSL_EXPIRY_TIME 24
#define CONFIG_SSL_ENABLE_CLIENT 1
#define CONFIG_BIGINT_CLASSICAL 1

#endif 
