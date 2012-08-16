#include <errno.h>

/** @file
 *
 * Error codes
 *
 * This file provides the global variable #errno.
 *
 */

/**
 * Global "last error" number.
 *
 * This is valid only when a function has just returned indicating a
 * failure.
 *
 */
int errno;
