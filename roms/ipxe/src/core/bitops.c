#include <strings.h>

FILE_LICENCE ( GPL2_OR_LATER );

int __flsl ( long x ) {
	unsigned long value = x;
	int ls = 0;

	for ( ls = 0 ; value ; ls++ ) {
		value >>= 1;
	}
	return ls;
}
