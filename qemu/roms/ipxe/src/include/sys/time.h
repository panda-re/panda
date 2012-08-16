#ifndef _SYS_TIME_H
#define _SYS_TIME_H

#include <time.h>

typedef unsigned long suseconds_t;

struct timeval {
	time_t tv_sec;		/* seconds */
	suseconds_t tv_usec;	/* microseconds */
};

struct timezone {
	int tz_minuteswest;	/* minutes W of Greenwich */
	int tz_dsttime;		/* type of dst correction */
};

extern int gettimeofday ( struct timeval *tv, struct timezone *tz );

#endif /* _SYS_TIME_H */
