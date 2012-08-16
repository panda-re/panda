#ifndef _TIME_H
#define _TIME_H

typedef unsigned long time_t;

struct tm {
	int tm_sec;	/* seconds */
	int tm_min;	/* minutes */
	int tm_hour;	/* hours */
	int tm_mday;	/* day of the month */
	int tm_mon;	/* month */
	int tm_year;	/* year */
	int tm_wday;	/* day of the week */
	int tm_yday;	/* day in the year */
	int tm_isdst;	/* daylight saving time */
};

extern time_t time ( time_t *t );

extern time_t mktime ( struct tm *tm );

#endif /* _TIME_H */
