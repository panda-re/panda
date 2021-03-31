#ifndef __PANDA_CONCOLIC_H
#define __PANDA_CONCOLIC_H

#define CONC_LVL_DEBUG 0
#define CONC_LVL_INFO 1
#define CONC_LVL_OFF 2

#ifndef CONC_LVL
#define CONC_LVL CONC_LVL_OFF
#endif

#if CONC_LVL <= CONC_LVL_DEBUG
#define CDEBUG(statement) do { statement; } while(0)
#else
#define CDEBUG(statement) do {} while(0)
#endif

#if CONC_LVL <= CONC_LVL_INFO
#define CINFO(statement) do { statement; } while(0)
#else
#define CINFO(statement) do {} while(0)
#endif

#endif

