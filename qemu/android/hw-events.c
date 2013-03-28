/* Copyright (C) 2007-2008 The Android Open Source Project
**
** This software is licensed under the terms of the GNU General Public
** License version 2, as published by the Free Software Foundation, and
** may be copied, distributed, and modified under those terms.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/
#include "android/hw-events.h"
#include "android/utils/bufprint.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char*  name;
    int          value;
} EventInfo;

#define  EV_TYPE(n,v)   { "EV_" STRINGIFY(n), (v) },

#define  BTN_CODE(n,v)  { "BTN_" STRINGIFY(n), (v) },
#define  KEY_CODE(n,v)  { "KEY_" STRINGIFY(n), (v) },
#define  REL_CODE(n,v)  { "REL_" STRINGIFY(n), (v) },
#define  ABS_CODE(n,v)  { "ABS_" STRINGIFY(n), (v) },
#define  END_CODE       { NULL, 0 }

static const EventInfo  _ev_types_tab[] =
{
    EVENT_TYPE_LIST
    END_CODE
};

static const EventInfo _key_codes_list[] =
{
    EVENT_KEY_LIST
    EVENT_BTN_LIST
    END_CODE
};

static const EventInfo _rel_codes_list[] =
{
    EVENT_REL_LIST
    END_CODE
};
static const EventInfo _abs_codes_list[] =
{
    EVENT_ABS_LIST
    END_CODE
};

#undef EV_TYPE
#undef BTN_CODE
#undef KEY_CODE
#undef REL_CODE
#undef ABS_CODE

typedef const EventInfo*  EventList;

typedef struct {
    int               type;
    const EventInfo*  table;
} EventCodeList;


static const EventCodeList  _codes[] = {
    { EV_KEY, _key_codes_list },
    { EV_REL, _rel_codes_list },
    { EV_ABS, _abs_codes_list },
    { -1, NULL }
};

static EventList
eventList_findByType( int  type )
{
    int  nn;

    for (nn = 0; _codes[nn].type >= 0; nn++) {
        if (_codes[nn].type == type)
            return _codes[nn].table;
    }
    return NULL;
}

static int
eventList_getCount( EventList  list )
{
    int  nn;

    if (list == NULL)
        return 0;

    for (nn = 0; list[nn].name != NULL; nn++) {
        /* nothing */
    }
    return nn;
}

static int
eventList_findCodeByName( EventList    list,
                          const char*  name,
                          int          namelen )
{
    if (namelen <= 0)
        return -1;

    for ( ; list->name != NULL; list += 1 ) {
        if ( !memcmp(name, list->name, namelen) &&
             list->name[namelen] == 0 )
        {
            return list->value;
        }
    }
    return -1;
}

static char*
eventList_bufprintCode( EventList  list,
                        int        index,
                        char*      buf,
                        char*      bufend )
{
    if (list == NULL)
        return buf;

    return bufprint(buf, bufend, "%s", list[index].name);
}


int
android_event_from_str( const char*  name,
                        int         *ptype,
                        int         *pcode,
                        int         *pvalue )
{
    const char*  p;
    const char*  pend;
    const char*  q;
    EventList    list;
    char*        end;

    *ptype  = 0;
    *pcode  = 0;
    *pvalue = 0;

    p    = name;
    pend = p + strcspn(p, " \t");
    q    = strchr(p, ':');
    if (q == NULL || q > pend)
        q = pend;

    *ptype = eventList_findCodeByName( _ev_types_tab, p, q-p );
    if (*ptype < 0) {
        *ptype = (int) strtol( p, &end, 0 );
        if (end != q)
            return -1;
    }

    if (*q != ':')
        return 0;

    p = q + 1;
    q = strchr(p, ':');
    if (q == NULL || q > pend)
        q = pend;

    list   = eventList_findByType( *ptype );
    if (list == NULL) {
        *pcode = -1;
    } else {
        *pcode = eventList_findCodeByName( list, p, q-p );
    }
    if (*pcode < 0) {
        *pcode = (int) strtol( p, &end, 0 );
        if (end != q)
            return -2;
    }

    if (*q != ':')
        return 0;

    p = q + 1;
    q = strchr(p, ':');
    if (q == NULL || q > pend)
        q = pend;

    *pvalue = (int)strtol( p, &end, 0 );
    if (end != q)
        return -3;

    return 0;
}

int
android_event_get_type_count( void )
{
    return eventList_getCount( _ev_types_tab );
}

char*
android_event_bufprint_type_str( char*  buff, char*  end, int  type_index )
{
    return eventList_bufprintCode( _ev_types_tab, type_index, buff, end );
}

/* returns the list of valid event code string aliases for a given event type */
int
android_event_get_code_count( int  type )
{
    EventList  list = eventList_findByType(type);

    return eventList_getCount(list);
}

char*
android_event_bufprint_code_str( char*  buff, char*  end, int  type, int  code_index )
{
    EventList  list = eventList_findByType(type);

    return eventList_bufprintCode(list, code_index, buff, end);
}

