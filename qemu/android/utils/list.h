/* Copyright (C) 2011 The Android Open Source Project
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
#ifndef _ANDROID_UTILS_LIST_H
#define _ANDROID_UTILS_LIST_H

#include <inttypes.h>

/* Encapsulates a double-linked, circular list.
 * The list is organized in the following way:
 * - List entries contain references to the next, and the previous entry in the
 *   list.
 * - The list is circular, i.e. the "last" list entry references the "list head"
 *   in its 'next' reference, and the "list head" references the "last" entry in
 *   its 'previous' reference.
 * - The list is empty if its 'next' and 'previous' references are addressing the
 *   head of the list.
 */
typedef struct ACList ACList;
struct ACList {
    /* Next entry in the list */
    ACList*  next;
    /* Previous entry in the list */
    ACList*  prev;
};

/* Initializes the list. */
AINLINED void
alist_init(ACList* list)
{
    list->next = list->prev = list;
}

/* Checks if the list is empty. */
AINLINED int
alist_is_empty(const ACList* list)
{
    return list->next == list;
}

/* Inserts an entry to the head of the list */
AINLINED void
alist_insert_head(ACList* list, ACList* entry)
{
    ACList* const next = list->next;
    entry->next = next;
    entry->prev = list;
    next->prev = entry;
    list->next = entry;
}
/* Inserts an entry to the tail of the list */
AINLINED void
alist_insert_tail(ACList* list, ACList* entry)
{
    ACList* const prev = list->prev;
    entry->next = list;
    entry->prev = prev;
    prev->next = entry;
    list->prev = entry;
}

/* Removes an entry from the list. NOTE: Entry must be in the list when this
 * routine is called. */
AINLINED void
alist_remove(ACList* entry)
{
    ACList* const next = entry->next;
    ACList* const prev = entry->prev;
    prev->next = next;
    next->prev = prev;
    entry->next = entry->prev = entry;
}

/* Returns an entry removed from the head of the list. If the list was empty,
 * this routine returns NULL. */
AINLINED ACList*
alist_remove_head(ACList* list)
{
    ACList* entry = NULL;
    if (!alist_is_empty(list)) {
        entry = list->next;
        list->next = entry->next;
        entry->next->prev = list;
        entry->next = entry->prev = entry;
    }
    return entry;
}

/* Returns an entry removed from the tail of the list. If the list was empty,
 * this routine returns NULL. */
AINLINED ACList*
alist_remove_tail(ACList* list)
{
    ACList* entry = NULL;
    if (!alist_is_empty(list)) {
        entry = list->prev;
        list->prev = entry->prev;
        entry->prev->next = list;
        entry->next = entry->prev = entry;
    }
    return entry;
}

#endif  /* _ANDROID_UTILS_LIST_H */
