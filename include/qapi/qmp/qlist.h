/*
 * QList Module
 *
 * Copyright (C) 2009 Red Hat Inc.
 *
 * Authors:
 *  Luiz Capitulino <lcapitulino@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#ifndef QLIST_H
#define QLIST_H

#include "qapi/qmp/qobject.h"
#include "qemu/queue.h"

typedef struct QListEntry {
    QObject *value;
    QTAILQ_ENTRY(QListEntry) next;
} QListEntry;

typedef struct QList {
    QObject base;
    QTAILQ_HEAD(,QListEntry) head;
} QList;

#define qlist_append(qlist, obj) \
        qlist_append_obj(qlist, QOBJECT(obj))

/* Helpers for int, bool, and string */
#define qlist_append_int(qlist, value) \
        qlist_append(qlist, qint_from_int(value))
#define qlist_append_bool(qlist, value) \
        qlist_append(qlist, qbool_from_bool(value))
#define qlist_append_str(qlist, value) \
        qlist_append(qlist, qstring_from_str(value))

#define QLIST_FOREACH_ENTRY(qlist, var)             \
        for ((var) = ((qlist)->head.tqh_first);     \
            (var);                                  \
            (var) = ((var)->next.tqe_next))

static inline QObject *qlist_entry_obj(const QListEntry *entry)
{
    return entry->value;
}

QList *qlist_new(void);
QList *qlist_copy(QList *src);
void qlist_append_obj(QList *qlist, QObject *obj);
void qlist_iter(const QList *qlist,
                void (*iter)(QObject *obj, void *opaque), void *opaque);
QObject *qlist_pop(QList *qlist);
QObject *qlist_peek(QList *qlist);
int qlist_empty(const QList *qlist);
size_t qlist_size(const QList *qlist);
QList *qobject_to_qlist(const QObject *obj);
void qlist_destroy_obj(QObject *obj);

static inline const QListEntry *qlist_first(const QList *qlist)
{
    return QTAILQ_FIRST(&qlist->head);
}

static inline const QListEntry *qlist_next(const QListEntry *entry)
{
    return QTAILQ_NEXT(entry, next);
}

#endif /* QLIST_H */
