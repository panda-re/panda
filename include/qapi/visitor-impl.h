/*
 * Core Definitions for QAPI Visitor implementations
 *
 * Copyright (C) 2012-2016 Red Hat, Inc.
 *
 * Author: Paolo Bonizni <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */
#ifndef QAPI_VISITOR_IMPL_H
#define QAPI_VISITOR_IMPL_H

#include "qapi/visitor.h"

/*
 * This file describes the callback interface for implementing a QAPI
 * visitor.  For the client interface, see visitor.h.  When
 * implementing the callbacks, it is easiest to declare a struct with
 * 'Visitor visitor;' as the first member.  A callback's contract
 * matches the corresponding public functions' contract unless stated
 * otherwise.  In the comments below, some callbacks are marked "must
 * be set for $TYPE visits to work"; if a visitor implementation omits
 * that callback, it should also document that it is only useful for a
 * subset of QAPI.
 */

/*
 * There are four classes of visitors; setting the class determines
 * how QAPI enums are visited, as well as what additional restrictions
 * can be asserted.  The values are intentionally chosen so as to
 * permit some assertions based on whether a given bit is set (that
 * is, some assertions apply to input and clone visitors, some
 * assertions apply to output and clone visitors).
 */
typedef enum VisitorType {
    VISITOR_INPUT = 1,
    VISITOR_OUTPUT = 2,
    VISITOR_CLONE = 3,
    VISITOR_DEALLOC = 4,
} VisitorType;

struct Visitor
{
    /* Must be set to visit structs */
    void (*start_struct)(Visitor *v, const char *name, void **obj,
                         size_t size, Error **errp);

    /* Optional; intended for input visitors */
    void (*check_struct)(Visitor *v, Error **errp);

    /* Must be set to visit structs */
    void (*end_struct)(Visitor *v, void **obj);

    /* Must be set; implementations may require @list to be non-null,
     * but must document it. */
    void (*start_list)(Visitor *v, const char *name, GenericList **list,
                       size_t size, Error **errp);

    /* Must be set */
    GenericList *(*next_list)(Visitor *v, GenericList *tail, size_t size);

    /* Optional; intended for input visitors */
    void (*check_list)(Visitor *v, Error **errp);

    /* Must be set */
    void (*end_list)(Visitor *v, void **list);

    /* Must be set by input and dealloc visitors to visit alternates;
     * optional for output visitors. */
    void (*start_alternate)(Visitor *v, const char *name,
                            GenericAlternate **obj, size_t size,
                            bool promote_int, Error **errp);

    /* Optional, needed for dealloc visitor */
    void (*end_alternate)(Visitor *v, void **obj);

    /* Must be set */
    void (*type_int64)(Visitor *v, const char *name, int64_t *obj,
                       Error **errp);

    /* Must be set */
    void (*type_uint64)(Visitor *v, const char *name, uint64_t *obj,
                        Error **errp);

    /* Optional; fallback is type_uint64() */
    void (*type_size)(Visitor *v, const char *name, uint64_t *obj,
                      Error **errp);

    /* Must be set */
    void (*type_bool)(Visitor *v, const char *name, bool *obj, Error **errp);

    /* Must be set */
    void (*type_str)(Visitor *v, const char *name, char **obj, Error **errp);

    /* Must be set to visit numbers */
    void (*type_number)(Visitor *v, const char *name, double *obj,
                        Error **errp);

    /* Must be set to visit arbitrary QTypes */
    void (*type_any)(Visitor *v, const char *name, QObject **obj,
                     Error **errp);

    /* Must be set to visit explicit null values.  */
    void (*type_null)(Visitor *v, const char *name, Error **errp);

    /* Must be set for input visitors to visit structs, optional otherwise.
       The core takes care of the return type in the public interface. */
    void (*optional)(Visitor *v, const char *name, bool *present);

    /* Must be set */
    VisitorType type;

    /* Must be set for output visitors, optional otherwise. */
    void (*complete)(Visitor *v, void *opaque);

    /* Must be set */
    void (*free)(Visitor *v);
};

#endif
