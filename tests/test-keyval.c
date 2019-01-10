/*
 * Unit tests for parsing of KEY=VALUE,... strings
 *
 * Copyright (C) 2017 Red Hat Inc.
 *
 * Authors:
 *  Markus Armbruster <armbru@redhat.com>,
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qmp/qstring.h"
#include "qapi/qobject-input-visitor.h"
#include "test-qapi-visit.h"
#include "qemu/cutils.h"
#include "qemu/option.h"

static void test_keyval_parse(void)
{
    Error *err = NULL;
    QDict *qdict, *sub_qdict;
    char long_key[129];
    char *params;

    /* Nothing */
    qdict = keyval_parse("", NULL, &error_abort);
    g_assert_cmpuint(qdict_size(qdict), ==, 0);
    QDECREF(qdict);

    /* Empty key (qemu_opts_parse() accepts this) */
    qdict = keyval_parse("=val", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* Empty key fragment */
    qdict = keyval_parse(".", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);
    qdict = keyval_parse("key.", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* Invalid non-empty key (qemu_opts_parse() doesn't care) */
    qdict = keyval_parse("7up=val", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* Overlong key */
    memset(long_key, 'a', 127);
    long_key[127] = 'z';
    long_key[128] = 0;
    params = g_strdup_printf("k.%s=v", long_key);
    qdict = keyval_parse(params + 2, NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* Overlong key fragment */
    qdict = keyval_parse(params, NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);
    g_free(params);

    /* Long key (qemu_opts_parse() accepts and truncates silently) */
    params = g_strdup_printf("k.%s=v", long_key + 1);
    qdict = keyval_parse(params + 2, NULL, &error_abort);
    g_assert_cmpuint(qdict_size(qdict), ==, 1);
    g_assert_cmpstr(qdict_get_try_str(qdict, long_key + 1), ==, "v");
    QDECREF(qdict);

    /* Long key fragment */
    qdict = keyval_parse(params, NULL, &error_abort);
    g_assert_cmpuint(qdict_size(qdict), ==, 1);
    sub_qdict = qdict_get_qdict(qdict, "k");
    g_assert(sub_qdict);
    g_assert_cmpuint(qdict_size(sub_qdict), ==, 1);
    g_assert_cmpstr(qdict_get_try_str(sub_qdict, long_key + 1), ==, "v");
    QDECREF(qdict);
    g_free(params);

    /* Crap after valid key */
    qdict = keyval_parse("key[0]=val", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* Multiple keys, last one wins */
    qdict = keyval_parse("a=1,b=2,,x,a=3", NULL, &error_abort);
    g_assert_cmpuint(qdict_size(qdict), ==, 2);
    g_assert_cmpstr(qdict_get_try_str(qdict, "a"), ==, "3");
    g_assert_cmpstr(qdict_get_try_str(qdict, "b"), ==, "2,x");
    QDECREF(qdict);

    /* Even when it doesn't in qemu_opts_parse() */
    qdict = keyval_parse("id=foo,id=bar", NULL, &error_abort);
    g_assert_cmpuint(qdict_size(qdict), ==, 1);
    g_assert_cmpstr(qdict_get_try_str(qdict, "id"), ==, "bar");
    QDECREF(qdict);

    /* Dotted keys */
    qdict = keyval_parse("a.b.c=1,a.b.c=2,d=3", NULL, &error_abort);
    g_assert_cmpuint(qdict_size(qdict), ==, 2);
    sub_qdict = qdict_get_qdict(qdict, "a");
    g_assert(sub_qdict);
    g_assert_cmpuint(qdict_size(sub_qdict), ==, 1);
    sub_qdict = qdict_get_qdict(sub_qdict, "b");
    g_assert(sub_qdict);
    g_assert_cmpuint(qdict_size(sub_qdict), ==, 1);
    g_assert_cmpstr(qdict_get_try_str(sub_qdict, "c"), ==, "2");
    g_assert_cmpstr(qdict_get_try_str(qdict, "d"), ==, "3");
    QDECREF(qdict);

    /* Inconsistent dotted keys */
    qdict = keyval_parse("a.b=1,a=2", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);
    qdict = keyval_parse("a.b=1,a.b.c=2", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* Trailing comma is ignored */
    qdict = keyval_parse("x=y,", NULL, &error_abort);
    g_assert_cmpuint(qdict_size(qdict), ==, 1);
    g_assert_cmpstr(qdict_get_try_str(qdict, "x"), ==, "y");
    QDECREF(qdict);

    /* Except when it isn't */
    qdict = keyval_parse(",", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* Value containing ,id= not misinterpreted as qemu_opts_parse() does */
    qdict = keyval_parse("x=,,id=bar", NULL, &error_abort);
    g_assert_cmpuint(qdict_size(qdict), ==, 1);
    g_assert_cmpstr(qdict_get_try_str(qdict, "x"), ==, ",id=bar");
    QDECREF(qdict);

    /* Anti-social ID is left to caller (qemu_opts_parse() rejects it) */
    qdict = keyval_parse("id=666", NULL, &error_abort);
    g_assert_cmpuint(qdict_size(qdict), ==, 1);
    g_assert_cmpstr(qdict_get_try_str(qdict, "id"), ==, "666");
    QDECREF(qdict);

    /* Implied value not supported (unlike qemu_opts_parse()) */
    qdict = keyval_parse("an,noaus,noaus=", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* Implied value, key "no" (qemu_opts_parse(): negated empty key) */
    qdict = keyval_parse("no", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* Implied key */
    qdict = keyval_parse("an,aus=off,noaus=", "implied", &error_abort);
    g_assert_cmpuint(qdict_size(qdict), ==, 3);
    g_assert_cmpstr(qdict_get_try_str(qdict, "implied"), ==, "an");
    g_assert_cmpstr(qdict_get_try_str(qdict, "aus"), ==, "off");
    g_assert_cmpstr(qdict_get_try_str(qdict, "noaus"), ==, "");
    QDECREF(qdict);

    /* Implied dotted key */
    qdict = keyval_parse("val", "eins.zwei", &error_abort);
    g_assert_cmpuint(qdict_size(qdict), ==, 1);
    sub_qdict = qdict_get_qdict(qdict, "eins");
    g_assert(sub_qdict);
    g_assert_cmpuint(qdict_size(sub_qdict), ==, 1);
    g_assert_cmpstr(qdict_get_try_str(sub_qdict, "zwei"), ==, "val");
    QDECREF(qdict);

    /* Implied key with empty value (qemu_opts_parse() accepts this) */
    qdict = keyval_parse(",", "implied", &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* Likewise (qemu_opts_parse(): implied key with comma value) */
    qdict = keyval_parse(",,,a=1", "implied", &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* Empty key is not an implied key */
    qdict = keyval_parse("=val", "implied", &err);
    error_free_or_abort(&err);
    g_assert(!qdict);
}

static void check_list012(QList *qlist)
{
    static const char *expected[] = { "null", "eins", "zwei" };
    int i;
    QString *qstr;

    g_assert(qlist);
    for (i = 0; i < ARRAY_SIZE(expected); i++) {
        qstr = qobject_to_qstring(qlist_pop(qlist));
        g_assert(qstr);
        g_assert_cmpstr(qstring_get_str(qstr), ==, expected[i]);
        QDECREF(qstr);
    }
    g_assert(qlist_empty(qlist));
}

static void test_keyval_parse_list(void)
{
    Error *err = NULL;
    QDict *qdict, *sub_qdict;

    /* Root can't be a list */
    qdict = keyval_parse("0=1", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* List elements need not be in order */
    qdict = keyval_parse("list.0=null,list.2=zwei,list.1=eins",
                         NULL, &error_abort);
    g_assert_cmpint(qdict_size(qdict), ==, 1);
    check_list012(qdict_get_qlist(qdict, "list"));
    QDECREF(qdict);

    /* Multiple indexes, last one wins */
    qdict = keyval_parse("list.1=goner,list.0=null,list.01=eins,list.2=zwei",
                         NULL, &error_abort);
    g_assert_cmpint(qdict_size(qdict), ==, 1);
    check_list012(qdict_get_qlist(qdict, "list"));
    QDECREF(qdict);

    /* List at deeper nesting */
    qdict = keyval_parse("a.list.1=eins,a.list.00=null,a.list.2=zwei",
                         NULL, &error_abort);
    g_assert_cmpint(qdict_size(qdict), ==, 1);
    sub_qdict = qdict_get_qdict(qdict, "a");
    g_assert_cmpint(qdict_size(sub_qdict), ==, 1);
    check_list012(qdict_get_qlist(sub_qdict, "list"));
    QDECREF(qdict);

    /* Inconsistent dotted keys: both list and dictionary */
    qdict = keyval_parse("a.b.c=1,a.b.0=2", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);
    qdict = keyval_parse("a.0.c=1,a.b.c=2", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);

    /* Missing list indexes */
    qdict = keyval_parse("list.1=lonely", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);
    qdict = keyval_parse("list.0=null,list.2=eins,list.02=zwei", NULL, &err);
    error_free_or_abort(&err);
    g_assert(!qdict);
}

static void test_keyval_visit_bool(void)
{
    Error *err = NULL;
    Visitor *v;
    QDict *qdict;
    bool b;

    qdict = keyval_parse("bool1=on,bool2=off", NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_bool(v, "bool1", &b, &error_abort);
    g_assert(b);
    visit_type_bool(v, "bool2", &b, &error_abort);
    g_assert(!b);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);

    qdict = keyval_parse("bool1=offer", NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_bool(v, "bool1", &b, &err);
    error_free_or_abort(&err);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void test_keyval_visit_number(void)
{
    Error *err = NULL;
    Visitor *v;
    QDict *qdict;
    uint64_t u;

    /* Lower limit zero */
    qdict = keyval_parse("number1=0", NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_uint64(v, "number1", &u, &error_abort);
    g_assert_cmpuint(u, ==, 0);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);

    /* Upper limit 2^64-1 */
    qdict = keyval_parse("number1=18446744073709551615,number2=-1",
                         NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_uint64(v, "number1", &u, &error_abort);
    g_assert_cmphex(u, ==, UINT64_MAX);
    visit_type_uint64(v, "number2", &u, &error_abort);
    g_assert_cmphex(u, ==, UINT64_MAX);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);

    /* Above upper limit */
    qdict = keyval_parse("number1=18446744073709551616",
                         NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_uint64(v, "number1", &u, &err);
    error_free_or_abort(&err);
    visit_end_struct(v, NULL);
    visit_free(v);

    /* Below lower limit */
    qdict = keyval_parse("number1=-18446744073709551616",
                         NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_uint64(v, "number1", &u, &err);
    error_free_or_abort(&err);
    visit_end_struct(v, NULL);
    visit_free(v);

    /* Hex and octal */
    qdict = keyval_parse("number1=0x2a,number2=052",
                         NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_uint64(v, "number1", &u, &error_abort);
    g_assert_cmpuint(u, ==, 42);
    visit_type_uint64(v, "number2", &u, &error_abort);
    g_assert_cmpuint(u, ==, 42);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);

    /* Trailing crap */
    qdict = keyval_parse("number1=3.14,number2=08",
                         NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_uint64(v, "number1", &u, &err);
    error_free_or_abort(&err);
    visit_type_uint64(v, "number2", &u, &err);
    error_free_or_abort(&err);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void test_keyval_visit_size(void)
{
    Error *err = NULL;
    Visitor *v;
    QDict *qdict;
    uint64_t sz;

    /* Lower limit zero */
    qdict = keyval_parse("sz1=0", NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_size(v, "sz1", &sz, &error_abort);
    g_assert_cmpuint(sz, ==, 0);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);

    /* Note: precision is 53 bits since we're parsing with strtod() */

    /* Around limit of precision: 2^53-1, 2^53, 2^53+1 */
    qdict = keyval_parse("sz1=9007199254740991,"
                         "sz2=9007199254740992,"
                         "sz3=9007199254740993",
                         NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_size(v, "sz1", &sz, &error_abort);
    g_assert_cmphex(sz, ==, 0x1fffffffffffff);
    visit_type_size(v, "sz2", &sz, &error_abort);
    g_assert_cmphex(sz, ==, 0x20000000000000);
    visit_type_size(v, "sz3", &sz, &error_abort);
    g_assert_cmphex(sz, ==, 0x20000000000000);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);

    /* Close to signed upper limit 0x7ffffffffffffc00 (53 msbs set) */
    qdict = keyval_parse("sz1=9223372036854774784," /* 7ffffffffffffc00 */
                         "sz2=9223372036854775295", /* 7ffffffffffffdff */
                         NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_size(v, "sz1", &sz, &error_abort);
    g_assert_cmphex(sz, ==, 0x7ffffffffffffc00);
    visit_type_size(v, "sz2", &sz, &error_abort);
    g_assert_cmphex(sz, ==, 0x7ffffffffffffc00);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);

    /* Close to actual upper limit 0xfffffffffffff800 (53 msbs set) */
    qdict = keyval_parse("sz1=18446744073709549568," /* fffffffffffff800 */
                         "sz2=18446744073709550591", /* fffffffffffffbff */
                         NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_size(v, "sz1", &sz, &error_abort);
    g_assert_cmphex(sz, ==, 0xfffffffffffff800);
    visit_type_size(v, "sz2", &sz, &error_abort);
    g_assert_cmphex(sz, ==, 0xfffffffffffff800);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);

    /* Beyond limits */
    qdict = keyval_parse("sz1=-1,"
                         "sz2=18446744073709550592", /* fffffffffffffc00 */
                         NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_size(v, "sz1", &sz, &err);
    error_free_or_abort(&err);
    visit_type_size(v, "sz2", &sz, &err);
    error_free_or_abort(&err);
    visit_end_struct(v, NULL);
    visit_free(v);

    /* Suffixes */
    qdict = keyval_parse("sz1=8b,sz2=1.5k,sz3=2M,sz4=0.1G,sz5=16777215T",
                         NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_size(v, "sz1", &sz, &error_abort);
    g_assert_cmpuint(sz, ==, 8);
    visit_type_size(v, "sz2", &sz, &error_abort);
    g_assert_cmpuint(sz, ==, 1536);
    visit_type_size(v, "sz3", &sz, &error_abort);
    g_assert_cmphex(sz, ==, 2 * M_BYTE);
    visit_type_size(v, "sz4", &sz, &error_abort);
    g_assert_cmphex(sz, ==, G_BYTE / 10);
    visit_type_size(v, "sz5", &sz, &error_abort);
    g_assert_cmphex(sz, ==, 16777215 * T_BYTE);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);

    /* Beyond limit with suffix */
    qdict = keyval_parse("sz1=16777216T", NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_size(v, "sz1", &sz, &err);
    error_free_or_abort(&err);
    visit_end_struct(v, NULL);
    visit_free(v);

    /* Trailing crap */
    qdict = keyval_parse("sz1=16E,sz2=16Gi", NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_size(v, "sz1", &sz, &err);
    error_free_or_abort(&err);
    visit_type_size(v, "sz2", &sz, &err);
    error_free_or_abort(&err);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void test_keyval_visit_dict(void)
{
    Error *err = NULL;
    Visitor *v;
    QDict *qdict;
    int64_t i;

    qdict = keyval_parse("a.b.c=1,a.b.c=2,d=3", NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_start_struct(v, "a", NULL, 0, &error_abort);
    visit_start_struct(v, "b", NULL, 0, &error_abort);
    visit_type_int(v, "c", &i, &error_abort);
    g_assert_cmpint(i, ==, 2);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_type_int(v, "d", &i, &error_abort);
    g_assert_cmpint(i, ==, 3);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);

    qdict = keyval_parse("a.b=", NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_start_struct(v, "a", NULL, 0, &error_abort);
    visit_type_int(v, "c", &i, &err);   /* a.c missing */
    error_free_or_abort(&err);
    visit_check_struct(v, &err);
    error_free_or_abort(&err);          /* a.b unexpected */
    visit_end_struct(v, NULL);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void test_keyval_visit_list(void)
{
    Error *err = NULL;
    Visitor *v;
    QDict *qdict;
    char *s;

    qdict = keyval_parse("a.0=,a.1=I,a.2.0=II", NULL, &error_abort);
    /* TODO empty list */
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_start_list(v, "a", NULL, 0, &error_abort);
    visit_type_str(v, NULL, &s, &error_abort);
    g_assert_cmpstr(s, ==, "");
    g_free(s);
    visit_type_str(v, NULL, &s, &error_abort);
    g_assert_cmpstr(s, ==, "I");
    g_free(s);
    visit_start_list(v, NULL, NULL, 0, &error_abort);
    visit_type_str(v, NULL, &s, &error_abort);
    g_assert_cmpstr(s, ==, "II");
    g_free(s);
    visit_check_list(v, &error_abort);
    visit_end_list(v, NULL);
    visit_check_list(v, &error_abort);
    visit_end_list(v, NULL);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);

    qdict = keyval_parse("a.0=,b.0.0=head", NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_start_list(v, "a", NULL, 0, &error_abort);
    visit_check_list(v, &err);  /* a[0] unexpected */
    error_free_or_abort(&err);
    visit_end_list(v, NULL);
    visit_start_list(v, "b", NULL, 0, &error_abort);
    visit_start_list(v, NULL, NULL, 0, &error_abort);
    visit_type_str(v, NULL, &s, &error_abort);
    g_assert_cmpstr(s, ==, "head");
    g_free(s);
    visit_type_str(v, NULL, &s, &err); /* b[0][1] missing */
    error_free_or_abort(&err);
    visit_end_list(v, NULL);
    visit_end_list(v, NULL);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void test_keyval_visit_optional(void)
{
    Visitor *v;
    QDict *qdict;
    bool present;
    int64_t i;

    qdict = keyval_parse("a.b=1", NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_optional(v, "b", &present);
    g_assert(!present);         /* b missing */
    visit_optional(v, "a", &present);
    g_assert(present);          /* a present */
    visit_start_struct(v, "a", NULL, 0, &error_abort);
    visit_optional(v, "b", &present);
    g_assert(present);          /* a.b present */
    visit_type_int(v, "b", &i, &error_abort);
    g_assert_cmpint(i, ==, 1);
    visit_optional(v, "a", &present);
    g_assert(!present);         /* a.a missing */
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void test_keyval_visit_alternate(void)
{
    Error *err = NULL;
    Visitor *v;
    QDict *qdict;
    AltNumStr *ans;
    AltNumInt *ani;

    /*
     * Can't do scalar alternate variants other than string.  You get
     * the string variant if there is one, else an error.
     */
    qdict = keyval_parse("a=1,b=2", NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_AltNumStr(v, "a", &ans, &error_abort);
    g_assert_cmpint(ans->type, ==, QTYPE_QSTRING);
    g_assert_cmpstr(ans->u.s, ==, "1");
    visit_type_AltNumInt(v, "a", &ani, &err);
    error_free_or_abort(&err);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void test_keyval_visit_any(void)
{
    Visitor *v;
    QDict *qdict;
    QObject *any;
    QList *qlist;
    QString *qstr;

    qdict = keyval_parse("a.0=null,a.1=1", NULL, &error_abort);
    v = qobject_input_visitor_new_keyval(QOBJECT(qdict));
    QDECREF(qdict);
    visit_start_struct(v, NULL, NULL, 0, &error_abort);
    visit_type_any(v, "a", &any, &error_abort);
    qlist = qobject_to_qlist(any);
    g_assert(qlist);
    qstr = qobject_to_qstring(qlist_pop(qlist));
    g_assert_cmpstr(qstring_get_str(qstr), ==, "null");
    qstr = qobject_to_qstring(qlist_pop(qlist));
    g_assert_cmpstr(qstring_get_str(qstr), ==, "1");
    g_assert(qlist_empty(qlist));
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);
    visit_free(v);
}

int main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/keyval/keyval_parse", test_keyval_parse);
    g_test_add_func("/keyval/keyval_parse/list", test_keyval_parse_list);
    g_test_add_func("/keyval/visit/bool", test_keyval_visit_bool);
    g_test_add_func("/keyval/visit/number", test_keyval_visit_number);
    g_test_add_func("/keyval/visit/size", test_keyval_visit_size);
    g_test_add_func("/keyval/visit/dict", test_keyval_visit_dict);
    g_test_add_func("/keyval/visit/list", test_keyval_visit_list);
    g_test_add_func("/keyval/visit/optional", test_keyval_visit_optional);
    g_test_add_func("/keyval/visit/alternate", test_keyval_visit_alternate);
    g_test_add_func("/keyval/visit/any", test_keyval_visit_any);
    g_test_run();
    return 0;
}
