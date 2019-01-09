/*
 * QAPI util functions
 *
 * Authors:
 *  Hu Tao       <hutao@cn.fujitsu.com>
 *  Peter Lieven <pl@kamp.de>
 * 
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "qapi/util.h"

int qapi_enum_parse(const char * const lookup[], const char *buf,
                    int max, int def, Error **errp)
{
    int i;

    if (!buf) {
        return def;
    }

    for (i = 0; i < max; i++) {
        if (!strcmp(buf, lookup[i])) {
            return i;
        }
    }

    error_setg(errp, "invalid parameter value: %s", buf);
    return def;
}

/*
 * Parse a valid QAPI name from @str.
 * A valid name consists of letters, digits, hyphen and underscore.
 * It may be prefixed by __RFQDN_ (downstream extension), where RFQDN
 * may contain only letters, digits, hyphen and period.
 * The special exception for enumeration names is not implemented.
 * See docs/qapi-code-gen.txt for more on QAPI naming rules.
 * Keep this consistent with scripts/qapi.py!
 * If @complete, the parse fails unless it consumes @str completely.
 * Return its length on success, -1 on failure.
 */
int parse_qapi_name(const char *str, bool complete)
{
    const char *p = str;

    if (*p == '_') {            /* Downstream __RFQDN_ */
        p++;
        if (*p != '_') {
            return -1;
        }
        while (*++p) {
            if (!qemu_isalnum(*p) && *p != '-' && *p != '.') {
                break;
            }
        }

        if (*p != '_') {
            return -1;
        }
        p++;
    }

    if (!qemu_isalpha(*p)) {
        return -1;
    }
    while (*++p) {
        if (!qemu_isalnum(*p) && *p != '-' && *p != '_') {
            break;
        }
    }

    if (complete && *p) {
        return -1;
    }
    return p - str;
}
