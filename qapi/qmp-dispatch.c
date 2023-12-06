/*
 * Core Definitions for QAPI/QMP Dispatch
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qmp/types.h"
#include "qapi/qmp/dispatch.h"
#include "qapi/qmp/json-parser.h"
#include "qapi/qmp/qjson.h"
#include "qapi-types.h"
#include "qapi/qmp/qerror.h"

//#include "panda/callbacks/cb-support.h"
extern bool panda_callbacks_qmp(char *command, char* args, char **result);
// And we have a stub in stubs/qtest.c  that always returns false if we build
// without panda for tests

static QDict *qmp_dispatch_check_obj(const QObject *request, Error **errp)
{
    const QDictEntry *ent;
    const char *arg_name;
    const QObject *arg_obj;
    bool has_exec_key = false;
    QDict *dict = NULL;

    dict = qobject_to_qdict(request);
    if (!dict) {
        error_setg(errp, "Expected '%s' in QMP input", "object");
        return NULL;
    }

    for (ent = qdict_first(dict); ent;
         ent = qdict_next(dict, ent)) {
        arg_name = qdict_entry_key(ent);
        arg_obj = qdict_entry_value(ent);

        if (!strcmp(arg_name, "execute")) {
            if (qobject_type(arg_obj) != QTYPE_QSTRING) {
                error_setg(errp, "QMP input object member '%s' expects '%s'",
                           "execute", "string");
                return NULL;
            }
            has_exec_key = true;
        } else if (!strcmp(arg_name, "arguments")) {
            if (qobject_type(arg_obj) != QTYPE_QDICT) {
                error_setg(errp, "QMP input object member '%s' expects '%s'",
                           "arguments", "object");
                return NULL;
            }
        } else {
            error_setg(errp, "QMP input object member '%s' is unexpected",
                       arg_name);
            return NULL;
        }
    }

    if (!has_exec_key) {
        error_setg(errp, "Expected '%s' in QMP input", "execute");
        return NULL;
    }

    return dict;
}

static QObject *do_qmp_dispatch(QmpCommandList *cmds, QObject *request,
                                Error **errp)
{
    Error *local_err = NULL;
    const char *command;
    QDict *args, *dict;
    QmpCommand *cmd;
    QObject *ret = NULL;

    dict = qmp_dispatch_check_obj(request, errp);
    if (!dict) {
        return NULL;
    }

    command = qdict_get_str(dict, "execute");
    cmd = qmp_find_command(cmds, command);

    if (!qdict_haskey(dict, "arguments")) {
        args = qdict_new();
    } else {
        args = qdict_get_qdict(dict, "arguments");
        QINCREF(args);
    }

    if (cmd == NULL) {
        // Call any PANDA consumers of the unhandled command
        // Provide them with arguments in json format.
        // If any plugin returns true, we assume it handled the command
        // and we expect a json output in result.
        char *result = NULL;
        const QString* cmd_args_q = qobject_to_json(QOBJECT(args));
        const char *cmd_args = qstring_get_str(cmd_args_q);

        if (panda_callbacks_qmp((char*)command, (char*)cmd_args, &result)) {
            if (result != NULL) {
                // We have a return value from the callback. Let's convert it to a qobject
                ret = qobject_from_json(result, &local_err);
                if (local_err) {
                    printf("PANDA ERROR decoding result json in callback");
                    error_propagate(errp, local_err);
                    return NULL;
                }
            }

            if (!ret) {
                printf("PANDA WARNING: a qmp callback consumer returned TRUE without providing \
                        a return value! Creating empty dictionary");

                ret = QOBJECT(qdict_new());
            }
            QDECREF(args);
            return ret;
        }

        error_set(errp, ERROR_CLASS_COMMAND_NOT_FOUND,
                  "The command %s has not been found", command);
        return NULL;
    }

    if (!cmd->enabled) {
        error_setg(errp, "The command %s has been disabled for this instance",
                   command);
        return NULL;
    }

    cmd->fn(args, &ret, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
    } else if (cmd->options & QCO_NO_SUCCESS_RESP) {
        g_assert(!ret);
    } else if (!ret) {
        ret = QOBJECT(qdict_new());
    }

    QDECREF(args);

    return ret;
}

QObject *qmp_build_error_object(Error *err)
{
    return qobject_from_jsonf("{ 'class': %s, 'desc': %s }",
                              QapiErrorClass_lookup[error_get_class(err)],
                              error_get_pretty(err));
}

QObject *qmp_dispatch(QmpCommandList *cmds, QObject *request)
{
    Error *err = NULL;
    QObject *ret;
    QDict *rsp;

    ret = do_qmp_dispatch(cmds, request, &err);

    rsp = qdict_new();
    if (err) {
        qdict_put_obj(rsp, "error", qmp_build_error_object(err));
        error_free(err);
    } else if (ret) {
        qdict_put_obj(rsp, "return", ret);
    } else {
        QDECREF(rsp);
        return NULL;
    }

    return QOBJECT(rsp);
}
