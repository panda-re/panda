#ifndef PANDA_DEBUG_H
#define PANDA_DEBUG_H
/*
 * Macros for better debug output.
 *
 *  PANDA_MSG_PREFIX, PANDA_MSG_SUFFIX: use with C++ iostream, when plugin name is dynamic
 *  PANDA_MSG_FMT: use with C stdio, when plugin name is dynamic
 *  PANDA_MSG: use with either C or C++ code, when plugin name is static
 *  PANDA_FLAG_STATUS: use with either C or C++ code
 */
#define PANDA_CORE_NAME "core"
#define PANDA_MSG_PREFIX "PANDA["
#define PANDA_MSG_SUFFIX "]: "
#define PANDA_MSG_FMT PANDA_MSG_PREFIX "%s" PANDA_MSG_SUFFIX
#ifdef PLUGIN_NAME
#define PANDA_MSG PANDA_MSG_PREFIX PLUGIN_NAME PANDA_MSG_SUFFIX
#else
#define PANDA_MSG PANDA_MSG_PREFIX PANDA_CORE_NAME PANDA_MSG_SUFFIX
#endif
#define PANDA_FLAG_STATUS(flag) ((flag) ? "ENABLED" : "DISABLED")
#endif
