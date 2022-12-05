#ifndef PLUGIN_QPP_H
#define PLUGIN_QPP_H

/*
 * Facilities for "Plugin to plugin" (QPP) interactions between tcg plugins.
 * These allows for direct function calls between loaded plugins. For more
 * details see docs/devel/plugin.rst.
 */


/*
 * Internal macros
 */
#define _PLUGIN_STR(s) #s
#define PLUGIN_STR(s) _PLUGIN_STR(s)
#define _PLUGIN_CONCAT(x, y) x##y
#define PLUGIN_CONCAT(x, y) _PLUGIN_CONCAT(x, y)
#define _QPP_SETUP_NAME(fn) PLUGIN_CONCAT(_qpp_setup_, fn)

/*
 * A header file that defines an exported function should use
 * the QPP_FUN_PROTOTYPE macro to create the necessary types.
 *
 * The generated function named after the output of QPP_SETUP_NAME should
 * dynamically resolve a target function in another plugin or raise a fatal
 * error on failure. This function has the constructor attribute so it will
 * run immediately when the plugin shared object object is loaded.
 *
 * Note that the variable qemu_plugin_name must be set before this macro is
 * used. In other words the plugin that includes a header file with these
 * macros should set qemu_plugin_name before including such headers. When the
 * generated function is run it compares the current plugin name to the name
 * of the plugin that provides the target function.
 *
 * If the target plugin is not the current plugin it will resolve the function
 * pointer from qemu_plugin_import_function, correctly cast it, and assign the
 * function pointer "[function_name]_qpp" which can then be used by the plugin
 * that imported it.
 */

#define QPP_FUN_PROTOTYPE(plugin_name, fn_ret, fn, args)                      \
  fn_ret fn(args);                                                            \
  typedef fn_ret(*PLUGIN_CONCAT(fn, _t))(args);                               \
  fn##_t fn##_qpp;                                                            \
  void _QPP_SETUP_NAME(fn) (void);                                            \
                                                                              \
  void __attribute__ ((constructor)) _QPP_SETUP_NAME(fn) (void) {             \
    if (strcmp(qemu_plugin_name, #plugin_name) != 0) {                        \
        fn##_qpp = (fn##_t)qemu_plugin_import_function(                       \
                                                      PLUGIN_STR(plugin_name),\
                                                      PLUGIN_STR(fn));        \
    }                                                                         \
  }
#endif /* PLUGIN_QPP_H */
