// Make things a little easier on other plugins

typedef int (* get_functions_t)(target_ulong functions[], int n, CPUState *env);
typedef int (* get_callers_t)(target_ulong callers[], int n, CPUState *env);
typedef void (* get_prog_point_t)(CPUState *env, prog_point *p);
typedef void (* on_call_t)(CPUState *env, target_ulong func);
typedef void (* add_on_call_t)(on_call_t fptr);
typedef void (* on_ret_t)(CPUState *env, target_ulong func);
typedef void (* add_on_ret_t)(on_ret_t fptr);
