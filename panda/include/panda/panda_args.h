#ifndef __PANDA_ARGS_H__
#define __PANDA_ARGS_H__

// Fns and structs to do with panda arg parsing 

// NOTE: Pls read README before editing!

// Struct for holding a parsed key/value pair from
// a -panda-arg plugin:key=value style argument.
typedef struct panda_arg {
    char *argptr;   // For internal use only
    char *key;      // Pointer to the key string
    char *value;    // Pointer to the value string
} panda_arg;


typedef struct panda_arg_list {
    int nargs;
    panda_arg *list;
    char *plugin_name;
} panda_arg_list;



bool panda_add_arg(const char *plugin_name, const char *plugin_arg);

// Parse out arguments and return them to caller
panda_arg_list *panda_get_args(const char *plugin_name);

// Free a list of parsed arguments
void panda_free_args(panda_arg_list *args);

bool panda_parse_bool_req(panda_arg_list *args, const char *argname, const char *help);
bool panda_parse_bool_opt(panda_arg_list *args, const char *argname, const char *help);
bool panda_parse_bool(panda_arg_list *args, const char *argname);

target_ulong panda_parse_ulong_req(panda_arg_list *args, const char *argname, const char *help);
target_ulong panda_parse_ulong_opt(panda_arg_list *args, const char *argname, target_ulong defval, const char *help);
target_ulong panda_parse_ulong(panda_arg_list *args, const char *argname, target_ulong defval);

uint32_t panda_parse_uint32_req(panda_arg_list *args, const char *argname, const char *help);
uint32_t panda_parse_uint32_opt(panda_arg_list *args, const char *argname, uint32_t defval, const char *help);
uint32_t panda_parse_uint32(panda_arg_list *args, const char *argname, uint32_t defval);

uint64_t panda_parse_uint64_req(panda_arg_list *args, const char *argname, const char *help);
uint64_t panda_parse_uint64_opt(panda_arg_list *args, const char *argname, uint64_t defval, const char *help);
uint64_t panda_parse_uint64(panda_arg_list *args, const char *argname, uint64_t defval);

double panda_parse_double_req(panda_arg_list *args, const char *argname, const char *help);
double panda_parse_double_opt(panda_arg_list *args, const char *argname, double defval, const char *help);
double panda_parse_double(panda_arg_list *args, const char *argname, double defval);

const char *panda_parse_string_req(panda_arg_list *args, const char *argname, const char *help);
const char *panda_parse_string_opt(panda_arg_list *args, const char *argname, const char *defval, const char *help);
const char *panda_parse_string(panda_arg_list *args, const char *argname, const char *defval);

char** str_split(char* a_str, const char a_delim);
extern const gchar *panda_argv[MAX_PANDA_PLUGIN_ARGS];
extern int panda_argc;


#endif
