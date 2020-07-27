#include "panda/plugin.h"

typedef struct sig_event_t {
    int32_t sig;
    bool supressed;
    std::string src_name;
    std::string dst_name;
    target_pid_t src_pid;
    target_pid_t dst_pid;
} sig_event_t;