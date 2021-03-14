#ifndef PANDA_PLUGIN_API
#define PANDA_PLUGIN_API
#include "panda/types.h"
#include "exec/exec-all.h"

target_ptr_t tb_get_pc(TranslationBlock * tb);
size_t tb_get_size(TranslationBlock * tb);


#endif
