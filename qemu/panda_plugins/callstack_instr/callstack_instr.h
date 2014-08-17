#ifndef __CALLSTACK_INSTR_H
#define __CALLSTACK_INSTR_H

typedef void (* on_call_t)(CPUState *env, TranslationBlock *pc, TranslationBlock *next);
typedef void (* on_ret_t)(CPUState *env, TranslationBlock *pc, TranslationBlock *next);

#endif
