#ifndef COVERAGE2_PREDICATE_H
#define COVERAGE2_PREDICATE_H

#include "panda/plugin.h"

namespace coverage
{

/**
 * A Predicate interface used to evaluate state of the guest.
 */
class Predicate
{
public:
    /**
     * Implemented by Predicate classes to determine if the guest is in a
     * particular state.
     */
    virtual bool eval(CPUState *cpu, TranslationBlock *tb) = 0;    
};

}

#endif
