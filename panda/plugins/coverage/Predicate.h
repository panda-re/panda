#ifndef COVERAGE_PREDICATE_H
#define COVERAGE_PREDICATE_H

#include "panda/plugin.h"

namespace coverage
{

/**
 * A Predicate interface used to evaluate state of the guest.
 */
class Predicate
{
public:
    virtual ~Predicate() = 0;

    /**
     * Implemented by Predicate classes to determine if the guest is in a
     * particular state.
     */
    virtual bool eval(CPUState *cpu, TranslationBlock *tb) = 0;    
};

}

#endif
