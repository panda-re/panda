#ifndef COVERAGE_PROCESSNAME_PREDICATE_H
#define COVERAGE_PROCESSNAME_PREDICATE_H

#include <string>

#include "Predicate.h"

namespace coverage
{

/**
 * A predicate for filtering on process name.
 */
class ProcessNamePredicate : public Predicate
{
public:
    ProcessNamePredicate(const std::string& pname);

    bool eval(CPUState *cpu, TranslationBlock *tb) override;
private:
    std::string process_name;
};

}

#endif
