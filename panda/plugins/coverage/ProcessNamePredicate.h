#ifndef COVERAGE2_PROCESSNAME_PREDICATE_H
#define COVERAGE2_PROCESSNAME_PREDICATE_H

#include <string>

#include "Predicate.h"

namespace coverage
{

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
