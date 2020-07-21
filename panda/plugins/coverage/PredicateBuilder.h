#ifndef COVERAGE2_PREDICATE_BUILDER_H
#define COVERAGE2_PREDICATE_BUILDER_H

#include <memory>

#include "Predicate.h"

namespace coverage
{

class PredicateBuilder
{
public:
    PredicateBuilder();
    void with_process_name(const std::string& pn);
    void with_pc_range(target_ulong low, target_ulong high);
    void in_kernel(bool ik);
    std::unique_ptr<Predicate> build(); 
private:
    std::unique_ptr<Predicate> predicate;
};

}

#endif
