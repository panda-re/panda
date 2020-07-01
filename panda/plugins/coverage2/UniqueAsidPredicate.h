#ifndef COVERAGE2_UNIQUEASID_PREDICATE_H
#define COVERAGE2_UNIQUEASID_PREDICATE_H

#include <unordered_set>

#include "Predicate.h"

struct UniqueAsidRecord
{
    target_ulong asid;
    target_ulong pc;
};

namespace std
{

template <> class hash<UniqueAsidRecord>
{
public:
    size_t operator()(UniqueAsidRecord const &rec) const noexcept
    {
        size_t const h1 = std::hash<target_ulong>{}(rec.asid);
        size_t const h2 = std::hash<target_ulong>{}(rec.pc);
        return h1 ^ (h2 << 2);
    }
};

}

static inline bool operator==(const UniqueAsidRecord &lhs, const UniqueAsidRecord &rhs)
{
    return (lhs.asid == rhs.asid) && (lhs.pc == rhs.pc);
}

namespace coverage2
{


class UniqueAsidPredicate : public Predicate
{
public:
    bool eval(CPUState *cpu, target_ulong pc) override;
private:
    std::unordered_set<UniqueAsidRecord> seen;
};

}

#endif
