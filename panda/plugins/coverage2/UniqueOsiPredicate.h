#ifndef COVERAGE2_UNIQUEOSI_PREDICATE_H
#define COVERAGE2_UNIQUEOSI_PREDICATE_H

#include <unordered_set>

#include "Predicate.h"

struct UniqueOsiRecord
{
    target_ulong pid;
    target_ulong tid;
    target_ulong pc;
};

namespace std
{

template <> class hash<UniqueOsiRecord>
{
public:
    size_t operator()(UniqueOsiRecord const &rec) const noexcept
    {
        size_t const h1 = std::hash<target_ulong>{}(rec.pid);
        size_t const h2 = std::hash<target_ulong>{}(rec.tid);
        size_t const h3 = std::hash<target_ulong>{}(rec.pc);
        return h1 ^ (h2 << 2) ^ (h3 << 3);
    }
};

}

static inline bool operator==(const UniqueOsiRecord &lhs, const UniqueOsiRecord &rhs)
{
    return (lhs.pid == rhs.pid) && (lhs.tid == rhs.tid) && (lhs.pc == rhs.pc);
}

namespace coverage2
{

class UniqueOsiPredicate : public Predicate
{
public:
    bool eval(CPUState *cpu, TranslationBlock *tb) override;
private:
    std::unordered_set<UniqueOsiRecord> seen;
};

}

#endif
