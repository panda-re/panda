extern "C" {
#include <sys/mman.h>
}

#include <map>
#include <vector>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <functional>

#include "label_set.h"

template<typename T>
class ArenaAlloc {
private:
    uint8_t *next = NULL;
    std::vector<std::pair<uint8_t *, size_t>> blocks;
    size_t next_block_size = 1 << 15;

    void alloc_block() {
        //printf("taint2: allocating block of size %lu\n", next_block_size);
        next = (uint8_t *)mmap(NULL, next_block_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(next);
        blocks.push_back(std::make_pair(next, next_block_size));
        next_block_size <<= 1;
    }

    T *alloc_imp() {
        assert(blocks.size() > 0);
        std::pair<uint8_t *, size_t>& block = blocks.back();
        if (next + sizeof(T) > block.first + block.second) {
            alloc_block();
            assert(next != NULL);
        }

        T *result = new(next) T;
        next += sizeof(T);
        return result;
    }

public:
    ArenaAlloc() {
        alloc_block();
    }

    const T *alloc() {
        return alloc_imp();
    }

    const T *alloc(T &old) {
        T *result = alloc_imp();
        result->swap(old);
        return result;
    }

    ~ArenaAlloc() {
        for (auto&& block : blocks) {
            munmap(block.first, block.second);
        }
    }
};

static ArenaAlloc<std::set<uint32_t>> LSA;

namespace std {
template<>
class hash<set<uint32_t>> {
  public:
    size_t operator()(const set<uint32_t> &labels) const {
        uint64_t result = 0;
        for (uint32_t l : labels) {
            result ^= l;
            result = result << 11 | result >> 53;
        }
        return result;
    }
};

template<>
class hash<pair<LabelSetP, LabelSetP>> {
  public:
    size_t operator()(const pair<LabelSetP, LabelSetP> &labels) const {
        return hash<LabelSetP>()(labels.first) ^
            (hash<LabelSetP>()(labels.second) << (sizeof(LabelSetP) / 2));
    }
};
}

static std::unordered_set<std::set<uint32_t>> label_sets;
LabelSetP label_set_union(LabelSetP ls1, LabelSetP ls2) {
    static std::unordered_map<std::pair<LabelSetP, LabelSetP>, LabelSetP> memoized_unions;

    if (ls1 == ls2) {
        return ls1;
    } else if (ls1 && ls2) {
        LabelSetP min = std::min(ls1, ls2);
        LabelSetP max = std::max(ls1, ls2);
        std::pair<LabelSetP, LabelSetP> minmax(min, max);

        {
            auto it = memoized_unions.find(minmax);
            if (it != memoized_unions.end()) {
                return it->second;
            }
        }

        std::set<uint32_t> temp(*min);
        for (auto l : *max) {
            temp.insert(l);
        }

        // insert returns a pair <iterator, bool>; second is whether it happened
        // first is iterator to new/existing element
        auto it = label_sets.insert(temp).first;
        const std::set<uint32_t> *result = &(*it);

        memoized_unions.insert(std::make_pair(minmax, result));
        return result;
    } else if (ls1) {
        return ls1;
    } else if (ls2) {
        return ls2;
    } else return nullptr;
}

LabelSetP label_set_singleton(uint32_t label) {
    std::set<uint32_t> temp;
    temp.insert(label);
    return LSA.alloc(temp);
}

std::set<uint32_t> label_set_render_set(LabelSetP ls) {
    if (ls) return *ls;
    else return std::set<uint32_t>();
}
