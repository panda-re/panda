extern "C" {
#include <sys/mman.h>
}

#include <map>
#include <vector>

#include "label_set.h"

class LabelSetAlloc {
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

public:
    LabelSetAlloc() {
        alloc_block();
    }

    LabelSetP alloc() {
        assert(blocks.size() > 0);
        std::pair<uint8_t *, size_t>& block = blocks.back();
        if (next > block.first + block.second) {
            alloc_block();
            assert(next != NULL);
        }

        LabelSetP result = new(next) struct LabelSet;
        next += sizeof(struct LabelSet);
        return result;
    }

    ~LabelSetAlloc() {
        for (auto&& block : blocks) {
            munmap(block.first, block.second);
        }
    }
} *LSA = NULL;

std::map<std::pair<LabelSetP, LabelSetP>, LabelSetP> *memoized_unions = NULL;

LabelSetP label_set_union(LabelSetP ls1, LabelSetP ls2) {
    if (ls1 == ls2) {
        return ls1;
    } else if (ls1 && ls2) {
        LabelSetP min = std::min(ls1, ls2);
        LabelSetP max = std::max(ls1, ls2);
        std::pair<LabelSetP, LabelSetP> minmax(min, max);

        if (!memoized_unions)
            memoized_unions = new std::map<std::pair<LabelSetP, LabelSetP>, LabelSetP>();
        //qemu_log_mask(CPU_LOG_TAINT_OPS, "  MEMO: %lu, %lu\n", (uint64_t)min, (uint64_t)max);

        auto it = memoized_unions->find(minmax);
        if (it != memoized_unions->end()) {
            return it->second;
        }
        //qemu_log_mask(CPU_LOG_TAINT_OPS, "  NOT FOUND\n");

        if (!LSA) LSA = new LabelSetAlloc();
        LabelSetP result = LSA->alloc();
        //labelset_count++;

        result->child1 = min;
        result->child2 = max;

        memoized_unions->insert(std::make_pair(minmax, result));
        //qemu_log_mask(CPU_LOG_TAINT_OPS, "  INSERTED\n");
        return result;
    } else if (ls1) {
        return ls1;
    } else if (ls2) {
        return ls2;
    } else return nullptr;
}

LabelSetP label_set_singleton(uint32_t label) {
    if (!LSA) LSA = new LabelSetAlloc();
    LabelSetP result = LSA->alloc();
    //labelset_count++;

    result->child1 = nullptr;
    result->label = label;
    return result;
}

std::set<uint32_t> label_set_render_set(LabelSetP ls) {
    return label_set_iter<std::set<uint32_t>, set_insert>(ls);
}

uint64_t label_set_render_uint(LabelSetP ls) {
    constexpr uint64_t zero = 0UL;
    return label_set_iter<uint64_t, bitset_insert, zero>(ls);
}
