/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

#ifndef __SHAD_H
#define __SHAD_H

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <map>

#ifdef TAINT2_DEBUG
#include "qemu/osdep.h"
#include "qemu/log.h"
#endif

#include "taint_defines.h"
#include "label_set.h"

class Shad;

extern "C" {
extern bool track_taint_state;
extern void taint_state_changed(Shad *shad, uint64_t addr, uint64_t size);
}

#define CPU_LOG_TAINT_OPS (1 << 28)

#ifdef TAINT2_DEBUG
#define tassert(cond) assert((cond))
#define taint_log(...) qemu_log_mask(CPU_LOG_TAINT_OPS, ## __VA_ARGS__);
#define taint_log_labels(shad, src, size) \
    extern int qemu_loglevel; \
    if (qemu_loglevel & CPU_LOG_TAINT_OPS) { \
        bool tainted = false; \
        for (int __i = 0; __i < size; __i++) { \
            LabelSetP ls = shad->query(src + __i); \
            qemu_log("{"); \
            if (ls) { \
                tainted = true; \
                for (uint32_t l : *shad->query(src + __i)) { \
                    qemu_log("%u, ", l); \
                } \
            } \
            qemu_log("}; "); \
        } \
        if (tainted) qemu_log("TAINTED"); \
        qemu_log("\n"); \
    }
#else
#define tassert(cond) {}
#define taint_log(...) {}
#define taint_log_labels(shad, src, size) {}
#endif

struct TaintData {
    LabelSetP ls;
    // Taint compute number.
    uint32_t tcn;

    // Controlled bit mask. This is an estimate of conditional entropy that
    // we compute at the small-step level. We assume that integers are
    // distributed according to a uniform distribution on some subset of the
    // bits of each byte.
    uint8_t cb_mask;

    // Bits known to be 1 or 0 via bitwise operations.
    uint8_t one_mask;
    uint8_t zero_mask;

    TaintData() : ls(NULL), tcn(0), cb_mask(0), one_mask(0), zero_mask(0) {}
    explicit TaintData(LabelSetP ls) : ls(ls), tcn(0), cb_mask(ls ? 0xFF : 0),
            one_mask(0), zero_mask(0) {}
    TaintData(LabelSetP ls, uint32_t tcn, uint8_t cb_mask, 
            uint8_t one_mask, uint8_t zero_mask)
        : ls(ls), tcn(ls ? tcn : 0), cb_mask(ls ? cb_mask : 0),
        one_mask(one_mask), zero_mask(zero_mask) {}

    bool operator==(const TaintData &other) const {
        return ls == other.ls &&
            tcn == other.tcn &&
            cb_mask == other.cb_mask &&
            one_mask == other.one_mask &&
            zero_mask == other.zero_mask;
    }

    inline void increment_tcn() {
        if (ls) tcn++;
    }

    static TaintData make_union(const TaintData td1, const TaintData td2,
            bool increment_tcn) {
        return TaintData(
                label_set_union(td1.ls, td2.ls),
                std::max(td1.tcn, td2.tcn) + (increment_tcn ? 1 : 0),
                0, 0, 0); // Destroy controlled bits on union.
    }
};

class Shad
{
  protected:
    uint64_t size; // Number of labelsets contained.
    std::string _name;

    // Determines if any of the memory locations in the range [addr ..
    // addr+size-1] are tainted.
    virtual bool range_tainted(uint64_t addr, uint64_t size) = 0;

  public:
    virtual ~Shad() = 0;

    uint64_t get_size()
    {
        return size; }

    virtual void label(uint64_t addr, LabelSetP ls) = 0;

    static void copy(Shad *shad_dest, uint64_t dest, Shad *shad_src,
                     uint64_t src, uint64_t size)
    {
        tassert(dest + size >= dest);
        tassert(src + size >= src);
        tassert(dest + size <= shad_dest->size);
        tassert(src + size <= shad_src->size);

        bool change = false;
        if (track_taint_state && (shad_dest->range_tainted(dest, size) ||
                    shad_src->range_tainted(src, size)))
            change = true;

        for (uint64_t i = 0; i < size; i++) {
            auto td = shad_src->query_full(src + i);
            shad_dest->set_full(dest + i, td);
        }

        if (change) taint_state_changed(shad_dest, dest, size);
    }

    virtual void remove(uint64_t addr, uint64_t remove_size) = 0;

    // Query. NULL if untainted.
    virtual LabelSetP query(uint64_t addr) = 0;

    virtual void reset_frame() = 0;

    virtual void push_frame(uint64_t framesize) = 0;

    virtual void pop_frame(uint64_t framesize) = 0;

    virtual TaintData query_full(uint64_t addr) = 0;

    virtual void set_full(uint64_t addr, TaintData td) = 0;

    virtual uint32_t query_tcn(uint64_t addr) = 0;

    const char *name()
    {
        return _name.c_str();
    }

};

// A fast shadow memory - allocates memory on creation.
class FastShad : public Shad
{
  private:
    TaintData *labels;
    TaintData *orig_labels;

    TaintData *get_td_p(uint64_t guest_addr)
    {
        tassert(guest_addr < size);
        return &labels[guest_addr];
    }

  protected:
    bool range_tainted(uint64_t addr, uint64_t size) override
    {
        for (unsigned i = addr; i < addr + size; i++) {
            if (get_td_p(i)->ls)
                return true;
        }
        return false;
    }

  public:
    FastShad(std::string name, uint64_t size);
    ~FastShad();

    // Taint an address with a labelset.
    void label(uint64_t addr, LabelSetP ls) override
    {
        taint_log("LABEL: %s[%lx] (%p)\n", name(), addr, ls);
        *get_td_p(addr) = TaintData(ls);
    }

    // Remove taint.
    void remove(uint64_t addr, uint64_t remove_size) override
    {
        tassert(addr + remove_size >= addr);
        tassert(addr + remove_size <= size);

        bool change = false;
        if (track_taint_state && range_tainted(addr, remove_size))
            change = true;
        memset(get_td_p(addr), 0, remove_size * sizeof(TaintData));

        if (change)
            taint_state_changed(this, addr, remove_size);
    }

    LabelSetP query(uint64_t addr) override
    {
        return get_td_p(addr)->ls;
    }

    void reset_frame() override
    {
        labels = orig_labels;
        taint_log("reset: %lx\n", (uint64_t)labels);
    }

    void push_frame(uint64_t framesize) override
    {
        labels += framesize;
        tassert(labels < orig_labels + size);
        taint_log("push: %lx\n", (uint64_t)labels);
    }

    void pop_frame(uint64_t framesize) override
    {
        labels -= framesize;
        tassert(labels >= orig_labels);
        taint_log("pop: %lx\n", (uint64_t)labels);
    }

    TaintData query_full(uint64_t addr) override
    {
        return labels[addr];
    }

    void set_full(uint64_t addr, TaintData td) override
    {
        tassert(addr < size);

        bool change = !(td == *get_td_p(addr));
        labels[addr] = td;

        if (change)
            taint_state_changed(this, addr, 1);
    }

    uint32_t query_tcn(uint64_t addr) override
    {
        return (query_full(addr)).tcn;
    }
};

class LazyShad : public Shad
{
  private:
    std::map<uint64_t, TaintData> labels;

  protected:
    bool range_tainted(uint64_t addr, uint64_t size) override
    {
        for (uint64_t cur = addr; cur < addr + size - 1; cur++) {
            auto it = labels.find(cur);
            if (it != labels.end() && it->second.ls) {
                return true;
            }
        }
        return false;
    }

  public:
    LazyShad(std::string name, uint64_t size);
    ~LazyShad();

    void label(uint64_t addr, LabelSetP ls) override
    {
        taint_log("LABEL: %s[%lx] (%p)\n", name(), addr, ls);

        TaintData td;
        td.ls = ls;

        labels[addr] = td;
    }

    void remove(uint64_t addr, uint64_t remove_size) override
    {
        bool change = false;
        if (track_taint_state && range_tainted(addr, remove_size)) {
            change = true;
            for (uint64_t cur = addr; cur < addr + remove_size - 1; cur++) {
                labels.erase(cur);
            }
        }

        if (change) {
            taint_state_changed(this, addr, remove_size);
        }
    }

    LabelSetP query(uint64_t addr) override
    {
        auto result = labels.find(addr);
        if (result == labels.end()) {
            return NULL;
        }
        return result->second.ls;
    }

    TaintData query_full(uint64_t addr) override
    {
        return labels[addr];
    }

    void set_full(uint64_t addr, TaintData td) override
    {
        bool change = !(td == query_full(addr));
        labels[addr] = td;

        if (change)
            taint_state_changed(this, addr, 1);
    }

    uint32_t query_tcn(uint64_t addr) override
    {
        return (query_full(addr)).tcn;
    }

    void reset_frame() override
    {
    }

    void push_frame(uint64_t framesize) override
    {
    }

    void pop_frame(uint64_t framesize) override
    {
    }
};

#endif
