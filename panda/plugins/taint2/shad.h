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

// force qemu_log to be undecorated so it can be found
extern "C" {
#include "qemu/log.h"
}
#endif

#include "taint_defines.h"
#include "label_set.h"
#include "sym_label.h"

class Shad;

extern "C" {
extern bool track_taint_state;
extern void taint_state_changed(Shad *shad, uint64_t addr, uint64_t size);

// maximum taintset compute number (0=unlimited)
// taint will be deleted once this value is exceeded
extern uint32_t max_tcn;

// maximum taintset cardinality (0=unlimited)
// taint will be deleted once this value is exceeded
extern uint32_t max_taintset_card;

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
    SymLabelP sym;

    TaintData() : ls(NULL), tcn(0), cb_mask(0), one_mask(0), zero_mask(0), sym(NULL) {}
    explicit TaintData(LabelSetP ls) : ls(ls), tcn(0), cb_mask(ls ? 0xFF : 0),
            one_mask(0), zero_mask(0), sym(NULL) {}
    TaintData(LabelSetP ls, uint32_t tcn, uint8_t cb_mask,
            uint8_t one_mask, uint8_t zero_mask)
        : ls(ls), tcn(ls ? tcn : 0), cb_mask(ls ? cb_mask : 0),
        one_mask(one_mask), zero_mask(zero_mask), sym(NULL) {}

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
    Shad(std::string name, uint64_t max_size);

    virtual ~Shad() = 0;

    // Puts the given TaintData object on the given address, without reporting
    // a taint change.  This method should ONLY be called internal to the Shad
    // inheritance tree, and only by methods that already take care of reporting
    // taint changes, or ONLY as a part of restoring taint earlier saved as a
    // part of preventing it from being lost (such as the i386 needs to work
    // around indeterminism in condition code calculations).
    virtual void set_full_quiet(uint64_t addr, TaintData td) = 0;

    uint64_t get_size()
    {
        return size; }

    virtual void label(uint64_t addr, LabelSetP ls) = 0;

    static bool copy(Shad *shad_dest, uint64_t dest, Shad *shad_src,
                     uint64_t src, uint64_t size)
    {
        tassert(dest + size >= dest);
        tassert(src + size >= src);
        tassert(dest + size <= shad_dest->size);
        tassert(src + size <= shad_src->size);

        bool change = false;
        if ((shad_dest->range_tainted(dest, size) ||
                    shad_src->range_tainted(src, size)))
            change = true;

        for (uint64_t i = 0; i < size; i++) {
            auto td = *shad_src->query_full(src + i);

            // don't report taint changes when store the taint data, as it is
            // already taken care of for all bytes below
            shad_dest->set_full_quiet(dest + i, td);
        }

        if (track_taint_state && change) taint_state_changed(shad_dest, dest, size);
        return change;
    }

    virtual void remove(uint64_t addr, uint64_t remove_size) = 0;

    // Removes the taint from remove_size items starting at address addr,
    // without reporting taint.  This method should ONLY be used by methods
    // that take care of reporting taint in other ways, or as a part of removing
    // erroneous taint introduced during a save/restore activity.
    virtual void remove_quiet(uint64_t addr, uint64_t remove_size) = 0;

    // Query. NULL if untainted.
    virtual LabelSetP query(uint64_t addr) = 0;

    virtual void reset_frame() = 0;

    virtual void push_frame(uint64_t framesize) = 0;

    virtual void pop_frame(uint64_t framesize) = 0;

    virtual TaintData *query_full(uint64_t addr) = 0;

    virtual bool set_full(uint64_t addr, TaintData td) = 0;

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
        // Even if the assert is disabled (prod build), this is still fatal
        tassert(guest_addr < size);
        if (guest_addr >= size) {
          fprintf(stderr, "PANDA[taint2]: Fatal error- taint query on invalid address 0x%lx\n", guest_addr);
          return NULL;
        }
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
        
#if 0
        // GCC8 doesn't like this memset and raises a warning but we really do want it
        // for performance reasons. The following code prevents the warning, but it's
        // about 10x slower so we instead disable the warning.
        TaintData *t = get_td_p(addr);
        for (int i=0; i < remove_size; i++) {
          t[i] = TaintData();
        }
#else
#pragma GCC diagnostic push
#if defined(__GNUC__) && __GNUC__ >= 8
#pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif
        memset(get_td_p(addr), 0, remove_size * sizeof(TaintData));
#pragma GCC diagnostic pop
#endif

        if (change)
            taint_state_changed(this, addr, remove_size);
    }

    void remove_quiet(uint64_t addr, uint64_t remove_size) override
    {
        tassert(addr + remove_size >= addr);
        tassert(addr + remove_size <= size);

#if 0
        // GCC8 doesn't like this memset and raises a warning but we really do want it
        // for performance reasons. The following code prevents the warning, but it's
        // about 10x slower so we instead disable the warning.
        TaintData *t = get_td_p(addr);
        for (int i=0; i < remove_size; i++) {
          t[i] = TaintData();
        }
#else
#pragma GCC diagnostic push
#if defined(__GNUC__) && __GNUC__ >= 8
#pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif
        memset(get_td_p(addr), 0, remove_size * sizeof(TaintData));
#pragma GCC diagnostic pop
#endif
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

    TaintData *query_full(uint64_t addr) override
    {
        tassert(addr < size);
        return &labels[addr];
    }

    bool set_full(uint64_t addr, TaintData td) override
    {
        tassert(addr < size);
        bool changed = false;

        uint32_t newcard = 0;
        if (td.ls != NULL) newcard = td.ls->size();
        if (((max_tcn == 0) || (td.tcn <= max_tcn)) &&
            ((max_taintset_card == 0) || (newcard <= max_taintset_card)))
        {
            bool change = !(td == *get_td_p(addr));
            labels[addr] = td;
            
            if (change) taint_state_changed(this, addr, 1);
            changed |= change;
        }
        else
        {
            // delete taint, if there is any, as things have gone too far
            if (range_tainted(addr, 1))
            {
                // remove will take care of taint_state_changed, unless they
                // don't care to be informed of removals
                remove(addr, 1);
            }
        }
        return changed;
    }

    // Set taint quietly - ie. no taint change report is made.
    void set_full_quiet(uint64_t addr, TaintData td) override
    {
        tassert(addr < size);
        labels[addr] = td;
    }

    uint32_t query_tcn(uint64_t addr) override
    {
        return query_full(addr)->tcn;
    }
};

class LazyShad : public Shad
{
  private:
    std::map<uint64_t, TaintData> labels;

  protected:
    bool range_tainted(uint64_t addr, uint64_t size) override
    {
        for (uint64_t cur = addr; cur < addr + size; cur++) {
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

        // use constructor that sets cb_mask to 0xFF, or it's not really tainted
        TaintData td = TaintData(ls);

        labels[addr] = td;
    }

    void remove(uint64_t addr, uint64_t remove_size) override
    {
        bool change = false;
        if (track_taint_state && range_tainted(addr, remove_size)) {
            change = true;
        }
        for (uint64_t cur = addr; cur < addr + remove_size; cur++) {
             labels.erase(cur);
        }

        if (change) {
            taint_state_changed(this, addr, remove_size);
        }
    }

    void remove_quiet(uint64_t addr, uint64_t remove_size) override
    {
        for (uint64_t cur = addr; cur < (addr + remove_size); cur++) {
             labels.erase(cur);
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

    TaintData *query_full(uint64_t addr) override
    {
        return &labels[addr];
    }

    bool set_full(uint64_t addr, TaintData td) override
    {
        bool changed = false;
        uint32_t newcard = 0;
        if (td.ls != NULL) newcard = td.ls->size();
        if (((max_tcn == 0) || (td.tcn <= max_tcn)) &&
            ((max_taintset_card == 0) || (newcard <= max_taintset_card)))
        {
            bool change = !(td == *query_full(addr));
            labels[addr] = td;
            
            if (change) taint_state_changed(this, addr, 1);
            changed |= change;
        }
        else
        {
            // delete taint, if there is any, as things have gone too far
            if (range_tainted(addr, 1))
            {
                // remove will take care of taint_state_changed, unless they
                // don't care to be informed of removals
                remove(addr, 1);
            }
        }
        return changed;
    }

    // Set taint quietly - ie. no taint change report is made
    void set_full_quiet(uint64_t addr, TaintData td) override
    {
        labels[addr] = td;
    }

    uint32_t query_tcn(uint64_t addr) override
    {
        return query_full(addr)->tcn;
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
