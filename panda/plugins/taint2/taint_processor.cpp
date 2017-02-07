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

/* This file is present mainly for compatibility with the old parts of the
 * taint system - we've mostly left in place hard drive taint, etc.
 */

#include <cstdint>
#include <cstdio>

#include <set>

#include "shad_dir_32.h"
#include "shad_dir_64.h"
#include "taint2.h"
#include "taint_defines.h"
#include "fast_shad.h"

Addr make_haddr(uint64_t a) {
    Addr ha;
    ha.typ = HADDR;
    ha.val.ha = a;
    ha.off = 0;
    ha.flag = (AddrFlag) 0;
    return ha;
}

Addr make_maddr(uint64_t a) {
    Addr ma;
    ma.typ = MADDR;
    ma.val.ma = a;
    ma.off = 0;
    ma.flag = (AddrFlag) 0;
    return ma;
}

Addr make_laddr(uint64_t a, uint64_t o) {
    Addr la;
    la.typ = LADDR;
    la.val.la = a;
    la.off = o;
    la.flag = (AddrFlag) 0;
    return la;
}

Addr make_iaddr(uint64_t a) {
    Addr ia;
    ia.typ = IADDR;
    ia.val.ia = a;
    ia.off = 0;
    ia.flag = (AddrFlag) 0;
    return ia;
}

Addr make_paddr(uint64_t a) {
    Addr pa;
    pa.typ = PADDR;
    pa.val.pa = a;
    pa.off = 0;
    pa.flag = (AddrFlag) 0;
    return pa;
}

Addr make_greg(uint64_t r, uint16_t off) {
    Addr a;
    a.typ = GREG;
    a.val.gr = r;
    a.off = off;
    a.flag = (AddrFlag) 0;
    return a;
}

extern ShadowState *shadow;

// returns a copy of the labelset associated with a.  or NULL if none.
// so you'll need to call labelset_free on this pointer when done with it.
static inline LabelSetP tp_labelset_get(const Addr &a) {
    assert(shadow);
    auto loc = shadow->query_loc(a);
    return loc.first ? loc.first->query(loc.second) : nullptr;
}

TaintData tp_query_full(const Addr &a) {
    assert(shadow);
    auto loc = shadow->query_loc(a);
    return loc.first ? loc.first->query_full(loc.second) : TaintData();
}

// untaint -- discard label set associated with a
void tp_delete(const Addr &a) {
    assert(shadow);
    auto loc = shadow->query_loc(a);
    if (loc.first) loc.first->remove(loc.second, 1);
}

static void tp_labelset_put(const Addr &a, LabelSetP ls) {
    assert(shadow);
    auto loc = shadow->query_loc(a);
    if (loc.first) loc.first->set_full(loc.second, TaintData(ls));
}

// returns std::set of labels.
LabelSetP tp_query(Addr a) {
    return tp_labelset_get(a);
}

// returns rendered label set
LabelSetP tp_query_ram(uint64_t pa) {
    return tp_query(make_maddr(pa));
}

// returns rendered label set
LabelSetP tp_query_reg(int reg_num, int offset) {
    return tp_query(make_greg(reg_num, offset));
}

// returns rendered label set
LabelSetP tp_query_llvm(int reg_num, int offset) {
    return tp_query(make_laddr(reg_num, offset));
}

// returns taint compute #
uint32_t tp_query_tcn(Addr a) {
    return tp_query_full(a).tcn;
}

uint32_t tp_query_tcn_ram(uint64_t pa) {
    return tp_query_tcn(make_maddr(pa));
}

uint32_t tp_query_tcn_reg(int reg_num, int offset) {
    return tp_query_tcn(make_greg(reg_num, offset));
}

uint32_t tp_query_tcn_llvm(int reg_num, int offset) {
    return tp_query_tcn(make_laddr(reg_num, offset));
}

// returns CB mask.
uint64_t tp_query_cb_mask(Addr a, uint8_t size) {
    uint64_t cb_mask = 0;
    for (unsigned i = 0; i < size; i++, a.off++) {
        cb_mask |= tp_query_full(a).cb_mask << (i * 8);
    }
    return cb_mask;
}

uint32_t ls_card(LabelSetP ls) {
    return label_set_render_set(ls).size();
}

// iterate over
void tp_lsr_iter(std::set<uint32_t> rendered, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    for (uint32_t el : rendered) {
        //        printf ("el=%d\n", el);
        if ((app(el, stuff2)) != 0) break;
    }
}

// retrieve ls for this addr
void tp_ls_iter(LabelSetP ls, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    std::set<uint32_t> rendered = label_set_render_set(ls);
    tp_lsr_iter(rendered, app, stuff2);
}

void tp_ls_a_iter(Addr a, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    // retrieve the tree-representation of the
    LabelSetP ls = tp_labelset_get(a);
    if (ls == NULL) return;
    tp_ls_iter(ls, app, stuff2);
}

void tp_ls_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    Addr a = make_maddr(pa);
    tp_ls_a_iter(a, app, stuff2);
}

void tp_ls_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    Addr a = make_greg(reg_num, offset);
    tp_ls_a_iter(a, app, stuff2);
}

void tp_ls_llvm_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    Addr a = make_laddr(reg_num, offset);
    tp_ls_a_iter(a, app, stuff2);
}

void addr_spit(Addr *a) {
  switch (a->typ) {
  case HADDR:    printf ("(h%lx", a->val.ha);    break;
  case MADDR:    printf ("(m%lx", a->val.ma);    break;
  case IADDR:    printf ("(i%lx", a->val.ia);    break;
  case PADDR:    printf ("(p%lx", a->val.pa);    break;
  case LADDR:    printf ("(l%lx", a->val.la);    break;
  case GREG:     printf ("(r%lx", a->val.gr);    break;
  case GSPEC:    printf ("(s%lx", a->val.gs);    break;
  case UNK:      printf ("(u");    break;
  case CONST:    printf ("(c");    break;
  case RET:      printf ("(r");    break;
  default: assert (1==0);
  }
  printf (",%d,%x)", a->off, a->flag);
}

// used to keep track of labels that have been applied
std::set<uint32_t> labels_applied;

// label -- associate label l with address a
void tp_label(Addr a, uint32_t l) {
    assert (shad != NULL);
    LabelSetP ls = label_set_singleton(l);
    tp_labelset_put(a, ls);
    labels_applied.insert(l);
}

uint32_t tp_num_labels_applied(void) {
    return labels_applied.size();
}

void tp_label_ram(uint64_t pa, uint32_t l) {
    Addr a = make_maddr(pa);
    tp_label(a, l);
}

void tp_label_reg(int reg_num, int offset, uint32_t l) {
    Addr a = make_greg(reg_num, offset);
    tp_label(a, l);
}

void tp_delete_ram(uint64_t pa) {
    Addr a = make_maddr(pa);
    tp_delete(a);
}

void tp_delete_reg(int reg_num, int offset) {
    Addr a = make_greg(reg_num, offset);
    tp_delete(a);
}
