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

#include <stdio.h>

#include "panda_plugin_plugin.h"
#include "panda_memlog.h"
#include "guestarch.h"

#include "my_mem.h"
#include "shad_dir_32.h"
#include "shad_dir_64.h"
#include "max.h"
#include "taint2.h"
#include "network.h"
#include "defines.h"

extern "C" {

#include "fast_shad.h"

}

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
    Addr ra = {
        .typ = GREG,
        .val = { .gr = r },
        .off = off,
        .flag = (AddrFlag) 0
    };
    return ra;
}

/*
   Initialize the shadow memory for taint processing.
 */
Shad *tp_init() {
    //    Shad *shad = (Shad *) my_malloc(sizeof(Shad), poolid_taint_processor);
    void *tmp = my_malloc(sizeof(Shad), poolid_taint_processor);
    Shad *shad = new(tmp) Shad;
    shad->port_size = 0xffff * 4; // assume a max port size of 4 bytes,
        // and 0xffff max ports according to Intel manual
    shad->num_vals = MAXFRAMESIZE;
    shad->guest_regs = NUMREGS;
    shad->hd = shad_dir_new_64(12,12,16);
    shad->ram = fast_shad_new(ram_size);
    shad->io = shad_dir_new_64(12,12,16);
    shad->ports = shad_dir_new_32(10,10,12);

    // we're working with LLVM values that can be up to 128 bits
    shad->llv = fast_shad_new(MAXFRAMESIZE * FUNCTIONFRAMES * MAXREGSIZE);
    shad->ret = fast_shad_new(MAXREGSIZE);
    // guest registers are generally the size of the guest architecture
    shad->grv = fast_shad_new(NUMREGS * WORDSIZE);
    shad->gsv = fast_shad_new(sizeof(CPUState));

    return shad;
}


/*
 * Delete a shadow memory
 */
void tp_free(Shad *shad){
    shad_dir_free_64(shad->hd);
    fast_shad_free(shad->ram);
    shad_dir_free_64(shad->io);
    shad_dir_free_32(shad->ports);
    fast_shad_free(shad->llv);
    fast_shad_free(shad->ret);
    fast_shad_free(shad->grv);
    fast_shad_free(shad->gsv);
    my_free(shad, sizeof(Shad), poolid_taint_processor);
}

// returns a copy of the labelset associated with a.  or NULL if none.
// so you'll need to call labelset_free on this pointer when done with it.
LabelSetP tp_labelset_get(Shad *shad, Addr *a) {
    assert(shad != NULL);
    switch (a->typ) {
        case HADDR:
            return shad_dir_find_64(shad->hd, a->val.ha+a->off);
        case MADDR:
            return fast_shad_query(shad->ram, a->val.ma+a->off);
        case IADDR:
            return shad_dir_find_64(shad->io, a->val.ia+a->off);
        case PADDR:
            return shad_dir_find_32(shad->ports, a->val.pa+a->off);
        case LADDR:
            return fast_shad_query(shad->llv, a->val.la*MAXREGSIZE + a->off);
        case GREG:
            return fast_shad_query(shad->grv, a->val.gr * WORDSIZE + a->off);
        case GSPEC:
            // SpecAddr enum is offset by the number of guest registers
            return fast_shad_query(shad->gsv, a->val.gs - NUMREGS + a->off);
        case CONST:
            return NULL;
        case RET:
            return fast_shad_query(shad->ret, a->off);
        default:
            assert(false);
    }
    return NULL;
}

extern "C" {
static void set_insert(uint32_t l, void *label_set_opaque);
}
static void set_insert(uint32_t l, void *label_set_opaque) {
    std::set<uint32_t> *label_set =
        reinterpret_cast<std::set<uint32_t> *>(label_set_opaque);
    label_set->insert(l);
}

// returns std::set of labels.
std::set<uint32_t> tp_query(Shad *shad, Addr *a) {
    assert (shad != NULL);
    LabelSetP ls = tp_labelset_get(shad, a);

    std::set<uint32_t> result;
    label_set_iter(ls, set_insert, &result);

    return result;
}

// returns label set cardinality
uint32_t tp_query_ram(Shad *shad, uint64_t pa) {
    Addr a = make_maddr(pa);
    return tp_query(shad, &a).size();
}

// returns label set cardinality
uint32_t tp_query_reg(Shad *shad, int reg_num, int offset) {
    Addr a = make_greg(reg_num, offset);
    return tp_query(shad, &a).size();
}

// untaint -- discard label set associated with a
void tp_delete(Shad *shad, Addr *a) {
    assert (shad != NULL);
    switch (a->typ) {
        case HADDR:
            // NB: just returns if nothing there
            shad_dir_mem_64(shad->hd, a->val.ha+a->off); 
            shad_dir_remove_64(shad->hd, a->val.ha+a->off);
            break;
        case MADDR:
            fast_shad_remove(shad->ram, a->val.ma+a->off,
                    WORDSIZE - a->off);
            break;
        case IADDR:
            shad_dir_remove_64(shad->io, a->val.ia+a->off);
            break;
        case PADDR:
            shad_dir_remove_32(shad->ports, a->val.pa+a->off);
            break;
        case LADDR:
            fast_shad_remove(shad->llv, a->val.la*MAXREGSIZE + a->off,
                    MAXREGSIZE - a->off);
            break;
        case GREG:
            fast_shad_remove(shad->grv, a->val.gr * WORDSIZE + a->off,
                    WORDSIZE - a->off);
            break;
        case GSPEC:
            fast_shad_remove(shad->gsv, a->val.gs - NUMREGS + a->off,
                    WORDSIZE - a->off);
            break;
        case RET:
            fast_shad_remove(shad->ret, a->off, MAXREGSIZE);
            break;
        default:
            assert (1==0);
    }
}


// here we are storing a copy of ls in the shadow memory.
// so ls is caller's to free
static void tp_labelset_put(Shad *shad, Addr *a, LabelSetP ls) {
    switch (a->typ) {
        case HADDR:
            shad_dir_add_64(shad->hd, a->val.ha + a->off, ls);
#ifdef TAINTDEBUG
            printf("Labelset put on HD: 0x%lx\n", (uint64_t)(a->val.ha + a->off));
            //labelset_spit(ls);
            printf("\n");
#endif
            break;
        case MADDR:
            fast_shad_set(shad->ram, a->val.ma + a->off, ls);
#ifdef TAINTDEBUG
            printf("Labelset put in RAM: 0x%lx\n", (uint64_t)(a->val.ma + a->off));
            //labelset_spit(ls);
            printf("\n");
#endif
            break;
        case IADDR:
#ifdef TAINTDEBUG
            printf("Labelset put in IO: 0x%lx\n", (uint64_t)(a->val.ia + a->off));
            //labelset_spit(ls);
            printf("\n");
#endif
            shad_dir_add_64(shad->io, a->val.ia + a->off, ls);
            break;
        case PADDR:
#ifdef TAINTDEBUG
            printf("Labelset put in port: 0x%lx\n", (uint64_t)(a->val.pa + a->off));
            //labelset_spit(ls);
            printf("\n");
#endif
            shad_dir_add_32(shad->ports, a->val.pa + a->off, ls);
            break;
        case LADDR:
#ifdef TAINTDEBUG
            printf("Labelset put in LA: 0x%lx\n", (uint64_t)(a->val.la+a->off));
            //labelset_spit(ls);
            printf("\n");
#endif
            fast_shad_set(shad->llv, a->val.la*MAXREGSIZE + a->off, ls);
            break;
        case GREG:
#ifdef TAINTDEBUG
            printf("Labelset put in GR: 0x%lx\n", (uint64_t)(a->val.gr+a->off));
            //labelset_spit(ls);
            printf("\n");
#endif
            // need to call labelset_copy to increment ref count
            fast_shad_set(shad->grv, a->val.gr * WORDSIZE + a->off, ls);
            break;
        case GSPEC:
#ifdef TAINTDEBUG
            printf("Labelset put in GS: 0x%lx\n", (uint64_t)(a->val.gs+a->off));
            //labelset_spit(ls);
            printf("\n");
#endif
            // SpecAddr enum is offset by the number of guest registers
            fast_shad_set(shad->gsv, a->val.gs - NUMREGS + a->off, ls);
            break;
        case RET:
#ifdef TAINTDEBUG
            printf("Labelset put in ret\n");
            //labelset_spit(ls);
            printf("\n");
#endif
            fast_shad_set(shad->ret, a->off, ls);
            break;
        default:
            assert (1==0);
    }
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

    

// label -- associate label l with address a
void tp_label(Shad *shad, Addr *a, uint32_t l) {
    assert (shad != NULL);

    LabelSetP ls = tp_labelset_get(shad, a);
    LabelSetP ls2 = label_set_singleton(l);
    LabelSetP result = label_set_union(ls, ls2);
    tp_labelset_put(shad, a, result);
}

void tp_label_ram(Shad *shad, uint64_t pa, uint32_t l) {
    Addr a = make_maddr(pa);
    tp_label(shad, &a, l);
}

void tp_delete_ram(Shad *shad, uint64_t pa) {
    Addr a = make_maddr(pa);
    tp_delete(shad, &a);
}

void fprintf_addr(Shad *shad, Addr *a, FILE *fp) {
  switch(a->typ) {
  case HADDR:
    fprintf(fp,"h0x%llx", (long long unsigned int) a->val.ha+a->off);
    break;
  case MADDR:
    fprintf(fp,"m0x%llx", (long long unsigned int) a->val.ma+a->off);
    break;
  case IADDR:
    fprintf(fp,"i0x%llx", (long long unsigned int) a->val.ia+a->off);
    break;
  case PADDR:
    fprintf(fp,"p0x%llx", (long long unsigned int) a->val.pa+a->off);
    break;
  case LADDR:
    if (a->flag == FUNCARG){
      fprintf(fp,"l%lld[%d]", 
	      (long long unsigned int) a->val.la, a->off);
    }
    else {
      fprintf(fp,"l%lld[%d]",
	      (long long unsigned int) a->val.la, a->off);
    }
    break;
  case GREG:
    fprintf_reg(a, fp);
    break;
  case GSPEC:
    fprintf_spec(a, fp);
    break;
  case UNK:
    if (a->flag == IRRELEVANT){
      fprintf(fp,"irrelevant");
    }
    //else if (a->flag == READLOG) {
    else if (a->typ == UNK){ 
      fprintf(fp,"unknown");
    }
    else {
      assert(1==0);
    }
    break;
  case CONST:
    fprintf(fp,"constant");
    break;
  case RET:
    fprintf(fp,"ret[%d]", a->off);
    break;
  default:
    assert (1==0);
  }
}

void print_addr(Shad *shad, Addr *a) {
  fprintf_addr(shad, a, stdout);
}
