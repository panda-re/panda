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

#include "shad_dir_32.h"
#include "shad_dir_64.h"
#include "max.h"
#include "taint2.h"
#include "network.h"
#include "defines.h"
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
Shad *tp_init(TaintLabelMode mode, TaintGranularity granularity) {
    //    Shad *shad = (Shad *) my_malloc(sizeof(Shad), poolid_taint_processor);
    void *tmp = malloc(sizeof(Shad));
    Shad *shad = new(tmp) Shad;
    shad->port_size = 0xffff * 4; // assume a max port size of 4 bytes,
        // and 0xffff max ports according to Intel manual
    shad->num_vals = MAXFRAMESIZE;
    shad->guest_regs = NUMREGS;
    shad->hd = shad_dir_new_64(12,12,16);
    shad->io = shad_dir_new_64(12,12,16);
    shad->ports = shad_dir_new_32(10,10,12);

    shad->granularity = granularity;
    shad->mode = mode;

    if (granularity == TAINT_GRANULARITY_BYTE) {
        printf("taint2: Creating byte-level taint processor\n");
        shad->ram = new FastShad(ram_size);
        // we're working with LLVM values that can be up to 128 bits
        shad->llv = new FastShad(MAXFRAMESIZE * FUNCTIONFRAMES * MAXREGSIZE);
        shad->ret = new FastShad(MAXREGSIZE);
        // guest registers are generally the size of the guest architecture
        shad->grv = new FastShad(NUMREGS * WORDSIZE);
    } else {
        printf("taint2: Creating word-level taint processor\n");
        shad->ram = new FastShad(ram_size / WORDSIZE);
        shad->llv = new FastShad(MAXFRAMESIZE * FUNCTIONFRAMES);
        shad->ret = new FastShad(1);
        shad->grv = new FastShad(NUMREGS);
    }

    shad->gsv = new FastShad(sizeof(CPUState));

    return shad;
}


/*
 * Delete a shadow memory
 */
void tp_free(Shad *shad){
    shad_dir_free_64(shad->hd);
    delete shad->ram;
    shad_dir_free_64(shad->io);
    shad_dir_free_32(shad->ports);
    delete shad->llv;
    delete shad->ret;
    delete shad->grv;
    delete shad->gsv;
    free(shad);
}

// returns a copy of the labelset associated with a.  or NULL if none.
// so you'll need to call labelset_free on this pointer when done with it.
LabelSetP tp_labelset_get(Shad *shad, Addr *a) {
    assert(shad != NULL);
    switch (a->typ) {
        case HADDR:
            return shad_dir_find_64(shad->hd, a->val.ha+a->off);
        case MADDR:
            return shad->ram->query(a->val.ma+a->off);
        case IADDR:
            return shad_dir_find_64(shad->io, a->val.ia+a->off);
        case PADDR:
            return shad_dir_find_32(shad->ports, a->val.pa+a->off);
        case LADDR:
            return shad->llv->query(a->val.la*MAXREGSIZE + a->off);
        case GREG:
            return shad->grv->query(a->val.gr * WORDSIZE + a->off);
        case GSPEC:
            // SpecAddr enum is offset by the number of guest registers
            return shad->gsv->query(a->val.gs - NUMREGS + a->off);
        case CONST:
            return NULL;
        case RET:
            return shad->ret->query(a->off);
        default:
            assert(false);
    }
    return NULL;
}


uint32_t tp_tcn_get(Shad *shad, Addr a) {
    assert(shad != NULL);
    switch (a.typ) {
    case HADDR:
        // TRL FIXME
        return 0; // had_dir_find_64(shad->hd, a.val.ha+a.off);
    case MADDR:
        return shad->ram->query_tcn(a.val.ma+a.off);
    case IADDR:
        // TRL FIXME
        return 0; // shad_dir_find_64(shad->io, a.val.ia+a.off);
    case PADDR:
        // TRL FIXME
        return 0; //        return shad_dir_find_32(shad->ports, a.val.pa+a.off);        
    case LADDR:
        return shad->llv->query_tcn(a.val.la*MAXREGSIZE + a.off);
    case GREG:
        return shad->grv->query_tcn(a.val.gr * WORDSIZE + a.off);
    case GSPEC:
        // SpecAddr enum is offset by the number of guest registers                                                                                                                             
        return shad->gsv->query_tcn(a.val.gs - NUMREGS + a.off);
    case CONST:
        return 0;
    case RET:
        return shad->ret->query_tcn(a.off);
    default:
        assert(false);
    }
    return 0;
}




// returns std::set of labels.
LabelSetP tp_query(Shad *shad, Addr a) {
    assert (shad != NULL);
    LabelSetP ls = tp_labelset_get(shad, &a);
    return ls;
}


// returns rendered label set 
LabelSetP tp_query_ram(Shad *shad, uint64_t pa) {
    Addr a = make_maddr(pa);
    return tp_query(shad, a);
}

// returns rendered label set 
LabelSetP tp_query_reg(Shad *shad, int reg_num, int offset) {
    Addr a = make_greg(reg_num, offset);
    return tp_query(shad, a);
}

// returns rendered label set
LabelSetP tp_query_llvm(Shad *shad, int reg_num, int offset) {
    Addr a = make_laddr(reg_num, offset);
    return tp_query(shad, a);
}

// returns taint compute # 
uint32_t tp_query_tcn(Shad *shad, Addr a) {
    assert (shad != NULL);
    return tp_tcn_get(shad, a);
}

uint32_t tp_query_tcn_ram(Shad *shad, uint64_t pa) {
    Addr a = make_maddr(pa);
    return tp_query_tcn(shad, a);
}

uint32_t tp_query_tcn_reg(Shad *shad, int reg_num, int offset) {
    Addr a = make_greg(reg_num, offset);
    return tp_query_tcn(shad, a);
}

uint32_t tp_query_tcn_llvm(Shad *shad, int reg_num, int offset) {
    Addr a = make_laddr(reg_num, offset);
    return tp_query_tcn(shad, a);
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

void tp_ls_a_iter(Shad *shad, Addr *a, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    // retrieve the tree-representation of the 
    LabelSetP ls = tp_labelset_get(shad, a);
    if (ls == NULL) return;
    tp_ls_iter(ls, app, stuff2);
}

void tp_ls_ram_iter(Shad *shad, uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    Addr a = make_maddr(pa);    
    tp_ls_a_iter(shad, &a, app, stuff2);
}

void tp_ls_reg_iter(Shad *shad, int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    Addr a = make_greg(reg_num, offset);
    tp_ls_a_iter(shad, &a, app, stuff2);
}

void tp_ls_llvm_iter(Shad *shad, int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    Addr a = make_laddr(reg_num, offset);
    tp_ls_a_iter(shad, &a, app, stuff2);
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
            shad->ram->remove(a->val.ma+a->off,
                    WORDSIZE - a->off);
            break;
        case IADDR:
            shad_dir_remove_64(shad->io, a->val.ia+a->off);
            break;
        case PADDR:
            shad_dir_remove_32(shad->ports, a->val.pa+a->off);
            break;
        case LADDR:
            shad->llv->remove(a->val.la*MAXREGSIZE + a->off,
                    MAXREGSIZE - a->off);
            break;
        case GREG:
            shad->grv->remove(a->val.gr * WORDSIZE + a->off,
                    WORDSIZE - a->off);
            break;
        case GSPEC:
            shad->gsv->remove(a->val.gs - NUMREGS + a->off,
                    WORDSIZE - a->off);
            break;
        case RET:
            shad->ret->remove(a->off, MAXREGSIZE);
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
            taint_log("Labelset put on HD: 0x%lx\n", (uint64_t)(a->val.ha + a->off));
            //labelset_spit(ls);
#endif
            break;
        case MADDR:
            shad->ram->label(a->val.ma + a->off, ls);
#ifdef TAINTDEBUG
            taint_log("Labelset put in RAM: 0x%lx\n", (uint64_t)(a->val.ma + a->off));
            //labelset_spit(ls);
#endif
            break;
        case IADDR:
#ifdef TAINTDEBUG
            taint_log("Labelset put in IO: 0x%lx\n", (uint64_t)(a->val.ia + a->off));
            //labelset_spit(ls);
#endif
            shad_dir_add_64(shad->io, a->val.ia + a->off, ls);
            break;
        case PADDR:
#ifdef TAINTDEBUG
            taint_log("Labelset put in port: 0x%lx\n", (uint64_t)(a->val.pa + a->off));
            //labelset_spit(ls);
#endif
            shad_dir_add_32(shad->ports, a->val.pa + a->off, ls);
            break;
        case LADDR:
#ifdef TAINTDEBUG
            taint_log("Labelset put in LA: 0x%lx\n", (uint64_t)(a->val.la+a->off));
            //labelset_spit(ls);
#endif
            shad->llv->label(a->val.la*MAXREGSIZE + a->off, ls);
            break;
        case GREG:
#ifdef TAINTDEBUG
            taint_log("Labelset put in GR: 0x%lx\n", (uint64_t)(a->val.gr+a->off));
            //labelset_spit(ls);
#endif
            // need to call labelset_copy to increment ref count
            shad->grv->label(a->val.gr * WORDSIZE + a->off, ls);
            break;
        case GSPEC:
#ifdef TAINTDEBUG
            taint_log("Labelset put in GS: 0x%lx\n", (uint64_t)(a->val.gs+a->off));
            //labelset_spit(ls);
#endif
            // SpecAddr enum is offset by the number of guest registers
            shad->gsv->label(a->val.gs - NUMREGS + a->off, ls);
            break;
        case RET:
#ifdef TAINTDEBUG
            taint_log("Labelset put in ret\n");
            //labelset_spit(ls);
#endif
            shad->ret->label(a->off, ls);
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


// used to keep track of labels that have been applied
std::set < uint32_t > labels_applied;

// label -- associate label l with address a
void tp_label(Shad *shad, Addr *a, uint32_t l) {
    assert (shad != NULL);
    LabelSetP ls = label_set_singleton(l);
    tp_labelset_put(shad, a, ls);
    labels_applied.insert(l);
}


// returns set of so-far applied labels as a sorted array
// NB: This allocates memory. Caller frees.
uint32_t *tp_labels_applied(void) {
    uint32_t *labels = (uint32_t *) malloc(sizeof(uint32_t) * labels_applied.size());
    uint32_t i=0;
    for ( auto el : labels_applied ) {
        labels[i] = el;
        i++;
    }
    return labels;
}

uint32_t tp_num_labels_applied(void) {
    return labels_applied.size();
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
