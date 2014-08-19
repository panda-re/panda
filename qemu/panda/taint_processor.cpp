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

#include <stdio.h>
#include "my_mem.h"
#include "my_bool.h"
#include "bitvector_label_set.cpp"
#include "shad_dir_32.h"
#include "shad_dir_64.h"
#include "max.h"
#include "guestarch.h"
#include "taint_processor.h"
#include "panda_memlog.h"
#include "panda/network.h"
#include "panda/panda_stats.h"

#define SB_INLINE inline

#ifdef TAINTSTATS
// Bool for whether or not the function operates on tainted data
uint8_t taintedfunc;
#endif

/* XXX: Note, there is currently only support for copying taint into a new stack
 * frame, i.e. through tp_copy() and tp_delete(), not anything else.
 */

// stuff for control flow in traces
int next_step;
int previous_branch; // keep a history of 1
int taken_branch;


uint32_t max_taintset_card = 0;
uint32_t max_taintset_compute_number = 0;

uint32_t max_ref_count = 0;

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

// if addr is one of HAddr, MAddr, IAddr, PAddr, LAddr, then add this offset to it
// else throw up
static Addr addr_add(Addr a, uint32_t o) {
  switch (a.typ) {
  case HADDR:
    a.val.ha += o;
    break;
  case MADDR:
    a.val.ma += o;
    break;
  case IADDR:
    a.val.ia += o;
    break;
  case PADDR:
    a.val.pa += o;
    break;
  default:
    // Thou shalt not.
    printf ("You called addr_add with an Addr other than HADDR, MADDR, IADDR, PADDR.  That isn't meaningful.\n");
    assert (1==0);
    break;
  }
  return a;
}


// increment addr a in place
static void addr_inc(Addr *a) {
  switch (a->typ) {
  case HADDR:
    a->val.ha++;
    break;
  case MADDR:
    a->val.ma++;
    break;
  case IADDR:
    a->val.ia++;
    break;
  case PADDR:
    a->val.pa++;
    break;
  default:
    // Thou shalt not.
    printf ("You called addr_add with an Addr other than HADDR, MADDR, IADDR, PADDR.  That isn't meaningful.\n");
    assert (1==0);
    break;
  }
}



SB_INLINE uint8_t get_ram_bit(Shad *shad, uint32_t addr) {
    uint8_t taint_byte = shad->ram_bitmap[addr >> 3];
    return (taint_byte & (1 << (addr & 7)));
}


static SB_INLINE void set_ram_bit(Shad *shad, uint32_t addr) {
    uint8_t taint_byte = shad->ram_bitmap[addr >> 3];
    taint_byte |= (1 << (addr & 7));
    shad->ram_bitmap[addr >> 3] = taint_byte;
}


static SB_INLINE void clear_ram_bit(Shad *shad, uint32_t addr) {
    uint8_t taint_byte = shad->ram_bitmap[addr >> 3];
    taint_byte &= (~(1 << (addr & 7)));
    shad->ram_bitmap[addr >> 3] = taint_byte;
}


/*
   Initialize the shadow memory for taint processing.
   hd_size -- size of hd in bytes
   mem_size -- size of ram in bytes
   io_size -- max address an io buffer address can be
   max_vals -- max number of numbered llvm values we'll need
 */
Shad *tp_init(uint64_t hd_size, uint32_t mem_size, uint64_t io_size,
        uint32_t max_vals) {
    Shad *shad = (Shad *) my_malloc(sizeof(Shad), poolid_taint_processor);
    shad->hd_size = hd_size;
    shad->mem_size = mem_size;
    shad->io_size = io_size;
    shad->port_size = 0xffff * 4; // assume a max port size of 4 bytes,
        // and 0xffff max ports according to Intel manual
    shad->num_vals = max_vals;
    shad->guest_regs = NUMREGS;
    shad->hd = shad_dir_new_64(12,12,16);
#ifdef TARGET_X86_64
    shad->ram = shad_dir_new_64(12,12,16);
#else
    shad->ram = shad_dir_new_32(10,10,12);
#endif
    shad->io = shad_dir_new_64(12,12,16);
    shad->ports = shad_dir_new_32(10,10,12);

    // we're working with LLVM values that can be up to 128 bits
    shad->llv = (LabelSet **) my_calloc(max_vals * FUNCTIONFRAMES * MAXREGSIZE,
            sizeof(LabelSet *), poolid_taint_processor);
    shad->ret = (LabelSet **) my_calloc(1 * MAXREGSIZE,
            sizeof(LabelSet *), poolid_taint_processor);
    // guest registers are generally the size of the guest architecture
    shad->grv = (LabelSet **) my_calloc(NUMREGS * WORDSIZE,
            sizeof(LabelSet *), poolid_taint_processor);
    // architecture-dependent size defined in guestarch.h
    if (NUMSPECADDRS){
        /*
         * +NUMREGS is necessary offset for how we process these according to
         * enums
         */
        shad->gsv = (LabelSet **) my_calloc(NUMSPECADDRS+NUMREGS,
            sizeof(LabelSet*), poolid_taint_processor);
    }
    else {
        shad->gsv = NULL;
    }
    shad->ram_bitmap = (uint8_t *) my_calloc(mem_size >> 3, 1,
            poolid_taint_processor);
    shad->current_frame = 0;
    return shad;
}


/*
 * Delete a shadow memory
 */
void tp_free(Shad *shad){
    shad_dir_free_64(shad->hd);
    shad->hd = NULL;
#ifdef TARGET_X86_64
    shad_dir_free_64(shad->ram);
#else
    shad_dir_free_32(shad->ram);
#endif
    shad->ram = NULL;
    shad_dir_free_64(shad->io);
    shad->io = NULL;
    shad_dir_free_32(shad->ports);
    shad->ports = NULL;
    my_free(shad->llv, (shad->num_vals * FUNCTIONFRAMES * MAXREGSIZE *
        sizeof(LabelSet *)), poolid_taint_processor);
    shad->llv = NULL;
    my_free(shad->ret, (MAXREGSIZE * sizeof(LabelSet *)),
        poolid_taint_processor);
    shad->ret = NULL;
    my_free(shad->grv, (NUMREGS * WORDSIZE * sizeof(LabelSet *)),
        poolid_taint_processor);
    shad->grv = NULL;
    if (shad->gsv){
        my_free(shad->gsv, ((NUMSPECADDRS+NUMREGS) * sizeof(LabelSet *)),
            poolid_taint_processor);
        shad->gsv = NULL;
    }
    my_free(shad->ram_bitmap, (shad->mem_size >> 3), poolid_taint_processor);
    shad->ram_bitmap = NULL;
    my_free(shad, sizeof(Shad), poolid_taint_processor);
    shad = NULL;
}


// returns a copy of the labelset associated with a.  or NULL if none.
// so you'll need to call labelset_free on this pointer when done with it.
static SB_INLINE LabelSet *tp_labelset_get(Shad *shad, Addr *a) {
    LabelSet *ls = NULL;
    switch (a->typ) {
        case HADDR:
            {
                ls = shad_dir_find_64(shad->hd, a->val.ha+a->off);
                break;
            }
        case MADDR:
            {
#ifdef TARGET_X86_64
                /* XXX: this only applies to x86_64 user because the bit array
                 * is too big to represent.  We can still use it for
                 * whole-system though.
                 */
                ls = shad_dir_find_64(shad->ram, a->val.ma+a->off);
#else
                if (get_ram_bit(shad, a->val.ma+a->off)) {
                    ls = shad_dir_find_32(shad->ram, a->val.ma+a->off);
                }
#endif
                break;
            }
        case IADDR:
            {
                ls = shad_dir_find_64(shad->io, a->val.ia+a->off);
                break;
            }
        case PADDR:
            {
                ls = shad_dir_find_32(shad->ports, a->val.ia+a->off);
                break;
            }
        // multipliers are for register and stack frame indexing in shadow
        // register space
        case LADDR:
            {
                if (a->flag == FUNCARG){
                    assert((shad->current_frame + 1) < FUNCTIONFRAMES);
                    ls = labelset_copy(
                        shad->llv[shad->num_vals*(shad->current_frame + 1) +
                                  a->val.la*MAXREGSIZE +
                                  a->off]);
                }
                else {
                    assert(shad->current_frame < FUNCTIONFRAMES);
                    ls = labelset_copy(
                        shad->llv[shad->num_vals*shad->current_frame +
                                  a->val.la*MAXREGSIZE +
                                  a->off]);
                }
                break;
            }
        case GREG:
            {
                ls = labelset_copy(shad->grv[a->val.gr * WORDSIZE + a->off]);
                break;
            }
        case GSPEC:
            {
                // SpecAddr enum is offset by the number of guest registers
                ls = labelset_copy(shad->gsv[a->val.gs - NUMREGS + a->off]);
                break;
            }
        case CONST:
            {
                ls = NULL;
                break;
            }
        case RET:
            {
                ls = labelset_copy(shad->ret[a->off]);
                break;
            }
        default:
            assert (1==0);
    }
    return ls;
}


// returns TRUE (1) iff a has a non-empty taint set
SB_INLINE uint8_t tp_query(Shad *shad, Addr *a) {
    assert (shad != NULL);
    LabelSet *ls = tp_labelset_get(shad, a);
    return !(labelset_is_empty(ls));
}


// untaint -- discard label set associated with a
SB_INLINE void tp_delete(Shad *shad, Addr *a) {

    assert (shad != NULL);
    switch (a->typ) {
        case HADDR:
            {
                // NB: just returns if nothing there
                shad_dir_remove_64(shad->hd, a->val.ha+a->off);
                break;
            }
        case MADDR:
            {
#ifdef TARGET_X86_64
                /* XXX: this only applies to x86_64 user because the bit array
                 * is too big to represent.  We can still use it for
                 * whole-system though.
                 */
                shad_dir_remove_64(shad->ram, a->val.ma+a->off);
#else
                if (get_ram_bit(shad, a->val.ma+a->off)) {
                    shad_dir_remove_32(shad->ram, a->val.ma+a->off);
                    clear_ram_bit(shad, a->val.ma+a->off);
                }
#endif
                break;
            }
        case IADDR:
            {
                shad_dir_remove_64(shad->io, a->val.ia+a->off);
                break;
            }
        case PADDR:
            {
                shad_dir_remove_32(shad->ports, a->val.ia+a->off);
                break;
            }
        case LADDR:
            {
                if (a->flag == FUNCARG){
                    // free the labelset and remove reference
                    LabelSet *ls =
                        shad->llv[shad->num_vals*(shad->current_frame + 1) +
                                  a->val.la*MAXREGSIZE +
                                  a->off];
                    labelset_free(ls);
                    shad->llv[shad->num_vals*(shad->current_frame + 1) +
                              a->val.la*MAXREGSIZE +
                              a->off] = NULL;
                }
                else {
                    // free the labelset and remove reference
                    LabelSet *ls =
                        shad->llv[shad->num_vals*shad->current_frame +
                                  a->val.la*MAXREGSIZE +
                                  a->off];
                    labelset_free(ls);
                    shad->llv[shad->num_vals*shad->current_frame +
                              a->val.la*MAXREGSIZE +
                              a->off] = NULL;
                }
                break;
            }
        case GREG:
            {
                // free the labelset and remove reference
                LabelSet *ls = shad->grv[a->val.gr * WORDSIZE + a->off];
                labelset_free(ls);
                shad->grv[a->val.gr * WORDSIZE + a->off] = NULL;
                break;
            }
        case GSPEC:
            {
                // SpecAddr enum is offset by the number of guest registers
                LabelSet *ls = shad->gsv[a->val.gs - NUMREGS + a->off];
                labelset_free(ls);
                shad->gsv[a->val.gs - NUMREGS + a->off] = NULL;
                break;
            }
        case RET:
            {
                LabelSet *ls = shad->ret[a->off];
                labelset_free(ls);
                shad->ret[a->off] = NULL;
                break;
            }
        default:
            assert (1==0);
    }
}


// here we are storing a copy of ls in the shadow memory.
// so ls is caller's to free
static SB_INLINE void tp_labelset_put(Shad *shad, Addr *a, LabelSet *ls) {
    assert (shad != NULL);
    tp_delete(shad, a);


    if ((max_taintset_compute_number != 0) && (ls->type > max_taintset_compute_number)) {
      // discard taint set that has become computationally too distant from input
      return;
    }

    if ((max_taintset_card !=0) && (labelset_card(ls) > max_taintset_card)) {
      // discard taint set with cardinality too high
      return;
    }


#ifdef TAINTSTATS
    taintedfunc = 1;
#endif

    switch (a->typ) {
        case HADDR:
            {

                shad_dir_add_64(shad->hd, a->val.ha + a->off, ls);
#ifdef TAINTDEBUG
                printf("Labelset put on HD: 0x%lx\n", (uint64_t)(a->val.ha + a->off));
                labelset_spit(ls);
                printf("\n");
#endif

                break;
            }
        case MADDR:
            {
#ifdef TARGET_X86_64
                /* XXX: this only applies to x86_64 user because the bit array
                 * is too big to represent.  We can still use it for
                 * whole-system though.
                 */
                shad_dir_add_64(shad->ram, a->val.ma + a->off, ls);
#ifdef TAINTDEBUG
                printf("Labelset put in RAM: 0x%lx\n", (uint64_t)(a->val.ma + a->off));
                labelset_spit(ls);
                printf("\n");
#endif
#else // TARGET_X86_64
                shad_dir_add_32(shad->ram, a->val.ma + a->off, ls);
                set_ram_bit(shad, a->val.ma + a->off);
#endif
                break;
            }
        case IADDR:
            {
#ifdef TAINTDEBUG
                printf("Labelset put in IO: 0x%lx\n", (uint64_t)(a->val.ia + a->off));
                labelset_spit(ls);
                printf("\n");
#endif
                shad_dir_add_64(shad->io, a->val.ia + a->off, ls);
                break;
            }
        case PADDR:
            {
#ifdef TAINTDEBUG
                printf("Labelset put in port: 0x%lx\n", (uint64_t)(a->val.pa + a->off));
                labelset_spit(ls);
                printf("\n");
#endif
                shad_dir_add_32(shad->ports, a->val.pa + a->off, ls);
                break;
            }
        case LADDR:
            {
#ifdef TAINTDEBUG
                printf("Labelset put in LA: 0x%lx\n", (uint64_t)(a->val.la+a->off));
                labelset_spit(ls);
                printf("\n");
#endif
                // need to call labelset_copy to increment ref count
                LabelSet *ls_copy = labelset_copy(ls);
                if (a->flag == FUNCARG){
                    // put in new function frame
                    assert((shad->current_frame + 1) < FUNCTIONFRAMES);
                    shad->llv[shad->num_vals*(shad->current_frame + 1) +
                              a->val.la*MAXREGSIZE +
                              a->off] = ls_copy;
                }
                else {
                    assert(shad->current_frame < FUNCTIONFRAMES);
                    shad->llv[shad->num_vals*shad->current_frame +
                              a->val.la*MAXREGSIZE +
                              a->off] = ls_copy;
                }
                break;
            }
        case GREG:
            {
#ifdef TAINTDEBUG
                printf("Labelset put in GR: 0x%lx\n", (uint64_t)(a->val.gr+a->off));
                labelset_spit(ls);
                printf("\n");
#endif
                // need to call labelset_copy to increment ref count
                LabelSet *ls_copy = labelset_copy(ls);
                shad->grv[a->val.gr * WORDSIZE + a->off] = ls_copy;
                break;
            }
        case GSPEC:
            {
#ifdef TAINTDEBUG
                printf("Labelset put in GS: 0x%lx\n", (uint64_t)(a->val.gs+a->off));
                labelset_spit(ls);
                printf("\n");
#endif
                // SpecAddr enum is offset by the number of guest registers
                LabelSet *ls_copy = labelset_copy(ls);
                shad->gsv[a->val.gs - NUMREGS + a->off] = ls_copy;
                break;
            }
        case RET:
            {
#ifdef TAINTDEBUG
                printf("Labelset put in ret\n");
                labelset_spit(ls);
                printf("\n");
#endif
                LabelSet *ls_copy = labelset_copy(ls);
                shad->ret[a->off] = ls_copy;
                break;
            }
        default:
            assert (1==0);
    }
}

SB_INLINE void addr_spit(Addr *a) {
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
SB_INLINE void tp_label(Shad *shad, Addr *a, Label l) {
    assert (shad != NULL);
    
    /*
    printf ("tp_label ");
    addr_spit(a);
    printf (" %d\n", l);
    */

    LabelSet *ls = tp_labelset_get(shad, a);

    /*
    if (!(labelset_is_empty(ls))) {
      printf ("*** not empty: ");
      labelset_spit(ls);
      printf("\n");
    }      
    
    */


    if (!ls){
        ls = labelset_new();
        labelset_set_type(ls, LST_COPY);
    }
    labelset_add(ls, l);
    
    tp_labelset_put(shad, a, ls);
    labelset_free(ls);
}


SB_INLINE uint8_t addrs_equal(Addr *a, Addr *b) {
    if (a->typ != b->typ)
        return FALSE;
    switch (a->typ) {
        case HADDR:
            return a->val.ha+a->off == b->val.ha+b->off;
        case MADDR:
            return a->val.ma+a->off == b->val.ma+b->off;
        case IADDR:
            return a->val.ia+a->off == b->val.ia+b->off;
        case PADDR:
            return a->val.pa+a->off == b->val.pa+b->off;
        case LADDR:
            return (a->val.la == b->val.la)
                   && (a->off == b->off)
                   && (a->flag == b->flag);
        case GREG:
            return (a->val.gr == b->val.gr) && (a->off == b->off);
        case GSPEC:
            return (a->val.gs == b->val.gs) && (a->off == b->off);
        case RET:
            return (a->off == b->off);
        default:
            assert (1==0);
    }
}


void print_addr(Shad *shad, Addr *a) {
    uint32_t current_frame;
    switch(a->typ) {
        case HADDR:
            printf ("h0x%llx", (long long unsigned int) a->val.ha+a->off);
            break;
        case MADDR:
            printf ("m0x%llx", (long long unsigned int) a->val.ma+a->off);
            break;
        case IADDR:
            printf ("i0x%llx", (long long unsigned int) a->val.ia+a->off);
            break;
        case PADDR:
            printf ("p0x%llx", (long long unsigned int) a->val.pa+a->off);
            break;
        case LADDR:
            if (!shad){
                current_frame = 0; // not executing taint ops, assume frame 0
            }
            else {
                current_frame = shad->current_frame;
            }

            if (a->flag == FUNCARG){
                printf ("[%d]l%lld[%d]", current_frame + 1,
                    (long long unsigned int) a->val.la, a->off);
            }
            else {
                printf ("[%d]l%lld[%d]", current_frame,
                    (long long unsigned int) a->val.la, a->off);
            }
            break;
        case GREG:
            printreg(a);
            break;
        case GSPEC:
            printspec(a);
            break;
        case UNK:
            if (a->flag == IRRELEVANT){
                printf("irrelevant");
            }
            //else if (a->flag == READLOG) {
            else if (a->typ == UNK){
                printf("unknown");
            }
            else {
                assert(1==0);
            }
            break;
        case CONST:
            printf("constant");
            break;
        case RET:
            printf("ret[%d]", a->off);
            break;
        default:
            assert (1==0);
    }
}


// copy -- b gets whatever label set is currently associated with a
SB_INLINE void tp_copy(Shad *shad, Addr *a, Addr *b) {

    assert (shad != NULL);
    //assert (!(addrs_equal(a,b)));
    if (addrs_equal(a, b)) return;
    LabelSet *ls_a = tp_labelset_get(shad, a);
    if (labelset_is_empty(ls_a)) {
        // a not tainted -- remove taint on b
        tp_delete(shad, b);
    }
    else {
        // a tainted -- copy it over to b
        tp_labelset_put(shad, b, ls_a);
#ifdef TAINTDEBUG
        LabelSet *ls_b = tp_labelset_get(shad, b);
        if (!labelset_is_empty(ls_b)){
            printf("labelset b: ");
            labelset_spit(ls_b);
            printf("\n");
        }
#endif
    }
    labelset_free(ls_a);
}


// compute -- c gets union of label sets currently associated with a and b
// delete previous association
SB_INLINE void tp_compute(Shad *shad, Addr *a, Addr *b, Addr *c) {
    assert (shad != NULL);
    // we want the possibilities of address equality for unioning
    //assert (!(addrs_equal(a,b)));
    //assert (!(addrs_equal(b,c)));
    //assert (!(addrs_equal(a,c)));
    LabelSet *ls_a = tp_labelset_get(shad, a);
    LabelSet *ls_b = tp_labelset_get(shad, b);
    tp_delete(shad, c);
    if ((labelset_is_empty(ls_a)) && (labelset_is_empty(ls_b))) {
        return;
    }
    LabelSet *ls_c = labelset_new();
    //labelset_set_type(ls_c, LST_COMPUTE);
    //LabelSetType ls_c_type;
    if (ls_a != NULL) {
        labelset_collect(ls_c, ls_a);
        //ls_c_type = labelset_get_type(ls_a);
    }
    if (ls_b != NULL) {
        labelset_collect(ls_c, ls_b);
        //ls_c_type = max(ls_c_type, labelset_get_type(ls_b));
    }
    //labelset_set_type(ls_c, ls_c_type);
    labelset_set_type(ls_c, LST_COMPUTE);
    tp_labelset_put(shad, c, ls_c);
#ifdef TAINTDEBUG
    if (!labelset_is_empty(ls_c)){
        printf("labelset c: ");
        labelset_spit(tp_labelset_get(shad, c));
        printf("\n");
    }
#endif
    labelset_free(ls_a);
    labelset_free(ls_b);
    labelset_free(ls_c);
}


/////////////////////////


TaintOpBuffer *tob_new(uint32_t size) {
    TaintOpBuffer *buf = (TaintOpBuffer *) my_malloc(sizeof(TaintOpBuffer),
            poolid_taint_processor);
    buf->max_size = size;
    buf->size = 0;
    buf->start = (char *) my_malloc(size, poolid_taint_processor);
    buf->ptr = buf->start;
    return buf;
}

void tob_delete(TaintOpBuffer *tbuf){
    my_free(tbuf->start, tbuf->max_size, poolid_taint_processor);
    tbuf->start = NULL;
    my_free(tbuf, sizeof(TaintOpBuffer), poolid_taint_processor);
    tbuf = NULL;
}



// if this taint op buffer is close to full (more than 80%),
// double it in size
void tob_resize(TaintOpBuffer **ptbuf) {
  TaintOpBuffer *tbuf = *ptbuf;
  if (tob_full_frac(tbuf) > 0.8) {
    printf ("Doubling size of taint buffer (probably I/O one)\n");
    // fresh buffer twice size of original
    TaintOpBuffer *tbuf_bigger = tob_new(tbuf->max_size * 2);
    // copy ops over
    memcpy(tbuf_bigger->start, tbuf->start, tbuf->size);
    // set current size
    tbuf_bigger->size = tbuf->size;
    // and pointer
    tbuf_bigger->ptr = tbuf_bigger->start + (tbuf_bigger->size);
    // discard contents of old buffer
    tob_delete(tbuf);
    // and re-point
    *ptbuf = tbuf_bigger;
  }
}



void tob_delete_iterate_ops(TaintOpBuffer *tbuf){
    //Make sure we are at the beginning of the buffer
    tob_rewind(tbuf);
    //Free up dynamically allocated arrays in phi and switch ops
    while (!(tob_end(tbuf))) {
      TaintOp *op;
      tob_op_read(tbuf, &op);

        if (op->typ == INSNSTARTOP){
            if (!strcmp(op->val.insn_start.name, "phi")){
                unsigned len = op->val.insn_start.phi_len;
                my_free(op->val.insn_start.phi_vals,
                    len * sizeof(int), poolid_taint_processor);
                op->val.insn_start.phi_vals = NULL;
                my_free(op->val.insn_start.phi_labels,
                    len * sizeof(int), poolid_taint_processor);
                op->val.insn_start.phi_labels = NULL;
            } else if (!strcmp(op->val.insn_start.name, "switch")){
                unsigned len = op->val.insn_start.switch_len;
                my_free(op->val.insn_start.switch_conds,
                    len * sizeof(int64_t), poolid_taint_processor);
                op->val.insn_start.switch_conds = NULL;
                my_free(op->val.insn_start.switch_labels,
                    len * sizeof(int), poolid_taint_processor);
                op->val.insn_start.switch_labels = NULL;
            }
        }
    }

    my_free(tbuf->start, tbuf->max_size, poolid_taint_processor);
    tbuf->start = NULL;
    my_free(tbuf, sizeof(TaintOpBuffer), poolid_taint_processor);
    tbuf = NULL;
}

SB_INLINE void tob_rewind(TaintOpBuffer *buf) {
    buf->ptr = buf->start;
}

void tob_clear(TaintOpBuffer *buf) {
    buf->size = 0;
    buf->ptr = buf->start;
}

SB_INLINE uint8_t tob_end(TaintOpBuffer *buf) {
    return (buf->ptr >= buf->start + buf->size);
}

float tob_full_frac(TaintOpBuffer *buf) {
    return (((float) (buf->ptr - buf->start)) / ((float)buf->max_size));
}


static SB_INLINE void tob_write(TaintOpBuffer *buf, char *stuff,
        uint32_t stuff_size) {
    uint64_t bytes_used = buf->ptr - buf->start;
    assert (buf->max_size - bytes_used >= stuff_size);
    memcpy(buf->ptr, stuff, stuff_size);
    buf->ptr += stuff_size;
    buf->size = max(buf->ptr - buf->start, buf->size);
}


/*
  NB: set pointer *stuff to point to current taint buffer pointer.
  And assume caller wont modify anything there.

*/

static SB_INLINE void tob_read(TaintOpBuffer *buf, char **stuff,
        uint32_t stuff_size) {
    uint64_t bytes_used = buf->ptr - buf->start;
    assert (buf->max_size - bytes_used >= stuff_size);
    //  memcpy(stuff, buf->ptr, stuff_size);
    *stuff = (char *) buf->ptr;
    buf->ptr += stuff_size;
    buf->size = max(buf->ptr - buf->start, buf->size);
}


static SB_INLINE void tob_addr_write(TaintOpBuffer *buf, Addr *a) {
    tob_write(buf, (char*) a, sizeof(Addr));
}

/* UNUSED
// *ap is a pointer to an addr.
static SB_INLINE void tob_addr_read(TaintOpBuffer *buf, Addr **ap) {
    tob_read(buf, (char**) ap, sizeof(Addr));
}
*/

void tob_op_print(Shad *shad, TaintOp *op) {
    switch (op->typ) {
        case LABELOP:
            {
                printf ("label ");
                print_addr(shad, &(op->val.label.a));
                printf (" %d\n", op->val.label.l);
                break;
            }
        case DELETEOP:
            {
                printf ("delete ");
                print_addr(shad, &(op->val.deletel.a));
                printf ("\n");
                break;
            }
        case COPYOP:
            {
                printf ("copy ");
                print_addr(shad, &(op->val.copy.a));
                printf (" ");
		print_addr(shad, &(op->val.copy.b));
                printf ("\n");
                break;
            }
        case BULKCOPYOP:
            {
                printf("bulk copy ");
                print_addr(shad, &(op->val.bulkcopy.a));
                printf(" ");
                print_addr(shad, &(op->val.bulkcopy.b));
                printf("Len: %u\n", op->val.bulkcopy.l);
                break;
            }
        case COMPUTEOP:
            {
                printf ("compute ");
                print_addr(shad, &(op->val.compute.a));
                printf (" ");
                print_addr(shad, &(op->val.compute.b));
                printf (" ");
                print_addr(shad, &(op->val.compute.c));
                printf ("\n");
                break;
            }
        case INSNSTARTOP:
            {
                printf("insn_start: %s, %d ops\n", op->val.insn_start.name,
                        op->val.insn_start.num_ops);
                break;
            }
        case CALLOP:
            {
                printf("call %s\n", op->val.call.name);
                break;
            }
        case RETOP:
            {
                printf("return\n");
                break;
            }
        case QUERYOP:
            {
                printf("query ");
                print_addr(shad, &(op->val.query.a));
                printf(" len: %d\n", op->val.query.l);
                break;
            }
        default:
            assert (1==0);
    }
}



//SB_INLINE void tob_op_write(TaintOpBuffer *buf, TaintOp *op) {
void tob_op_write(TaintOpBuffer *buf, TaintOp *op) {
    tob_write(buf, (char*) op, sizeof(TaintOp));
}

// *aop is pointer to a taint op
SB_INLINE void tob_op_read(TaintOpBuffer *buf, TaintOp **aop) {
    tob_read(buf, (char**) aop, sizeof(TaintOp));
}

SB_INLINE void process_insn_start_op(TaintOp *op, TaintOpBuffer *buf,
        DynValBuffer *dynval_buf){
#ifdef TAINTDEBUG
    printf("Fixing up taint op buffer for: %s\n", op->val.insn_start.name);
#endif

    DynValEntry dventry;
    if(op->val.insn_start.flag == INSNREADLOG) {
      // Make sure there is still something to read in the buffer
      assert(((uintptr_t)(dynval_buf->ptr) - (uintptr_t)(dynval_buf->start))
          < dynval_buf->cur_size);

      read_dynval_buffer(dynval_buf, &dventry);

      if (dventry.entrytype == EXCEPTIONENTRY){
          //printf("EXCEPTION FOUND IN DYNAMIC LOG\n");
          next_step = EXCEPT;
          return;
      }
    }

    if (!strcmp(op->val.insn_start.name, "load")){

        // Check to see if it's either a regular load or port load
        if (((dventry.entrytype != ADDRENTRY) && (dventry.entrytype != PADDRENTRY))
                || ((dventry.entry.memaccess.op != LOAD)
                    && (dventry.entry.memaccess.op != PLOAD))){
            fprintf(stderr, "Error: dynamic log doesn't align\n");
            fprintf(stderr, "In: load\n");
            exit(1);
        }

        else if ((dventry.entrytype == ADDRENTRY)
                && (dventry.entry.memaccess.op == LOAD)) {
            /*** Fix up taint op buffer here ***/
            char *saved_buf_ptr = buf->ptr;
            TaintOp *cur_op = (TaintOp*) buf->ptr;

            int i;
            for (i = 0; i < op->val.insn_start.num_ops; i++){

                switch (cur_op->typ){
                    case COPYOP:
                        if (dventry.entry.memaccess.addr.flag == IRRELEVANT){
                            // load from irrelevant part of CPU state
                            // delete taint at the destination
                            cur_op->val.copy.a.flag = IRRELEVANT;
                        }
                        else if (dventry.entry.memaccess.addr.typ == GREG){
                            // guest register
                            cur_op->val.copy.a.flag = (AddrFlag) 0;
                            cur_op->val.copy.a.typ = GREG;
                            cur_op->val.copy.a.val.gr =
                                dventry.entry.memaccess.addr.val.gr;
                        }
                        else if (dventry.entry.memaccess.addr.typ == GSPEC){
                            // guest special address
                            cur_op->val.copy.a.flag = (AddrFlag) 0;
                            cur_op->val.copy.a.typ = GSPEC;
                            cur_op->val.copy.a.val.gs =
                                dventry.entry.memaccess.addr.val.gs;

                        }
                        else if (dventry.entry.memaccess.addr.typ == MADDR){
                            // guest RAM
                            cur_op->val.copy.a.flag = (AddrFlag) 0;
                            cur_op->val.copy.a.typ = MADDR;
                            cur_op->val.copy.a.val.ma =
                                dventry.entry.memaccess.addr.val.ma;
                        }
                        else {
                            assert(1==0);
                        }
                        break;

                    default:
                        // taint ops for load only consist of copy ops
                        assert(1==0);
                }

                cur_op++;
            }

            buf->ptr = saved_buf_ptr;
        }

        else if ((dventry.entrytype == PADDRENTRY)
                && (dventry.entry.portaccess.op == PLOAD)) {
            /*** Fix up taint op buffer here ***/
            char *saved_buf_ptr = buf->ptr;
            TaintOp *cur_op = (TaintOp*) buf->ptr;

            int i;
            for (i = 0; i < op->val.insn_start.num_ops; i++){
                // For port accesses, we assume that data is only moved between
                // ports and guest registers.  If this assumption is wrong then
                // we will fail here.
                switch (cur_op->typ){
                    case COPYOP:
                        if (dventry.entry.memaccess.addr.typ == PADDR){
                            // guest register
                            cur_op->val.copy.a.flag = (AddrFlag) 0;
                            cur_op->val.copy.a.typ = PADDR;
                            cur_op->val.copy.a.val.pa =
                                dventry.entry.portaccess.addr.val.pa;
                        }
                        else {
                            assert(1==0);
                        }
                        break;

                    default:
                        // taint ops for port load only consist of copy ops
                        assert(1==0);
                }

                cur_op++;
            }

            buf->ptr = saved_buf_ptr;
        }


        else {
            fprintf(stderr, "Error: unknown error in dynamic log\n");
            fprintf(stderr, "In: load\n");
            exit(1);
        }
    }

    else if (!strcmp(op->val.insn_start.name, "store")){

        // Check to see if it's either a regular store or port store
        if (((dventry.entrytype != ADDRENTRY) && (dventry.entrytype != PADDRENTRY))
                || ((dventry.entry.memaccess.op != STORE)
                    && (dventry.entry.memaccess.op != PSTORE))){
            fprintf(stderr, "Error: dynamic log doesn't align\n");
            fprintf(stderr, "In: store\n");
            exit(1);
        }

        else if ((dventry.entrytype == ADDRENTRY)
                && (dventry.entry.memaccess.op == STORE)) {
            /*** Fix up taint op buffer here ***/
            char *saved_buf_ptr = buf->ptr;
            TaintOp *cur_op = (TaintOp*) buf->ptr;

            int i;
            for (i = 0; i < op->val.insn_start.num_ops; i++){

                switch (cur_op->typ){
                    case COPYOP:
                        if (dventry.entry.memaccess.addr.flag == IRRELEVANT){
                            // store to irrelevant part of CPU state
                            // delete taint at the destination
                            cur_op->val.copy.b.flag = IRRELEVANT;
                        }
                        else if (dventry.entry.memaccess.addr.typ == GREG){
                            // guest register
                            cur_op->val.copy.b.flag = (AddrFlag) 0;
                            cur_op->val.copy.b.typ = GREG;
                            cur_op->val.copy.b.val.gr =
                                dventry.entry.memaccess.addr.val.gr;
                        }
                        else if (dventry.entry.memaccess.addr.typ == GSPEC){
                            // guest special address
                            cur_op->val.copy.b.flag = (AddrFlag) 0;
                            cur_op->val.copy.b.typ = GSPEC;
                            cur_op->val.copy.b.val.gs =
                                dventry.entry.memaccess.addr.val.gs;
                        }
                        else if (dventry.entry.memaccess.addr.typ == MADDR){
                            // guest RAM
                            cur_op->val.copy.b.flag = (AddrFlag) 0;
                            cur_op->val.copy.b.typ = MADDR;
                            cur_op->val.copy.b.val.ma =
                                dventry.entry.memaccess.addr.val.ma;
                        }
                        else {
                            assert(1==0);
                        }
                        break;

#ifdef TAINTED_POINTER
                    /* this only assumes we are in tainted pointer mode,
                     * with the associated taint models
                     */
                    case COMPUTEOP:
                        if (dventry.entry.memaccess.addr.flag == IRRELEVANT){
                            // store to irrelevant part of CPU state
                            // delete taint at the destination
                            cur_op->val.compute.b.flag = IRRELEVANT;
                            cur_op->val.compute.c.flag = IRRELEVANT;
                        }

                        // for store, if B and C aren't of type UNK, then
                        // skip over them (see the taint model, and how we
                        // use RET as a temp register)
                        else if (cur_op->val.compute.b.typ != UNK
                                && cur_op->val.compute.c.typ != UNK){
                            // do nothing
                        }
                        else if (dventry.entry.memaccess.addr.typ == GREG){
                            // guest register
                            // a register should never be a tainted pointer,
                            // so this is ignored in tob_process()
                            cur_op->val.compute.b.flag = (AddrFlag) 0;
                            cur_op->val.compute.b.typ = GREG;
                            cur_op->val.compute.b.val.gr =
                                dventry.entry.memaccess.addr.val.gr;
                            cur_op->val.compute.c.flag = (AddrFlag) 0;
                            cur_op->val.compute.c.typ = GREG;
                            cur_op->val.compute.c.val.gr =
                                dventry.entry.memaccess.addr.val.gr;
                        }
                        else if (dventry.entry.memaccess.addr.typ == GSPEC){
                            // special address
                            // a register should never be a tainted pointer,
                            // so this is ignored in tob_process()
                            cur_op->val.compute.b.flag = (AddrFlag) 0;
                            cur_op->val.compute.b.typ = GSPEC;
                            cur_op->val.compute.b.val.gs =
                                dventry.entry.memaccess.addr.val.gs;
                            cur_op->val.compute.c.flag = (AddrFlag) 0;
                            cur_op->val.compute.c.typ = GSPEC;
                            cur_op->val.compute.c.val.gs =
                                dventry.entry.memaccess.addr.val.gs;
                        }
                        else if (dventry.entry.memaccess.addr.typ == MADDR){
                            // guest RAM
                            cur_op->val.compute.b.flag = (AddrFlag) 0;
                            cur_op->val.compute.b.typ = MADDR;
                            cur_op->val.compute.b.val.ma =
                                dventry.entry.memaccess.addr.val.ma;
                            cur_op->val.compute.c.flag = (AddrFlag) 0;
                            cur_op->val.compute.c.typ = MADDR;
                            cur_op->val.compute.c.val.ma =
                                dventry.entry.memaccess.addr.val.ma;
                        }
                        else {
                            assert(1==0);
                        }
                        break;
#endif

                    case DELETEOP:
                        if (dventry.entry.memaccess.addr.flag == IRRELEVANT){
                            // do nothing for delete at address we aren't
                            // tracking
                            cur_op->val.deletel.a.flag = IRRELEVANT;
                        }
                        else if (dventry.entry.memaccess.addr.typ == GREG){
                            // guest register
                            cur_op->val.deletel.a.flag = (AddrFlag) 0;
                            cur_op->val.deletel.a.typ = GREG;
                            cur_op->val.deletel.a.val.gr =
                                dventry.entry.memaccess.addr.val.gr;
                        }
                        else if (dventry.entry.memaccess.addr.typ == GSPEC){
                            // guest special address
                            cur_op->val.deletel.a.flag = (AddrFlag) 0;
                            cur_op->val.deletel.a.typ = GSPEC;
                            cur_op->val.deletel.a.val.gs =
                                dventry.entry.memaccess.addr.val.gs;
                        }
                        else if (dventry.entry.memaccess.addr.typ == MADDR){
                            // guest RAM
                            cur_op->val.deletel.a.flag = (AddrFlag) 0;
                            cur_op->val.deletel.a.typ = MADDR;
                            cur_op->val.deletel.a.val.ma =
                                dventry.entry.memaccess.addr.val.ma;
                        }
                        else {
                            assert(1==0);
                        }
                        break;

                    default:
                        // rest are unhandled for now
                        assert(1==0);
                }

                cur_op++;
            }

            buf->ptr = saved_buf_ptr;
        }

        else if ((dventry.entrytype == PADDRENTRY)
                && (dventry.entry.portaccess.op == PSTORE)) {
            /*** Fix up taint op buffer here ***/
            char *saved_buf_ptr = buf->ptr;
            TaintOp *cur_op = (TaintOp*) buf->ptr;

            int i;
            for (i = 0; i < op->val.insn_start.num_ops; i++){
                // For port accesses, we assume that data is only moved between
                // ports and guest registers.  If this assumption is wrong then
                // we will fail here.
                switch (cur_op->typ){
                    case COPYOP:
                        if (dventry.entry.portaccess.addr.typ == PADDR){
                            // guest register
                            cur_op->val.copy.b.flag = (AddrFlag) 0;
                            cur_op->val.copy.b.typ = PADDR;
                            cur_op->val.copy.b.val.pa =
                                dventry.entry.portaccess.addr.val.pa;
                        }
                        else {
                            assert(1==0);
                        }
                        break;
                    case DELETEOP:
                        if (dventry.entry.portaccess.addr.typ == PADDR){
                            // guest register
                            cur_op->val.deletel.a.flag = (AddrFlag) 0;
                            cur_op->val.deletel.a.typ = PADDR;
                            cur_op->val.deletel.a.val.pa =
                                dventry.entry.portaccess.addr.val.pa;
                        }
                        else {
                            assert(1==0);
                        }
                        break;
                    default:
                        // Ops for port store only consist of copy ops
                        assert(1==0);
                }

                cur_op++;
            }

            buf->ptr = saved_buf_ptr;
        }

        else {
            fprintf(stderr, "Error: unknown error in dynamic log\n");
            fprintf(stderr, "In: store\n");
            exit(1);
        }
    }

    else if (!strcmp(op->val.insn_start.name, "condbranch")){

        if (dventry.entrytype != BRANCHENTRY){
            fprintf(stderr, "Error: dynamic log doesn't align\n");
            fprintf(stderr, "In: branch\n");
            exit(1);
        }

        else if (dventry.entrytype == BRANCHENTRY) {

            /*** Fix up taint op buffer here ***/
            /*
             * The true branch is target[0] for brcond and br, and the
             * optional false branch is target[1], so that is how we log it
             */
            if (dventry.entry.branch.br == false){
                previous_branch = op->val.insn_start.cur_branch_bb;
                taken_branch = op->val.insn_start.branch_labels[0];
#ifdef TAINTDEBUG
                printf("Taken branch: %d\n", taken_branch);
#endif
            }
            else if (dventry.entry.branch.br == true) {
                previous_branch = op->val.insn_start.cur_branch_bb;
                taken_branch = op->val.insn_start.branch_labels[1];
#ifdef TAINTDEBUG
                printf("Taken branch: %d\n", taken_branch);
#endif
            }
            else {
                assert(1==0);
            }

            next_step = BRANCH;
        }

        else {
            fprintf(stderr, "Error: unknown error in dynamic log\n");
            fprintf(stderr, "In: branch\n");
            exit(1);
        }
    }

    else if (!strcmp(op->val.insn_start.name, "switch")){

        if (dventry.entrytype != SWITCHENTRY){
            fprintf(stderr, "Error: dynamic log doesn't align\n");
            fprintf(stderr, "In: switch\n");
            exit(1);
        }

        else if (dventry.entrytype == SWITCHENTRY) {

            /*** Fix up taint op buffer here ***/

            int64_t switchCond = dventry.entry.switchstmt.cond;
            bool found = 0;

            unsigned len = op->val.insn_start.switch_len;
            unsigned i;
            for (i = 0; i < (len-1); i++){
                if (op->val.insn_start.switch_conds[i] == switchCond){
                    previous_branch = op->val.insn_start.cur_branch_bb;
                    taken_branch = op->val.insn_start.switch_labels[i];
                    found = 1;
                    break;
                }
            }

            // handle default case in switch
            if (!found){
                previous_branch = op->val.insn_start.cur_branch_bb;
                taken_branch = op->val.insn_start.switch_labels[len-1];
            }
#ifdef TAINTDEBUG
            printf("Switch cond: %ld\n", switchCond);
            printf("Taken branch: %d\n", taken_branch);
#endif
            next_step = SWITCHSTEP;
        }

        else {
            fprintf(stderr, "Error: unknown error in dynamic log\n");
            fprintf(stderr, "In: switch\n");
            exit(1);
        }
    }

    else if (!strcmp(op->val.insn_start.name, "select")){

        if (dventry.entrytype != SELECTENTRY){
            fprintf(stderr, "Error: dynamic log doesn't align\n");
            fprintf(stderr, "In: select\n");
            exit(1);
        }

        else if (dventry.entrytype == SELECTENTRY) {
            /*** Fix up taint op buffer here ***/

            TaintOp *cur_op = (TaintOp*) buf->ptr;
            char *saved_buf_ptr = buf->ptr;

            int i;
            for (i = 0; i < op->val.insn_start.num_ops; i++){
                // fill in src value
                cur_op->val.copy.a.flag = (AddrFlag) 0;
                cur_op->val.copy.a.typ = LADDR;
                if (dventry.entry.select.sel == false){
                    if (op->val.insn_start.branch_labels[0] == -1){
                        // select value was a constant, so we delete taint
                        // at dest
                        cur_op->typ = DELETEOP;
                        cur_op->val.deletel.a.val.la =
                            cur_op->val.copy.b.val.la;
                    }
                    else {
                        cur_op->val.copy.a.val.la =
                            op->val.insn_start.branch_labels[0];
                    }
                }
                else if (dventry.entry.select.sel == true){
                    if (op->val.insn_start.branch_labels[1] == -1){
                        // select value was a constant, so we delete taint
                        // at dest
                        cur_op->typ = DELETEOP;
                        cur_op->val.deletel.a.val.la =
                            cur_op->val.copy.b.val.la;
                    }
                    else {
                        cur_op->val.copy.a.val.la =
                            op->val.insn_start.branch_labels[1];
                    }
                }
                else {
                    assert(1==0);
                }

                cur_op++;
            }

            buf->ptr = saved_buf_ptr;
        }

        else {
            fprintf(stderr, "Error: unknown error in dynamic log\n");
            fprintf(stderr, "In: select\n");
            exit(1);
        }
    }
    else if (!strcmp(op->val.insn_start.name, "phi")){
        char *saved_buf_ptr = buf->ptr;
        TaintOp *cur_op = (TaintOp*) buf->ptr;

        /*** Fix up taint op buffer here ***/
        int phiSource = 0xDEADBEEF;
        int len = op->val.insn_start.phi_len;
        int i;
        for(i = 0; i < len; i++)
        {
            if(previous_branch == op->val.insn_start.phi_labels[i]) {
                //This is the source llvm register for the phi instruction
                //We need to copy taint from here to destination
                phiSource = op->val.insn_start.phi_vals[i];
                break;
            }
        }

        if (phiSource == (int)0xDEADBEEF){
            /* This means a match wasn't found between the previous basic block
             * executed and one of the predecessor basic blocks in the phi
             * instruction.  This should never happen.
             */
            assert(0);
        }

        //Skip copy operations if phiSource is a constant (-1)
        if(phiSource == -1) {
          //Move buffer pointer past copy operations
          cur_op += op->val.insn_start.num_ops;
          buf->ptr = (char*)cur_op;
        } else {
          //Patch up source for copy operations
          for (i = 0; i < op->val.insn_start.num_ops; i++){
              switch (cur_op->typ){
                  case COPYOP:
                    cur_op->val.copy.a.flag = (AddrFlag) 0;
                    cur_op->val.copy.a.typ = LADDR;
                    cur_op->val.copy.a.val.la = phiSource;
                    break;
                  default:
                    //Taint ops for phi only consist of copy ops
                    assert(1==0);
              }
              cur_op++;
          }
          buf->ptr = saved_buf_ptr;
        }
    }
    else if (!strcmp(op->val.insn_start.name, "memset")){
        if ((dventry.entrytype != ADDRENTRY)
                || (dventry.entry.memaccess.op != STORE)){
            fprintf(stderr, "Error: dynamic log doesn't align\n");
            fprintf(stderr, "In: memset\n");
            exit(1);
        }
        else if ((dventry.entrytype == ADDRENTRY)
                && (dventry.entry.memaccess.op == STORE)) {
            /*** Fix up taint op buffer here ***/
            char *saved_buf_ptr = buf->ptr;
            TaintOp *cur_op = (TaintOp*) buf->ptr;
            int i;
            for (i = 0; i < op->val.insn_start.num_ops; i++){
                switch (cur_op->typ){
                    case DELETEOP:
                        if (dventry.entry.memaccess.addr.flag == IRRELEVANT){
                            // do nothing for delete at address we aren't
                            // tracking
                            cur_op->val.deletel.a.flag = IRRELEVANT;
                        }
                        else if (dventry.entry.memaccess.addr.typ == GREG){
                            // guest register
                            cur_op->val.deletel.a.flag = (AddrFlag) 0;
                            cur_op->val.deletel.a.typ = GREG;
                            cur_op->val.deletel.a.val.gr =
                                dventry.entry.memaccess.addr.val.gr;
                        }
                        else if (dventry.entry.memaccess.addr.typ == GSPEC){
                            // guest special address
                            cur_op->val.deletel.a.flag = (AddrFlag) 0;
                            cur_op->val.deletel.a.typ = GSPEC;
                            cur_op->val.deletel.a.val.gs =
                                dventry.entry.memaccess.addr.val.gs;
                        }
                        else if (dventry.entry.memaccess.addr.typ == MADDR){
                            // guest RAM
                            cur_op->val.deletel.a.flag = (AddrFlag) 0;
                            cur_op->val.deletel.a.typ = MADDR;
                            cur_op->val.deletel.a.val.ma =
                                dventry.entry.memaccess.addr.val.ma;
                        }
                        else {
                            assert(1==0);
                        }
                        break;

                    default:
                        // taint ops for memset only consist of delete ops
                        assert(1==0);
                }
                cur_op++;
            }
            buf->ptr = saved_buf_ptr;
        }
    }
    else if (!strcmp(op->val.insn_start.name, "memcpy")){
        /*
         *MemCpy has two values in the dynamic log, the src and the dst.
         *The src is modeled as a LOAD and comes first in the log.
         *The dst is modeled as a STORE and comes second in the log.
         */

        DynValEntry dventry_src = dventry;
        DynValEntry dventry_dst;
        // Make sure there is still something to read in the buffer
        assert(((uintptr_t)(dynval_buf->ptr) - (uintptr_t)(dynval_buf->start))
            < dynval_buf->cur_size);

        read_dynval_buffer(dynval_buf, &dventry_dst);

        if (dventry_dst.entrytype == EXCEPTIONENTRY){
            printf("EXCEPTION FOUND IN DYNAMIC LOG\n");
            next_step = EXCEPT;
            return;
        }

        if ((dventry_src.entrytype != ADDRENTRY) ||
             (dventry_src.entry.memaccess.op != LOAD) ||
             (dventry_dst.entrytype != ADDRENTRY) ||
             (dventry_dst.entry.memaccess.op != STORE)) {
            fprintf(stderr, "Error: dynamic log doesn't align\n");
            fprintf(stderr, "In: memcpy\n");
            exit(1);
        } else {
            /*** Fix up taint op buffer here ***/
            char *saved_buf_ptr = buf->ptr;
            TaintOp *cur_op = (TaintOp*) buf->ptr;
            int i;
            for (i = 0; i < op->val.insn_start.num_ops; i++){
                switch (cur_op->typ){
                    case COPYOP:
                        if (dventry_src.entry.memaccess.addr.flag == IRRELEVANT){
                            // store to irrelevant part of CPU state
                            // delete taint at the destination
                            cur_op->val.copy.a.flag = IRRELEVANT;
                        }
                        else if (dventry_src.entry.memaccess.addr.typ == GREG){
                            // guest register
                            cur_op->val.copy.a.flag = (AddrFlag) 0;
                            cur_op->val.copy.a.typ = GREG;
                            cur_op->val.copy.a.val.gr =
                                dventry_src.entry.memaccess.addr.val.gr;
                        }
                        else if (dventry_src.entry.memaccess.addr.typ == GSPEC){
                            // guest special address
                            cur_op->val.copy.a.flag = (AddrFlag) 0;
                            cur_op->val.copy.a.typ = GSPEC;
                            cur_op->val.copy.a.val.gs =
                                dventry_src.entry.memaccess.addr.val.gs;
                        }
                        else if (dventry_src.entry.memaccess.addr.typ == MADDR){
                            // guest RAM
                            cur_op->val.copy.a.flag = (AddrFlag) 0;
                            cur_op->val.copy.a.typ = MADDR;
                            cur_op->val.copy.a.val.ma =
                                dventry_src.entry.memaccess.addr.val.ma;
                        }
                        else {
                            assert(1==0);
                        }

                        if (dventry_dst.entry.memaccess.addr.flag == IRRELEVANT){
                            // store to irrelevant part of CPU state
                            // delete taint at the destination
                            cur_op->val.copy.b.flag = IRRELEVANT;
                        }
                        else if (dventry_dst.entry.memaccess.addr.typ == GREG){
                            // guest register
                            cur_op->val.copy.b.flag = (AddrFlag) 0;
                            cur_op->val.copy.b.typ = GREG;
                            cur_op->val.copy.b.val.gr =
                                dventry_dst.entry.memaccess.addr.val.gr;
                        }
                        else if (dventry_dst.entry.memaccess.addr.typ == GSPEC){
                            // guest special address
                            cur_op->val.copy.b.flag = (AddrFlag) 0;
                            cur_op->val.copy.b.typ = GSPEC;
                            cur_op->val.copy.b.val.gs =
                                dventry_dst.entry.memaccess.addr.val.gs;
                        }
                        else if (dventry_dst.entry.memaccess.addr.typ == MADDR){
                            // guest RAM
                            cur_op->val.copy.b.flag = (AddrFlag) 0;
                            cur_op->val.copy.b.typ = MADDR;
                            cur_op->val.copy.b.val.ma =
                                dventry_dst.entry.memaccess.addr.val.ma;
                        }
                        else {
                            assert(1==0);
                        }

                        break;
                    default:
                        // taint ops for memcpy only consist of copy ops
                        assert(1==0);
                }
                cur_op++;
            }
            buf->ptr = saved_buf_ptr;
        }
    }
}

void execute_taint_ops(TaintTB *ttb, Shad *shad, DynValBuffer *dynval_buf){

    // execute taint ops starting with the entry BB
    assert(ttb);
    assert(shad);
    assert(dynval_buf);
    next_step = RETURN;
    tob_process(ttb->entry->ops, shad, dynval_buf);

    // process successor(s) if necessary
    while (next_step != RETURN && next_step != EXCEPT){
        next_step = RETURN;
        int i;
        for (i = 0; i < ttb->numBBs-1; i++){
            if (ttb->tbbs[i]->label == taken_branch){
                tob_process(ttb->tbbs[i]->ops, shad, dynval_buf);
                break;
            }
        }
    }

#ifdef TAINTSTATS
    // we're not caching these with TAINTSTATS so we need to clean up
    taint_tb_cleanup(ttb);
#endif

}

SB_INLINE void tob_process(TaintOpBuffer *buf, Shad *shad,
        DynValBuffer *dynval_buf) {

    uint32_t i;
    tob_rewind(buf);
    i = 0;
    while (!(tob_end(buf))) {

      //      if ((ii % 10000) == 0) {
      //	printf ("i=%d\n", ii);
      //      }
      TaintOp *op;
      tob_op_read(buf, &op);


#ifdef TAINTDEBUG
        printf("op %d ", i);
        tob_op_print(shad, op);
#endif
        switch (op->typ) {
            case LABELOP:
                {
		  //		  tob_op_print(shad, op);
		  
		  tp_label(shad, &(op->val.label.a), op->val.label.l);
                    break;
                }

            case DELETEOP:
                {
                    /* if it's a delete of an address we aren't tracking,
                     * do nothing
                     */
                    if (op->val.copy.a.flag == IRRELEVANT){
                        break;
                    }
#ifdef TAINTDEBUG
                    if (tp_query(shad, &(op->val.deletel.a))) {
                        printf ("  [removes taint]\n");
                    }
#endif
		    tp_delete(shad, &(op->val.deletel.a));
                    break;
                }

            case COPYOP:
                {
                    /* if source is address we aren't tracking, then delete the
                     * taint at dest
                     */
                    if (op->val.copy.a.flag == IRRELEVANT){
#ifdef TAINTDEBUG
                            uint8_t foo = 0;
                            if (tp_query(shad, &(op->val.copy.b))){
                                printf ("  [dest was tainted]"); foo = 1;
                            }
                            if (foo) printf("\n");
#endif
			    tp_delete(shad, &(op->val.copy.b));
                        break;
                    }

                    /* if it's a copy to an address we aren't tracking, do
                     * nothing
                     */
                    if (op->val.copy.b.flag == IRRELEVANT){
                        break;
                    }

#ifdef TAINTDEBUG
                    uint8_t foo = 0;
                    if (tp_query(shad, &(op->val.copy.a))) {
                        printf ("  [src is tainted]"); foo = 1;
                    }
                    if (tp_query(shad, &(op->val.copy.b))) {
                        printf ("  [dest was tainted]"); foo = 1;
                    }
                    if (foo) printf("\n");
#endif
		    tp_copy(shad, &(op->val.copy.a), &(op->val.copy.b));
                    break;
                }

	   case BULKCOPYOP:
                // TRL this is used by hd taint.  idea is to
                // specify a src and dest and a number of bytes to copy
                {
                    uint32_t i;
		    Addr a,b;
		    a = op->val.bulkcopy.a;
		    b = op->val.bulkcopy.b;
                    for (i=0; i<op->val.bulkcopy.l; i++) {
#ifdef TAINTDEBUG
                        uint8_t foo = 0;
                        if (tp_query(shad, &(op->val.bulkcopy.a))) {
                            printf ("  [src is tainted]"); foo = 1;
                        }
                        if (tp_query(shad, &(op->val.bulkcopy.b))) {
                            printf ("  [dest was tainted]"); foo = 1;
                        }
                        if (foo) printf("\n");
#endif
			tp_copy(shad, &a, &b);
			addr_inc(&a);
			addr_inc(&b);
			//                        tp_copy(shad, addr_add(op->val.bulkcopy.a, i),
			//				addr_add(op->val.bulkcopy.b, i));
                    }

                    break;
                }

           case COMPUTEOP:
                {
                    /* if it's a compute to an address we aren't tracking, do
                     * nothing
                     */
                    if (op->val.compute.c.flag == IRRELEVANT){
                        break;
                    }

                    /* in tainted pointer mode, if for some reason the pointer
                     * is tainted but it points to a guest register, do nothing
                     */
#ifdef TAINTED_POINTER
                    if (op->val.compute.c.typ == GREG){
                        break;
                    } else if (op->val.compute.c.typ == GSPEC){
                        break;
                    }
#endif

#ifdef TAINTDEBUG
                    uint8_t foo = 0;
                    if (tp_query(shad, &(op->val.compute.a))) {
                        printf ("  [src1 was tainted]"); foo = 1;
                    }
                    if (tp_query(shad, &(op->val.compute.b))) {
                        printf ("  [src2 was tainted]"); foo = 1;
                    }
                    if (tp_query(shad, &(op->val.compute.c))) {
                        printf ("  [dest was tainted]"); foo = 1;
                    }
                    if (foo) printf("\n");
#endif
		    tp_compute(shad, &(op->val.compute.a), &(op->val.compute.b),
			       &(op->val.compute.c));
                    break;
                }

            case INSNSTARTOP:
                {
		  process_insn_start_op(op, buf, dynval_buf);
                    if (next_step == EXCEPT){
                        return;
                    }
                    break;
                }

            case CALLOP:
                {
                    shad->current_frame = shad->current_frame + 1;
		    execute_taint_ops(op->val.call.ttb, shad, dynval_buf);
                    break;
                }

            case RETOP:
                {
                    if (shad->current_frame > 0){
                        shad->current_frame = shad->current_frame - 1;
                    }
                    else if ((int)shad->current_frame < 0){
                        assert(1==0);
                    }
                    break;
                }

            case QUERYOP:
                {
                    bufplot(NULL, shad, &(op->val.query.a), op->val.query.l);
                    break;
                }

            default:
                assert (1==0);
        }
	i++;
    }
    tob_rewind(buf);
}


/*** taint translation block stuff ***/

SB_INLINE TaintTB *taint_tb_new(const char *name, int numBBs){
    TaintTB *ttb = (TaintTB*) my_malloc(sizeof(TaintTB), poolid_taint_processor);
    ttb->name = (char*) my_malloc(strlen(name)+1, poolid_taint_processor);
    strncpy(ttb->name, name, strlen(name)+1);
    ttb->numBBs = numBBs;
    ttb->entry = (TaintBB*) my_malloc(sizeof(TaintBB), poolid_taint_processor);
    if (numBBs > 1){
        ttb->tbbs = (TaintBB**) my_malloc((numBBs-1) * sizeof(TaintBB*),
                poolid_taint_processor);
        int i;
        for (i = 0; i < numBBs-1; i++){
            ttb->tbbs[i] = (TaintBB*) my_malloc(sizeof(TaintBB), poolid_taint_processor);
        }
    } else {
        ttb->tbbs = NULL;
    }
    return ttb;
}

void taint_tb_cleanup(TaintTB *ttb){
    my_free(ttb->name, strlen(ttb->name)+1, poolid_taint_processor);
    ttb->name = NULL;
    tob_delete_iterate_ops(ttb->entry->ops);
    my_free(ttb->entry, sizeof(TaintBB), poolid_taint_processor);
    ttb->entry = NULL;
    if (ttb->numBBs > 1){
        int i;
        for (i = 0; i < (ttb->numBBs) - 1; i++){
            tob_delete_iterate_ops(ttb->tbbs[i]->ops);
            my_free(ttb->tbbs[i], sizeof(TaintBB), poolid_taint_processor);
            ttb->tbbs[i] = NULL;
        }
        my_free(ttb->tbbs, (ttb->numBBs-1) * sizeof(TaintBB*),
                poolid_taint_processor);
    }
    ttb->tbbs = NULL;
    my_free(ttb, sizeof(TaintTB), poolid_taint_processor);
    ttb = NULL;
}
