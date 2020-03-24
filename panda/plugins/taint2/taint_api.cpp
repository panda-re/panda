#include "taint2.h"
#include "taint_api.h"
#include <set>

Addr make_haddr(uint64_t a)
{
    Addr ha;
    ha.typ = HADDR;
    ha.val.ha = a;
    ha.off = 0;
    ha.flag = (AddrFlag)0;
    return ha;
}

Addr make_iaddr(uint64_t a)
{
    Addr ia;
    ia.typ = IADDR;
    ia.val.ia = a;
    ia.off = 0;
    ia.flag = (AddrFlag)0;
    return ia;
}

Addr make_paddr(uint64_t a)
{
    Addr pa;
    pa.typ = PADDR;
    pa.val.pa = a;
    pa.off = 0;
    pa.flag = (AddrFlag)0;
    return pa;
}

Addr make_maddr(uint64_t a) {
    Addr ma;
    ma.typ = MADDR;
    ma.val.ma = a;
    ma.off = 0;
    ma.flag = (AddrFlag) 0;
    return ma;
}

Addr make_laddr(uint64_t a, uint64_t off) {
    Addr la;
    la.typ = LADDR;
    la.val.la = a;
    la.off = off;
    la.flag = (AddrFlag) 0;
    return la;
}

Addr make_greg(uint64_t r, uint16_t off) {
    Addr a;
    a.typ = GREG;
    a.val.gr = r;
    a.off = off;
    a.flag = (AddrFlag) 0;
    return a;
}

extern bool debug_taint;
target_ulong debug_asid = 0;

// Implements taint2:debug plugin arg. Turns on -d llvm_ir,taint_ops,in_asm,exec
// for that specific asid.
extern "C"
int asid_changed_callback(CPUState *env, target_ulong oldval, target_ulong newval) {
    if (debug_asid) {
        if (newval == debug_asid) {
            qemu_loglevel |= CPU_LOG_TAINT_OPS | CPU_LOG_LLVM_IR | CPU_LOG_TB_IN_ASM | CPU_LOG_EXEC;
        } else {
            qemu_loglevel &= ~(CPU_LOG_TAINT_OPS | CPU_LOG_LLVM_IR | CPU_LOG_TB_IN_ASM | CPU_LOG_EXEC);
        }
    }
    return 0;
}

static void start_debugging() {
    extern int qemu_loglevel;
    if (!debug_asid) {
        debug_asid = panda_current_asid(first_cpu);
        printf("taint2: ENABLING DEBUG MODE for asid 0x" TARGET_FMT_lx "\n",
                debug_asid);
    }
    qemu_loglevel |= CPU_LOG_TAINT_OPS | CPU_LOG_LLVM_IR | CPU_LOG_TB_IN_ASM | CPU_LOG_EXEC;
}

extern ShadowState *shadow;

// returns a copy of the labelset associated with a.  or NULL if none.
// so you'll need to call labelset_free on this pointer when done with it.
static LabelSetP tp_labelset_get(const Addr &a) {
    assert(shadow);
    auto loc = shadow->query_loc(a);
    return loc.first ? loc.first->query(loc.second) : nullptr;
}

static TaintData tp_query_full(const Addr &a) {
    assert(shadow);
    auto loc = shadow->query_loc(a);
    return loc.first ? loc.first->query_full(loc.second) : TaintData();
}

// untaint -- discard label set associated with a
static void tp_delete(const Addr &a) {
    assert(shadow);
    auto loc = shadow->query_loc(a);
    if (loc.first) loc.first->remove(loc.second, 1);
}

static void tp_labelset_put(const Addr &a, LabelSetP ls) {
    assert(shadow);
    auto loc = shadow->query_loc(a);
    if (loc.first) loc.first->set_full(loc.second, TaintData(ls));
}

// used to keep track of labels that have been applied
std::set<uint32_t> labels_applied;

// label -- associate label l, and only label l, with address a. any previous
// labels applied to the address are removed.
static void tp_label(Addr a, uint32_t l) {
    if (debug_taint) start_debugging();

    LabelSetP ls = label_set_singleton(l);
    tp_labelset_put(a, ls);
    labels_applied.insert(l);
}

// label -- add label l to the label set of address a. previous labels applied
// to the address are not removed.
static void tp_label_additive(Addr a, uint32_t l) {
    if (debug_taint) start_debugging();

    LabelSetP ls_at_a = tp_labelset_get(a);     // get the set at addr a
    LabelSetP ls_of_l = label_set_singleton(l); // get new set with label l

    // merge the existing set at addr a and the new set containing the label l.
    // if successful, add the labelset, skip otherwise.
    LabelSetP new_ls = label_set_union(ls_at_a, ls_of_l);
    if (new_ls) {
        tp_labelset_put(a, new_ls);
        labels_applied.insert(l);
	}
}

// retrieve ls for this addr
static void tp_ls_iter(LabelSetP ls, int (*app)(uint32_t, void *), void *opaque) {
    if (ls == nullptr) {
        return;
    }
    for (uint32_t el : *ls) {
        if (app(el, opaque) != 0) break;
    }
}

// label this phys addr in memory with this label
void taint2_label_ram(uint64_t pa, uint32_t l) {
    Addr a = make_maddr(pa);
    tp_label(a, l);
}

// label this IO address with this label
void taint2_label_io(uint64_t ia, uint32_t l) {
    Addr a = make_iaddr(ia);
    tp_label(a, l);
}

void taint2_label_addr(Addr a, int offset, uint32_t l) {
    a.off = offset;
    if (a.typ == LADDR)
        taint_log("LABEL: Laddr[%lx] offset=%d (%d)\n", a.val.la, offset, l);
    if (a.typ == GREG)
        taint_log("LABEL: Greg[%lx] offset=%d (%d)\n", a.val.gr, offset, l);
    tp_label(a, l);
}

void taint2_label_reg(int reg_num, int offset, uint32_t l) {
    Addr a = make_greg(reg_num, offset);
    tp_label(a, l);
}

void taint2_label_ram_additive(uint64_t pa, uint32_t l) {
    Addr a = make_maddr(pa);
    tp_label_additive(a, l);
}

void taint2_label_reg_additive(int reg_num, int offset, uint32_t l) {
    Addr a = make_greg(reg_num, offset);
    tp_label_additive(a, l);
}

void taint2_label_io_additive(uint64_t ia, uint32_t l) {
    Addr a = make_iaddr(ia);
    tp_label_additive(a, l);
}

void label_byte(CPUState *cpu, target_ulong virt_addr, uint32_t label_num) {
    hwaddr pa = panda_virt_to_phys(cpu, virt_addr);
    if (pandalog) {
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.has_taint_label_virtual_addr = 1;
        ple.has_taint_label_physical_addr = 1;
        ple.has_taint_label_number = 1;
        ple.taint_label_virtual_addr = virt_addr;
        ple.taint_label_physical_addr = pa;
        ple.taint_label_number = label_num;
        pandalog_write_entry(&ple);
    }
    taint2_label_ram(pa, label_num);
}


// Apply positional taint to a buffer of memory
void taint2_add_taint_ram_pos(CPUState *cpu, uint64_t addr, uint32_t length, uint32_t start_label){
    for (unsigned i = 0; i < length; i++){
        hwaddr pa = panda_virt_to_phys(cpu, addr + i);
        if (pa == (hwaddr)(-1)) {
            printf("can't label addr=0x%" PRIx64 ": mmu hasn't mapped virt->phys, "
                   "i.e., it isnt actually there.\n", addr+i);
            continue;
        }
        printf("taint2: adding positional taint label %d\n", i+start_label);
        label_byte(cpu, addr+i, i+start_label);
    }
}


// Apply single label taint to a buffer of memory
void taint2_add_taint_ram_single_label(CPUState *cpu, uint64_t addr,
        uint32_t length, long label){
    for (unsigned i = 0; i < length; i++){
        hwaddr pa = panda_virt_to_phys(cpu, addr + i);
        if (pa == (hwaddr)(-1)) {
            printf("can't label addr=0x%" PRIx64 ": mmu hasn't mapped virt->phys, "
                   "i.e., it isnt actually there.\n", addr+i);
            continue;
        }
        //taint2_label_ram(pa, label);
        printf("taint2: adding single taint label %lu\n", label);
        label_byte(cpu, addr+i, label);
    }
}

uint32_t taint2_query(Addr a) {
    LabelSetP ls = tp_labelset_get(a);
    return ls ? ls->size() : 0;
}

// if phys addr pa is untainted, return 0.
// else returns label set cardinality
uint32_t taint2_query_ram(uint64_t pa) {
    LabelSetP ls = tp_labelset_get(make_maddr(pa));
    return ls ? ls->size() : 0;
}
//
// if laddr addr la is untainted, return 0.
// else returns label set cardinality
uint32_t taint2_query_laddr(uint64_t la, uint64_t off) {
    LabelSetP ls = tp_labelset_get(make_laddr(la, off));
    return ls ? ls->size() : 0;
}

uint32_t taint2_query_reg(int reg_num, int offset) {
    LabelSetP ls = tp_labelset_get(make_greg(reg_num, offset));
    return ls ? ls->size() : 0;
}



// if IO address is untainted, return 0
// otherwise, return the label set cardinality
uint32_t taint2_query_io(uint64_t ia) {
    LabelSetP ls = tp_labelset_get(make_iaddr(ia));
    return ls ? ls->size() : 0;
}

/**
 * @brief Returns taint labels associated with address \p a.
 * Both the number of labels and their count are returned.
 *
 * This function essentially combines taint2_query() and taint2_query_set().
 * However, unlike taint2_query_set(), it will reallocate buffer \p *out and
 * update it's size \p *outsz as needed to fit the returned labels.
 * In the case where \p out is `nullptr`, the function is equivalent with
 * taint2_query().
 *
 * \param a	the address to be queried for taint
 * \param out	a pointer to the the buffer where taint labels will be stored.
 * \param outsz	the number of labels that buffer \p *out can hold.
 * \return The number of labels associated with \p a.
 */
extern "C" uint32_t taint2_query_set_a(Addr a, uint32_t **out, uint32_t *outsz) {
    auto s = tp_labelset_get(a);
    if (s == nullptr || s->empty()) return 0;

    // only return size
    if (out == nullptr) return s->size();

    // allocate/reallocate buffer
    uint32_t sz = s->size();
    if (*out == nullptr || *outsz < sz) {
        *out = (uint32_t *)realloc(*out, sz*sizeof(uint32_t));
        *outsz = sz;
    }

    // fill buffer
    uint32_t *buf = *out;
    uint32_t i = 0;
    for (uint32_t l: *s) { buf[i++] = l; }

    return sz;
}

/**
 * @brief Fills \p out with the taint labels associated with address \p a.
 * It is assumed that \p out is large enough to hold the returned data.
 */
extern "C" void taint2_query_set(Addr a, uint32_t *out) {
	auto set = tp_labelset_get(a);
	if (set == nullptr || set->empty()) return;

	auto it = set->begin();
	for (size_t i = 0; it != set->end(); ++i, ++it) {
		out[i] = *it;
	}
}

extern "C" void taint2_query_set_ram(uint64_t pa, uint32_t *out) {
	auto set = tp_labelset_get(make_maddr(pa));
	if (set == nullptr || set->empty()) return;

	auto it = set->begin();
	for (size_t i = 0; it != set->end(); ++i, ++it) {
		out[i] = *it;
	}
}

extern "C" void taint2_query_set_reg(int reg_num, int offset, uint32_t *out) {
	auto set = tp_labelset_get(make_greg(reg_num, offset));
	if (set == nullptr || set->empty()) return;

	auto it = set->begin();
	for (size_t i = 0; it != set->end(); ++i, ++it) {
		out[i] = *it;
	}
}

extern "C" void taint2_query_set_io(uint64_t ia, uint32_t *out) {
	auto set = tp_labelset_get(make_iaddr(ia));
	if (set == nullptr || set->empty()) return;

	auto it = set->begin();
	for (size_t i = 0; it != set->end(); ++i, ++it) {
		out[i] = *it;
	}
}

uint32_t taint2_query_tcn(Addr a) {
    return tp_query_full(a).tcn;
}

uint32_t taint2_query_tcn_ram(uint64_t pa) {
    return taint2_query_tcn(make_maddr(pa));
}

uint32_t taint2_query_tcn_reg(int reg_num, int offset) {
    return taint2_query_tcn(make_greg(reg_num, offset));
}

uint32_t taint2_query_tcn_io(uint64_t ia) {
    return taint2_query_tcn(make_iaddr(ia));
}

uint64_t taint2_query_cb_mask(Addr a, uint8_t size) {
    uint64_t cb_mask = 0;
    for (unsigned i = 0; i < size; i++, a.off++) {
        cb_mask |= tp_query_full(a).cb_mask << (i * 8);
    }
    return cb_mask;
}

uint32_t taint2_num_labels_applied(void) {
    return labels_applied.size();
}

void taint2_delete_ram(uint64_t pa) {
    Addr a = make_maddr(pa);
    tp_delete(a);
}

void taint2_delete_reg(int reg_num, int offset) {
    Addr a = make_greg(reg_num, offset);
    tp_delete(a);
}

void taint2_delete_io(uint64_t ia) {
    Addr a = make_iaddr(ia);
    tp_delete(a);
}

void taint2_labelset_addr_iter(Addr a, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    tp_ls_iter(tp_labelset_get(a), app, stuff2);
}

void taint2_labelset_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    tp_ls_iter(tp_labelset_get(make_maddr(pa)), app, stuff2);
}

void taint2_labelset_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    tp_ls_iter(tp_labelset_get(make_greg(reg_num, offset)), app, stuff2);
}

void taint2_labelset_io_iter(uint64_t ia, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    tp_ls_iter(tp_labelset_get(make_iaddr(ia)), app, stuff2);
}

void taint2_track_taint_state(void) {
    track_taint_state = true;
}

#define MAX_EL_ARR_IND 1000000
static uint32_t el_arr_ind = 0;

// used to pack pandalog array with query result
static int collect_query_labels_pandalog(uint32_t el, void *stuff) {
    uint32_t *label = (uint32_t *) stuff;
    assert (el_arr_ind < MAX_EL_ARR_IND);
    label[el_arr_ind++] = el;
    return 0;
}

/*
  Queries taint on this addr and return a Panda__TaintQuery
  data structure containing results of taint query.

  if there is no taint set associated with that address, return nullptr.

  NOTE: offset is offset into the thing that was queried.
  so, e.g., if that thing was a buffer and the query came
  from guest source code, then offset is where we are in the buffer.
  offset isn't intended to be used in any other way than to
  propagate this to the offset part of the pandalog entry for
  a taint query.
  In other words, this offset is not necessarily related to a.off

  ugh.
*/

Panda__TaintQuery *taint2_query_pandalog (Addr a, uint32_t offset) {
    // used to ensure that we only write a label sets to pandalog once
    static std::set <LabelSetP> ls_returned;

    LabelSetP ls = tp_labelset_get(a);
    if (ls) {
        Panda__TaintQuery *tq = (Panda__TaintQuery *) malloc(sizeof(Panda__TaintQuery));
        *tq = PANDA__TAINT_QUERY__INIT;

        // Returns true if insertion took place, i.e. we should plog this LS.
        if (ls_returned.insert(ls).second) {
            // we only want to actually write a particular set contents to pandalog once
            // this ls hasn't yet been written to pandalog
            // write out mapping from ls pointer to labelset contents
            // as its own separate log entry
            Panda__TaintQueryUniqueLabelSet *tquls =
                (Panda__TaintQueryUniqueLabelSet *)
                malloc (sizeof (Panda__TaintQueryUniqueLabelSet));
            *tquls = PANDA__TAINT_QUERY_UNIQUE_LABEL_SET__INIT;
            tquls->ptr = (uint64_t) ls;
            tquls->n_label = ls ? ls->size() : 0;
            tquls->label = (uint32_t *) malloc (sizeof(uint32_t) * tquls->n_label);
            el_arr_ind = 0;
            tp_ls_iter(ls, collect_query_labels_pandalog, (void *) tquls->label);
            tq->unique_label_set = tquls;
        }
        tq->ptr = (uint64_t) ls;
        tq->tcn = taint2_query_tcn(a);
        // offset within larger thing being queried
        tq->offset = offset;
        return tq;
    }
    return nullptr;
}

void pandalog_taint_query_free(Panda__TaintQuery *tq) {
    if (tq->unique_label_set) {
        if (tq->unique_label_set->label) {
            free(tq->unique_label_set->label);
        }
        free(tq->unique_label_set);
    }
    free(tq);
}

extern bool taintEnabled;
int taint2_enabled() {
    return taintEnabled;
}

// from label_set.h
// typedef const std::set<TaintLabel> *LabelSetP;
typedef std::set<TaintLabel>::iterator LabelSetIter;

void taint2_query_results_iter(QueryResult *qr) {

	LabelSetIter *foo = new(LabelSetIter);
	*foo = ((LabelSetP) qr->ls)->begin();
	qr->it_curr = (void *) foo;

	LabelSetIter *bar = new(LabelSetIter);
	*bar = ((LabelSetP) qr->ls)->end();
	qr->it_end = (void *) bar;
}

// Return next taint label in iteration over labelset in qr.
// Also, sets *next to false if that was in fact the last value
// things will go badly if you ignore that setting of *next and call this again, maybe?
TaintLabel taint2_query_result_next(QueryResult *qr, bool *done) {
	// get next label
	TaintLabel l = *(*(LabelSetIter *) qr->it_curr);

	// Increment iterator
  (*(LabelSetIter*)qr->it_curr)++;

	// detect if we've iterated to the end
  *done = (*(LabelSetIter*)qr->it_curr == *(LabelSetIter*)qr->it_end);
	return l;
}

// pass in query result pre-allocated
void taint2_query_laddr_full(uint64_t la, uint64_t offset, QueryResult *qr) {
	// Hmm.  Doesn't this allocate a LabeSetP ? 
	// are we leaking (if so we leaking in a bunch of other places)
	TaintData td = tp_query_full(make_laddr(la, offset));
	qr->num_labels = td.ls->size();
	qr->tcn = td.tcn;
	qr->cb_mask = td.cb_mask;
	qr->ls = (void *) td.ls;  // this should be a (const std::set<TaintLabel> *) type
	taint2_query_results_iter(qr);
}

// pass in query result pre-allocated
void taint2_query_reg_full(uint32_t reg_num, uint32_t offset, QueryResult *qr) {
	// Hmm.  Doesn't this allocate a LabeSetP ? 
	// are we leaking (if so we leaking in a bunch of other places)
	TaintData td = tp_query_full(make_greg(reg_num, offset));
	qr->num_labels = td.ls->size();
	qr->tcn = td.tcn;
	qr->cb_mask = td.cb_mask;
	qr->ls = (void *) td.ls;  // this should be a (const std::set<TaintLabel> *) type
	taint2_query_results_iter(qr);
}
//
// pass in query result pre-allocated
void taint2_query_ram_full(uint64_t pa, QueryResult *qr) {
	// Hmm.  Doesn't this allocate a LabeSetP?
	// are we leaking (if so we leaking in a bunch of other places)
	Addr a = make_maddr(pa);
	TaintData td = tp_query_full(a);
	qr->num_labels = td.ls->size();
	qr->tcn = td.tcn;
	qr->cb_mask = td.cb_mask;
	qr->ls = (void *) td.ls;  // this should be a (const std::set<TaintLabel> *) type
	taint2_query_results_iter(qr);
}
