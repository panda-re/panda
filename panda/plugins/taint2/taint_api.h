#ifndef __TAINT_API_H_
#define __TAINT_API_H_


#ifdef __cplusplus
#include <cstdint>
#endif

#ifndef PYPANDA
#include "taint2.h"
#endif



extern "C" {
// For the C API to taint accessible from other plugins
void taint2_enable_taint(void);
void taint2_enable_tainted_pointer(void);
int taint2_enabled(void);
void taint2_label_addr(Addr a, int offset, uint32_t l) ;
void taint2_label_ram(uint64_t pa, uint32_t l) ;
void taint2_label_reg(int reg_num, int offset, uint32_t l) ;
void taint2_label_io(uint64_t ia, uint32_t l);
void taint2_label_ram_additive(uint64_t pa, uint32_t l);
void taint2_label_reg_additive(int reg_num, int offset, uint32_t l);
void taint2_label_io_additive(uint64_t ia, uint32_t l);
void taint2_add_taint_ram_pos(CPUState *cpu, uint64_t addr, uint32_t length, uint32_t start_label);
void taint2_add_taint_ram_single_label(CPUState *cpu, uint64_t addr,
    uint32_t length, long label);
void taint2_delete_ram(uint64_t pa);
void taint2_delete_reg(int reg_num, int offset);
void taint2_delete_io(uint64_t ia);

Panda__TaintQuery *taint2_query_pandalog (Addr addr, uint32_t offset);
void pandalog_taint_query_free(Panda__TaintQuery *tq);

uint32_t taint2_query(Addr a);
uint32_t taint2_query_ram(uint64_t pa);
uint32_t taint2_query_laddr(uint64_t la, uint64_t off);
uint32_t taint2_query_reg(int reg_num, int offset);
uint32_t taint2_query_io(uint64_t ia);
uint32_t taint2_query_llvm(int reg_num, int offset);

uint32_t taint2_query_set_a(Addr a, uint32_t **out, uint32_t *outsz);

void taint2_query_set(Addr a, uint32_t *out);
void taint2_query_set_ram(uint64_t pa, uint32_t *out);
void taint2_query_set_reg(int reg_num, int offset, uint32_t *out);
void taint2_query_set_io(uint64_t ia, uint32_t *out);

uint32_t taint2_query_tcn(Addr a);
uint32_t taint2_query_tcn_ram(uint64_t pa);
uint32_t taint2_query_tcn_reg(int reg_num, int offset);
uint32_t taint2_query_tcn_io(uint64_t ia);
uint32_t taint2_query_tcn_llvm(int reg_num, int offset);

uint64_t taint2_query_cb_mask(Addr a, uint8_t size);

void taint2_labelset_addr_iter(Addr addr, int (*app)(uint32_t el, void *stuff1), void *stuff2);
void taint2_labelset_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2);
void taint2_labelset_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);
void taint2_labelset_io_iter(uint64_t ia, int (*app)(uint32_t el, void *stuff1), void *stuff2);
void taint2_labelset_llvm_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);

uint32_t taint2_num_labels_applied(void);

void taint2_track_taint_state(void);

//typedef uint32_t TaintLabel;

void taint2_query_results_iter(QueryResult *qr);

uint32_t taint2_query_result_next(QueryResult *qr, bool *done);

void taint2_query_laddr_full(uint64_t reg_num, uint64_t offset, QueryResult *qr);

void taint2_query_reg_full(uint32_t reg_num, uint32_t offset, QueryResult *qr);

void taint2_query_ram_full(uint64_t pa, QueryResult *qr);

}


#endif
