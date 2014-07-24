
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "taint_api.h"
#include "taint_processor.h"


/*
 * Provides a C API to the taint plugin
 * after it has been loaded
 */

// these will get filled in by taint.cpp
void     (*taint_enable_taint_fp)(void) = NULL;
int      (*taint_enabled_fp)(void) = NULL;
void     (*taint_label_ram_fp)(uint64_t pa, uint32_t l) = NULL;
uint32_t (*taint_query_ram_fp)(uint64_t pa) = NULL;
uint32_t (*taint_query_reg_fp)(int reg_num, int offset) = NULL;
void     (*taint_delete_ram_fp)(uint64_t pa) = NULL;
void     (*taint_labels_ram_iter_fp)(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2) = NULL;
void     (*taint_labels_reg_iter_fp)(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) = NULL;
uint32_t (*taint_occ_ram_fp)(void) = NULL;


#define CHECK_FP(p) \
{ \
  if (p == NULL) { \
    printf ("taint plugin hasn't been loaded so taint_api not available\n"); \
    exit(1); \
  } \
}

  

void taint_enable_taint_cpp(void) {
  CHECK_FP(taint_enable_taint_fp);
  taint_enable_taint_fp();
}

int taint_enabled_cpp(void) {
  CHECK_FP(taint_enabled_fp);
  return taint_enabled_fp();
}

// label this phys addr in memory with this label                                                                                         
void taint_label_ram_cpp(uint64_t pa, uint32_t l) {
  CHECK_FP(taint_label_ram_fp);
  taint_label_ram_fp(pa, l);
}

// if phys addr pa is untainted, return 0.                                                                                                
// else returns label set cardinality                                                                                                     
uint32_t taint_query_ram_cpp(uint64_t pa) {
  CHECK_FP(taint_query_ram_fp);
  return (taint_query_ram_fp(pa));
}

uint32_t taint_query_reg_cpp(int reg_num, int offset) {
  CHECK_FP(taint_query_reg_fp);
  return (taint_query_reg_fp(reg_num, offset));
}

void taint_delete_ram_cpp(uint64_t pa) {
  CHECK_FP(taint_delete_ram_fp);
  taint_delete_ram_fp(pa);
}
  
void taint_labels_ram_iter_cpp(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
  CHECK_FP(taint_labels_ram_iter_fp);
  taint_labels_ram_iter_fp(pa, app, stuff2);
}

void taint_labels_reg_iter_cpp(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
  CHECK_FP(taint_labels_reg_iter_fp);
  taint_labels_reg_iter_fp(reg_num, offset, app, stuff2);
}

uint32_t taint_occ_ram_cpp() { 
  CHECK_FP(taint_occ_ram_fp);
  return taint_occ_ram_fp();
}

// taint c api                                                                                                                              
///////////////////////////////////////////////////////////////////                               
                                                                                                                                         


extern "C" void taint_enable_taint(void) {
  taint_enable_taint_cpp();
}

extern "C" int taint_enabled(void) {
  return taint_enabled_cpp();
}

extern "C" void taint_label_ram(uint64_t pa, uint32_t l) {
  taint_label_ram_cpp(pa, l);
}


extern "C" uint32_t taint_query_ram(uint64_t pa) {
  return taint_query_ram_cpp(pa);
}


extern "C" uint32_t taint_query_reg(int reg_num, int offset) {
  return taint_query_reg_cpp(reg_num, offset);
}


extern "C" void taint_delete_ram(uint64_t pa) {
  taint_delete_ram_cpp(pa);
}


extern "C" void taint_labels_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
  taint_labels_ram_iter_cpp(pa, app, stuff2);
}


extern "C" void taint_labels_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
  taint_labels_reg_iter_cpp(reg_num, offset, app, stuff2);
}


extern "C" uint32_t taint_occ_ram() {
  return taint_occ_ram_cpp();
}
