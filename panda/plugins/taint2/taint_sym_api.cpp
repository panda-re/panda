#ifndef __TAINT_SYM_API_H_
#define __TAINT_SYM_API_H_


#ifdef __cplusplus
#include <cstdint>
#endif
#define SHAD_LLVM
#include "taint2.h"
#include "taint_sym_api.h"
#include "panda/plugin.h"

#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>
#include <unordered_set>
#include <unordered_map>

z3::context context;
std::vector<z3::expr> path_constraints;
void taint2_sym_label_addr(Addr a, int offset, uint32_t l) {
    assert(shadow);
    assert(symexEnabled);
    a.off = offset;
    auto loc = shadow->query_loc(a);
    if (loc.first) {
        std::string id("val_");
        std::stringstream ss;
        ss << std::hex << l;
        id += ss.str();
        z3::expr *expr = new z3::expr(context.bv_const(id.c_str(), 8));
        // std::cout << "expr: " << *expr << "\n";
        loc.first->query_full(loc.second)->expr = expr;
    }
}

void *taint2_sym_query(Addr a) {
    assert(shadow);
    assert(symexEnabled);
    auto loc = shadow->query_loc(a);
    if (loc.first) {
        return loc.first->query_full(loc.second)->expr;
    }
    return nullptr;
}

z3::expr *taint2_sym_query_expr(Addr a) {
    return (z3::expr *) taint2_sym_query(a);
}


void taint2_sym_label_ram(uint64_t RamOffset, uint32_t l) {
    assert(symexEnabled);
    Addr a = make_maddr(RamOffset);
    taint2_sym_label_addr(a, 0, l);
}

void reg_branch_pc(z3::expr condition, bool concrete) {
    assert(symexEnabled);

    z3::expr pc(context);
    target_ulong current_pc = first_cpu->panda_guest_pc;

    pc = (concrete ? condition : !condition);
    pc = pc.simplify();

    if (pc.is_true() || pc.is_false())
        return;

    std::cerr << "PC: " << std::hex << current_pc << std::dec << "\n";
    std::cerr << "Path constraint: " << pc << "\n";

}


#endif
