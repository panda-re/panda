#ifndef __TAINT_SYM_API_H_
#define __TAINT_SYM_API_H_


#ifdef __cplusplus
#include <cstdint>
#endif
#define SHAD_LLVM
#include "taint_sym_api.h"
#include "taint2.h"
#include "panda/plugin.h"

#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>
#include <unordered_set>
#include <unordered_map>

z3::context context;

void taint2_sym_label_addr(Addr a, int offset, uint32_t l) {
    assert(shadow);
    if(!symexEnabled) taint2_enable_sym();
    a.off = offset;
    auto loc = shadow->query_loc(a);
    if (loc.first) {
        std::string id("val_");
        std::stringstream ss;
        ss << std::hex << l;
        id += ss.str();
        std::shared_ptr<z3::expr> expr = 
            std::make_shared<z3::expr>(context.bv_const(id.c_str(), 8));
        if (!loc.first->query_full(loc.second)->sym)
            loc.first->query_full(loc.second)->sym = new SymLabel();
        loc.first->query_full(loc.second)->sym->expr = expr;
    }
}

void *taint2_sym_query(Addr a) {
    assert(shadow);
    if(!symexEnabled) taint2_enable_sym();
    auto loc = shadow->query_loc(a);
    if (loc.first) {
        if (loc.first->query_full(loc.second)->sym)
            return loc.first->query_full(loc.second)->sym->expr.get();
    }
    return nullptr;
}

z3::expr *taint2_sym_query_expr(Addr a) {
    return (z3::expr *) taint2_sym_query(a);
}


void taint2_sym_label_ram(uint64_t RamOffset, uint32_t l) {
    if(!symexEnabled) taint2_enable_sym();
    Addr a = make_maddr(RamOffset);
    taint2_sym_label_addr(a, 0, l);
}

void taint2_sym_label_reg(int reg_num, int offset, uint32_t l) {
    if(!symexEnabled) taint2_enable_sym();
    Addr a = make_greg(reg_num, offset);
    taint2_sym_label_addr(a, 0, l);
}

void reg_branch_pc(z3::expr condition, bool concrete) {
    if(!symexEnabled) taint2_enable_sym();

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
