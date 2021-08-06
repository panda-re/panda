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

void expr_to_string(z3::expr *expr, uint32_t *n, char** strptr) {
    std::stringstream ss;
    z3::solver solver(context);
    solver.add(*expr == *expr);
    ss << solver;
    std::string cppstr = ss.str();
    // std::cerr << "cppstr: " << cppstr << std::endl;
    size_t size = cppstr.length() + 1;
    char *str = (char*) malloc(size);
    strncpy(str, cppstr.c_str(), size);
    *n = size;
    *strptr = str;
}

z3::expr bytes_to_expr(Shad *shad, uint64_t src, uint64_t size,
        uint64_t concrete, bool* symbolic);

void cpu_physical_memory_read(hwaddr, void*, int);
void taint2_sym_query_ram(uint64_t RamOffset, uint32_t size, uint32_t *n, char** strptr) {
    bool symbolic = false;
    uint64_t concrete = 0;
    if(!symexEnabled) return;
    assert(shadow);
    assert(size <= 8);
    *n = 0;
    // Get concrete value for memory
    cpu_physical_memory_read((hwaddr)RamOffset, (void*)&concrete, size);
    auto expr = bytes_to_expr(&shadow->ram, RamOffset, size, concrete, &symbolic);
    if (symbolic)
        expr_to_string(&expr, n, strptr);
}

void taint2_sym_query_reg(uint32_t reg_num, uint32_t *n, char** strptr) {
    bool symbolic = false;
    uint64_t concrete = 0;
    if(!symexEnabled) return;
    assert(shadow);
    *n = 0;
    // Get concrete value for reg
    concrete = ((CPUArchState*)current_cpu->env_ptr)->regs[reg_num];
    auto expr = bytes_to_expr(&shadow->grv, reg_num * sizeof(target_ulong), sizeof(target_ulong), concrete, &symbolic);
    if (symbolic)
        expr_to_string(&expr, n, strptr);
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
