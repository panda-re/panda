/* PANDABEGINCOMMENT
 * 
 * Authors:
 * Luke Craig               luke.craig@ll.mit.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS
#include "dynamic_symbols.h"

void* self_ptr;
panda_cb pcb_bbt;

// pair<asid, name> -> base
unordered_map<pair<ASID, string>, BASE, pair_hash> process_libraries;
// name of library -> Library (must be rebound)
unordered_map<string, Library> libraries;
// these are section names we've tried and confirmed are not libraries
unordered_set<string> seen_nonlibraries{"ld.so.cache"};
// section -> name -> set struct
unordered_map<string, unordered_map<string, set<struct hook_symbol_resolve>>> hooks;
unordered_map<ASID, enum AsidState> asid_status;

void hook_symbol_resolution(struct hook_symbol_resolve *h){
    string section(h->section);
    string name(h->name);

    // this part checks for previously found matches
    vector<pair<struct hook_symbol_resolve*, struct symbol>> symbols_to_flush;

    // loop through resolved process libraries
    for (auto &pl : process_libraries){
        target_ulong base = pl.second;
        // empty matches everything. otherwise match partial section name
        if (section.empty() || pl.first.second.find(section) != string::npos){
            // find Library from libraries
            auto it = libraries.find(pl.first.second);
            if (it != libraries.end()){
                Library &l = it->second;
                // if section is empty, either match everything or hook offset
                if (name.empty()){
                    if (h->hook_offset){
                        l.bind(first_cpu, base, (char*)pl.first.second.c_str());
                        struct symbol s;
                        memset(&s, 0, sizeof(struct symbol));
                        s.address = pl.second + h->offset;
                        strncpy((char*)&s.section, (char*)pl.first.second.c_str(), sizeof(s.section)-2);
                        symbols_to_flush.push_back(make_pair(h,s));
                    }else{
                        // otherwise match everything
                        l.bind_all(first_cpu, base);
                        for (auto &s : l.symbols){
                            symbols_to_flush.push_back(make_pair(h,s.second));
                        }
                    }
                }else{
                    // otherwise match for names
                    auto it = l.symbols.find(name);
                    if (it != l.symbols.end()){
                        auto &a = *it;
                        l.bind(first_cpu, base, (char*)&a.second.name);
                        symbols_to_flush.push_back(make_pair(h, a.second));
                    }
                }

            }
        }
    }
    while (!symbols_to_flush.empty()){
        auto p = symbols_to_flush.back();
        auto hook_candidate = p.first;
        auto s = p.second;
        (*(hook_candidate->cb))(hook_candidate, s, get_id(first_cpu));
        symbols_to_flush.pop_back();
    }

    // add to the hook list
    hooks[section][name].insert(*h);
}

void bind_symbol(CPUState *cpu, char* name, target_ulong base, struct symbol *s, target_ulong pltgot, target_ulong mips_local_gotno, target_ulong mips_gotsym_idx){
#if defined(TARGET_ARM)
        s->address = base + s->value;
        s->address &= ~0x1;
#elif defined(TARGET_MIPS)
//https://elixir.bootlin.com/uclibc-ng/latest/source/ldso/ldso/mips/elfinterp.c#L298
    switch (s->reloc_type){
    case R_MIPS_32:
	case R_MIPS_64:
	case R_MIPS_REL32:
        if (s->symtab_idx < mips_gotsym_idx){
            // printf("taking the easy path\n");
            s->address = s->value + base;
        } else {
            target_ulong gotentry= 0;
            target_ulong pltgotentry = base + pltgot + sizeof(target_ulong)*(s->symtab_idx + mips_local_gotno - mips_gotsym_idx);
            if (panda_virtual_memory_read(cpu, pltgotentry, (uint8_t*) &gotentry, sizeof(target_ulong)) != MEMTX_OK){
                // printf("Error reading GOT entry @ %s (reloc_type: %d) @ " TARGET_FMT_lx "\n", name, s->reloc_type, pltgotentry);
                s->address = 0;
                return;
            }else{
                fixupendian(gotentry)
                // printf("found symbol using gotentry\n");
                s->address = base + s->value + gotentry;
            }
        }
        break;
    case R_MIPS_REL16:
    case R_MIPS_ADD_IMMEDIATE:
        s->address = s->value + base;
        break;
    case R_MIPS_JUMP_SLOT:
        s->address = s->value;
        break;
    case R_MIPS_SHIFT6:
    case R_MIPS_NONE:
        s->address = 0;
        break;
    default:
        // printf("Can't relocate :'( %s %i %d\n", name, s->symtab_idx, s->reloc_type);
        s->address = 0;
    }
#else
    s->address = base + s->value;
#endif
}


void new_assignment_check_symbols(CPUState* cpu, char* procname, Library l, OsiModule* m){
    string module(m->name);
    vector<tuple<struct hook_symbol_resolve, struct symbol, OsiModule>> symbols_to_flush;
    l.bind_all(cpu, m->base);

    set<string> matching_libs;
    matching_libs.insert("");

    for (auto strs : hooks){
        string lib = strs.first;
        auto h = strs.second;
        if (!h.empty() && module.find(lib) != std::string::npos && !module.empty()){
            matching_libs.insert(lib);
        }
    }

    for (string lib : matching_libs){
        for (auto symbol_matcher : hooks[lib]){
            string symname = symbol_matcher.first;
            set<struct hook_symbol_resolve> h = symbol_matcher.second;
            for (auto hook_candidate: h){
                if (hook_candidate.enabled){
                    if (symname.empty()){
                        if (hook_candidate.hook_offset){
                            struct symbol s;
                            memset(&s, 0, sizeof(struct symbol));
                            s.address = m->base + hook_candidate.offset;
                            strncpy((char*)&s.section, m->name, sizeof(s.section)-2);
                            symbols_to_flush.push_back(make_tuple(hook_candidate,s, *m));
                        }else{
                            for (auto sym: l.symbols){
                                symbols_to_flush.push_back(make_tuple(hook_candidate, sym.second, *m));
                            }
                        }
                    }else{
                        auto it = l.symbols.find(symname);
                        if (it != l.symbols.end()){
                            auto a = *it;
                            symbols_to_flush.push_back(make_tuple(hook_candidate, a.second, *m));
                        }
                    }
                }
            }
        }
    }
    if (!symbols_to_flush.empty()){
        //panda_do_flush_tb();
        // printf("%s hooking %d symbols in %s\n", procname, (int)symbols_to_flush.size(), m->name);
    }
    while (!symbols_to_flush.empty()){
        auto p = symbols_to_flush.back();
        auto hook_candidate = get<0>(p);
        auto s = get<1>(p);
        // auto m = get<2>(p);
        (*(hook_candidate.cb))(&hook_candidate, s, get_id(cpu));
        symbols_to_flush.pop_back();
    }
    // printf("finished adding symbols for %s:%s\n", procname, m->name);
}

struct symbol resolve_symbol(CPUState* cpu, target_ulong asid, char* section_name, char* symbol){
    update_symbols_in_space(cpu);
    for (auto &section: process_libraries){
        pair<target_ulong,string> location = section.first;
        target_ulong base = section.second;
        if (!(location.first == asid || asid == 0)){
            continue;
        }
        auto library = libraries[location.second];
        if (!(section_name == NULL || library.name == string(section_name))){
            continue;
        }
        if (symbol == NULL){
            continue;
        }
        auto it = library.symbols.find(symbol);
        if (it != library.symbols.end()){
            struct symbol val = it->second;
            strncpy((char*) &val.section, location.second.c_str(), sizeof(val.section) -2);
            library.bind(cpu, base, (char*)it->first.c_str());
            return val;
        }
    }
    struct symbol blank;
    blank.address = 0;
    memset((char*) & blank.name, 0, MAX_PATH_LEN);
    memset((char*) & blank.section, 0, MAX_PATH_LEN);
    return blank;
}

struct symbol get_best_matching_symbol(CPUState* cpu, target_ulong address, target_ulong asid){
    update_symbols_in_space(cpu);
    struct symbol best_candidate;
    best_candidate.address = 0;
    memset((char*) & best_candidate.name, 0, MAX_PATH_LEN);
    memset((char*) & best_candidate.section, 0, MAX_PATH_LEN);
    for (const auto& section : process_libraries){
        if (asid == 0 || section.first.first == asid){
            auto library = libraries[section.first.second];
            // rebind before checking
            library.bind_all(cpu, section.second);
            for (auto i : library.symbols){
                struct symbol it = i.second;
                if (it.address > address){
                    if (it.address == address){
                        // if we found a match just break and move on.
                        memcpy(&best_candidate, &it, sizeof(struct symbol));
                        break;
                    }
                    if (it.address > best_candidate.address){
                        //copy it
                        memcpy(&best_candidate, &it, sizeof(struct symbol));
                    }
                }
            }
        }
    }
    return best_candidate;
}


bool find_symbols(CPUState* cpu, target_ulong asid, char* procname, OsiModule *m){
    string name(m->name);
    ELF(Ehdr) ehdr;
    ELF(Phdr) dynamic_phdr;
    ELF(Dyn) tag;
    target_ulong strtab = 0, symtab = 0, strtab_size = 0, dt_hash = 0;
    target_ulong symtab_size;
    target_ulong gnu_hash = 0;
    target_ulong pltgot = 0;
    target_ulong phnum, phoff;
    target_ulong mips_gotsym_idx = 0, mips_local_gotno = 0;
    char *symtab_buf, *strtab_buf;
    int numelements_dyn, numelements_symtab;

    if (panda_virtual_memory_read(cpu, m->base, (uint8_t*)&ehdr, sizeof(ELF(Ehdr))) != MEMTX_OK){            
        error_case(procname, m->name, "3 CNRB");
        // can't read page. try again later;
        return false;
    }

    // is this an ELF?
    if (!(ehdr.e_ident[0] == ELFMAG0 && ehdr.e_ident[1] == ELFMAG1 && ehdr.e_ident[2] == ELFMAG2 && ehdr.e_ident[3] == ELFMAG3)){
        // If we aren't an ELF we don't need to get symbols
        // therefore we return true
        error_case(procname, m->name, "NOT AN ELF HEADER");
        return true;
    } 
    // is this a shared object?
    uint16_t e_type = ehdr.e_type;
    #if defined(TARGET_WORDS_BIGENDIAN)
    e_type = bswap16(e_type);
    #endif
    if (e_type != ET_DYN){
        // printf("add " TARGET_FMT_lx " %s to seen_nonlibraries\n", asid, m->name);
        seen_nonlibraries.insert(name);
        return true;
    }

    phnum = ehdr.e_phnum;
    phoff = ehdr.e_phoff;
    fixupendian(phnum);
    fixupendian(phoff);

    for (int j=0; j<phnum; j++){
        if (panda_virtual_memory_read(cpu, m->base + phoff + (j*sizeof(ELF(Phdr))), (uint8_t*)&dynamic_phdr, sizeof(ELF(Phdr))) != MEMTX_OK){
            error_case(procname, m->name, "5 DPHDR");
            return false;
        }
        fixupendian(dynamic_phdr.p_type)
        if (dynamic_phdr.p_type == PT_DYNAMIC){
            break;
        }else if (dynamic_phdr.p_type == PT_NULL){
            error_case(procname, m->name, "PTNULL");
            //printf("hit PT_NULL\n");
            return false;
        }else if (j == phnum -1){
            error_case(procname, m->name, "END");
            //printf("hit phnum-1\n");
            return false;
        }
    }
    
    fixupendian(dynamic_phdr.p_filesz);
    numelements_dyn = dynamic_phdr.p_filesz / sizeof(ELF(Dyn));
    // iterate over dynamic program headers and find strtab
    // and symtab
    int j = 0;

    fixupendian(dynamic_phdr.p_vaddr);
    while (j < numelements_dyn){
        if (panda_virtual_memory_read(cpu, m->base + dynamic_phdr.p_vaddr + (j*sizeof(ELF(Dyn))), (uint8_t*)&tag, sizeof(ELF(Dyn))) != MEMTX_OK){
            //printf("%s:%s Failed to read entry %d\n", name.c_str(), procname, j);
            error_case(procname, m->name, "5 DPDR");
            return false;
        }

        fixupendian(tag.d_tag);
        fixupendian(tag.d_un.d_ptr);

        if (tag.d_tag == DT_STRTAB){
            strtab = tag.d_un.d_ptr;
        }else if (tag.d_tag == DT_SYMTAB){
            symtab = tag.d_un.d_ptr;
        }else if (tag.d_tag == DT_STRSZ){
            strtab_size = tag.d_un.d_ptr;
        }else if (tag.d_tag == DT_HASH){
            dt_hash = tag.d_un.d_ptr;
        }else if (tag.d_tag == DT_GNU_HASH){
            gnu_hash = tag.d_un.d_ptr;
        }else if (tag.d_tag == DT_PLTGOT){
            pltgot = tag.d_un.d_ptr;
        }else if (tag.d_tag == DT_NULL){
            j = numelements_dyn;
        }else if (tag.d_tag == DT_MIPS_GOTSYM){
            mips_gotsym_idx = tag.d_un.d_ptr;
        }else if (tag.d_tag == DT_MIPS_LOCAL_GOTNO){
            mips_local_gotno = tag.d_un.d_ptr;
            // printf("MIPSLOCALGOTNO %d\n", (int)mips_local_gotno);
        }
        j++;
    }  

    #define FIXUP(X) if (X < m->base){ X += m->base; }
    // some of these are offsets. some are fully qualified
    // addresses. this is a gimmick that can sort-of tell.
    // probably better to replace this at some point
    FIXUP(strtab)
    FIXUP(symtab)
    FIXUP(dt_hash)
    FIXUP(gnu_hash)


    numelements_symtab = get_numelements_symtab(cpu,m->base, dt_hash, gnu_hash, m->base + dynamic_phdr.p_vaddr, symtab, numelements_dyn);
    if (numelements_symtab == -1){
        error_case(procname, m->name, "6 GETELEMENTSSYMTAB");
        return false;
    }

    symtab_size = numelements_symtab * sizeof(ELF(Sym));
    symtab_buf = (char*)malloc(symtab_size);
    strtab_buf = (char*)malloc(strtab_size);
    
    if (panda_virtual_memory_read(cpu, symtab, (uint8_t*)symtab_buf, symtab_size) != MEMTX_OK){
        error_case(procname, m->name, "8 CNR SYMTAB");
        free(symtab_buf);
        free(strtab_buf);
        return false;
    }
    if (panda_virtual_memory_read(cpu, strtab, (uint8_t*) strtab_buf, strtab_size) != MEMTX_OK){
        error_case(procname, m->name, "7 CNR STRTAB");
        free(symtab_buf);
        free(strtab_buf);
        return false;
    }
    // printf("relocating for %s %llx\n", m->name, (long long unsigned int)m->base);
    // printf("GOTNO is %d\n", (int)mips_local_gotno);
    Library l;
    l.name = name;
    
    for (int i=0;i<numelements_symtab; i++){
        ELF(Sym)* a = (ELF(Sym)*) (symtab_buf + i*sizeof(ELF(Sym)));
        fixupendian(a->st_name);
        fixupendian(a->st_value);
        // fixupendian(a->st_info);

        if (a->st_name != 0 && a->st_name < strtab_size && a->st_value != 0){
            struct symbol s;
            strncpy((char*)&s.name, &strtab_buf[a->st_name], sizeof(s.name)-2);
            strncpy((char*)&s.section, m->name, sizeof(s.section)-2);
            s.reloc_type = ELFD(R_TYPE)(a->st_info);
            s.symtab_idx = i;
            s.value = a->st_value;
            bind_symbol(cpu, m->name, m->base, &s, pltgot, mips_local_gotno, mips_gotsym_idx);
            // printf("found symbol @(%d) section:%s name:%s address:0x%llx reloc_type: %d value: %llx\n",i, s.section, &strtab_buf[a->st_name],(long long unsigned int)s.address, s.reloc_type, (long long unsigned int)s.value);
            l.symbols[string(s.name)] = s;
        }
    }
    pair<target_ulong, string> c(asid, name);
    if (l.symbols.size() > 0){
        libraries[name] = l;
        process_libraries[c] = m->base;
        new_assignment_check_symbols(cpu, procname, libraries[name], m);
        error_case(procname, m->name, "SUCCESS");
        // printf("Successful on %s. Found %d symbols " TARGET_FMT_lx "\n", m->name, (int)libraries[name].symbols.size(), m->base);
    }else{
        // printf("no symbols not adding for %s\n", m->name);
    }
    free(symtab_buf);
    free(strtab_buf);
    return true;
}


enum SymUpdateStatus update_symbols_in_space(CPUState* cpu){
    OsiProc *current;
    OsiModule *m;
    target_ulong asid;
    char *procname;
    GArray *ms;
    bool none_missing;

    if (panda_in_kernel(cpu)){
        return PRE_READ_FAIL;
    }
    if (!id_is_initialized()){
        return PRE_READ_FAIL;
    }
    asid = get_id(cpu);
    current = get_current_process(cpu);
    if (current == NULL){
        return PRE_READ_FAIL;
    }
    procname = current->name;
    ms = get_mappings(cpu, current);
    if (ms == NULL) {
        return PRE_READ_FAIL;
    }
    //iterate over mappings and find the lowest VA for each relevant library
    for (int i = 0; i < ms->len; i++) {
        m = &g_array_index(ms, OsiModule, i);
        // printf("mapping name: %s base: " TARGET_FMT_lx "\n", m->name, m->base);
        if (m->name == NULL){
            continue;
        }
        if (strstr(m->name, ".so") != NULL){
            pair<target_ulong, string> candidate(asid,m->name);
            
            // check if we already read this one
            if (process_libraries.find(candidate) != process_libraries.end()){
                // error_case(current->name, m->name, " in symbols[asid] already and has");
                continue;
            }
            // check if this isn't a library
            if (seen_nonlibraries.find(m->name) != seen_nonlibraries.end()){
                // error_case(current->name, m->name, " in seen_nonlibraries[asid] already");
                continue;
            }
            // check if we've previously read this library in another process
            if (libraries.find(m->name) != libraries.end()) {
                // printf("COPY %s:%s for asid " TARGET_PTR_FMT "  and base of " TARGET_PTR_FMT "\n",  current->name, m->name, get_id(cpu), m->base);
                process_libraries[candidate] = m->base;
                new_assignment_check_symbols(cpu, current->name, libraries[m->name], m);
                continue;
            }
            // lastly, lets go try to find the symbols
            if (!find_symbols(cpu, asid, procname, m)){
                // printf("missing %s\n", m->name);
                none_missing = false;
            }
        }
    }
    
    if (!none_missing){
        return READ_FAIL;
    }
    return SYM_SUCCESS;
}

void bbt(CPUState *env, target_ulong pc){
    enum SymUpdateStatus ret = update_symbols_in_space(env);
    target_ulong asid = get_id(env);
    if (ret == READ_FAIL){
        // identify this one needs more scrutiny
        asid_status[asid] = ASID_STATE_FAIL;
        panda_disable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
    }else if (ret == SYM_SUCCESS){
        // failed
        asid_status[asid] = ASID_STATE_SUCCESS;
        panda_disable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
    }else if (ret == PRE_READ_FAIL){
        // this is a PRE_READ_FAIL. We can't read anything yet. Ignore until
        // we can
        asid_status[asid] = ASID_STATE_UNKNOWN;
    }
}

/**
 * This function takes a specific event and decides whether or not to enable
 * further analysis. If the event is specific, we always enable analysis.
 * 
 * If the event is general, we only enable analysis if we've had success for
 * this process.
 */
void enable_analysis(enum AnalysisType at){
    // always take specific events into account
    if (at == ANALYSIS_SPECIFIC){
        panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
        return;
    }
    // only take general events into account for asids with unknown status
    enum AsidState state = ASID_STATE_UNKNOWN;
    if (asid_status.find(get_id(first_cpu)) != asid_status.end()){
        state = asid_status[get_id(first_cpu)];
    }
    if (state == ASID_STATE_FAIL || state == ASID_STATE_UNKNOWN){
        panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
    }
}

void remove_asid_entries(target_ulong asid){
    asid_status.erase(asid);
    auto it = process_libraries.begin();
    while (it != process_libraries.end()){
        if (it->first.first == asid) {
            process_libraries.erase(it++);
        } else {
            ++it;
        }
    }
}

bool init_plugin(void *self) {
    self_ptr = self;
    pcb_bbt.before_block_translate = bbt;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
    panda_require("hw_proc_id");
    assert(init_hw_proc_id_api());
    panda_require("osi");
    assert(init_osi_api());
    #if defined(TARGET_PPC)
        fprintf(stderr, "[ERROR] dynamic_symbols: PPC architecture not supported by syscalls2!\n");
        return false;
    #else
        panda_require("syscalls2");
        assert(init_syscalls2_api());
        return initialize_process_infopoints(self);
    #endif
}

void uninit_plugin(void *self) {}
