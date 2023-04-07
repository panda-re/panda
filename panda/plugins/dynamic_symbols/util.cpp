#include "dynamic_symbols.h"

vector<int> possible_tags{ DT_PLTGOT , DT_HASH , DT_STRTAB , DT_SYMTAB , DT_RELA , DT_INIT , DT_FINI , DT_REL , DT_DEBUG , DT_JMPREL, 25, 26, 32, DT_SUNW_RTLDINF , DT_CONFIG , DT_DEPAUDIT , DT_AUDIT , DT_PLTPAD , DT_MOVETAB , DT_SYMINFO , DT_VERDEF , DT_VERNEED };

string read_str(CPUState* cpu, target_ulong ptr){
    string buf = "";
    char tmp;
    while (true){
        if (panda_virtual_memory_read(cpu, ptr, (uint8_t*)&tmp,1) == MEMTX_OK){
            buf += tmp;
            if (tmp == '\x00'){
                break;
            }
            ptr+=1;
        }else{
            break;
        }
    }
    return buf;
}

int get_numelements_hash(CPUState* cpu, target_ulong dt_hash){
    //printf("in dt_hash_section 0x%llx\n", (long long unsigned int) dt_hash);
    struct dt_hash_section dt;

    if (panda_virtual_memory_read(cpu, dt_hash, (uint8_t*) &dt, sizeof(struct dt_hash_section))!= MEMTX_OK){
        //printf("got error 2\n");
        return -1;
    }
    fixupendian(dt.nbuckets);
    //printf("Nbucks: 0x%x\n", dt.nbuckets);
    return dt.nbuckets;
}

int get_numelements_gnu_hash(CPUState* cpu, target_ulong gnu_hash){
    //printf("Just DT_HASH with %s\n", name.c_str());
    // must do gnu_hash method
    // see the following for details:
    // http://deroko.phearless.org/dt_gnu_hash.txt
    // https://flapenguin.me/elf-dt-gnu-hash

    struct gnu_hash_table ght;
    if (panda_virtual_memory_read(cpu, gnu_hash, (uint8_t*)&ght, sizeof(ght))!=MEMTX_OK){
        //printf("got error in gnu_hash_table\n");
        return -1;
    }
    //printf("GNU numbucks: 0x%x, bloom_size 0x%x\n", ght.nbuckets, ght.bloom_size);
    uint32_t* buckets = (uint32_t*) malloc(ght.nbuckets*sizeof(uint32_t));
    assert(buckets != NULL);

    target_ulong bucket_offset = gnu_hash + sizeof(gnu_hash_table) + (ght.bloom_size*sizeof(target_ulong));

    if (panda_virtual_memory_read(cpu, bucket_offset, (uint8_t*) buckets, ght.nbuckets*sizeof(uint32_t)) != MEMTX_OK){
        //printf("Couldn't read buckets\n");
        free(buckets);
        return -1;
    }

    unsigned int last_sym = 0;
    int index = 0;
    for (index = 0; index < ght.nbuckets; index++){
        //printf("%d %x\n", index, buckets[index]);
        if (buckets[index] > last_sym){
            last_sym = buckets[index]; 
        }
    }
    //printf("last_sym %x index: %d\n", last_sym, index);
    
    free(buckets);
    
    uint32_t num = 0;

    uint32_t chain_index = last_sym - ght.symoffset;
    target_ulong chain_address = bucket_offset + (sizeof(uint32_t)*ght.nbuckets);

    while (!(num&1)){
        if (panda_virtual_memory_read(cpu, chain_address + (chain_index * sizeof(uint32_t)), (uint8_t*) &num, sizeof(uint32_t))!= MEMTX_OK){                                
            //printf("Failed loading chains\n");
            return -1;
        }
        chain_index++;
    }
    return chain_index + ght.symoffset;
}

int get_numelements_symtab(CPUState* cpu, target_ulong base, target_ulong dt_hash, target_ulong gnu_hash, target_ulong dynamic_section, target_ulong symtab, int numelements_dyn){
    if (base != dt_hash){
        int result = get_numelements_hash(cpu, dt_hash);
        if (result != -1)
            return result;
    }
    if (base != gnu_hash){
        int result = get_numelements_gnu_hash(cpu, gnu_hash);
        if (result != -1)
            return result;
    }
    target_ulong symtab_min = symtab + 0x100000;
    ELF(Dyn) tag;
    for (int j=0; j< numelements_dyn; j++){
        if (panda_virtual_memory_read(cpu, dynamic_section + j*sizeof(ELF(Dyn)), (uint8_t*)&tag, sizeof(ELF(Dyn))) != MEMTX_OK){
            return -1;
        }
        fixupendian(tag.d_tag);
        fixupendian(tag.d_un.d_ptr);
        if (find(begin(possible_tags), end(possible_tags), (int)tag.d_tag) != end(possible_tags)){
            uint32_t candidate = tag.d_un.d_ptr;
            if (candidate > symtab && candidate < symtab_min){
                symtab_min = candidate;
            }
        }
    }
    return (symtab_min - symtab)/(sizeof(ELF(Dyn)));
}