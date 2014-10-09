
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

#ifndef PANDA_WRAPPER_H
#define PANDA_WRAPPER_H


#include "panda_plugin.h"
#include "linux_vmi_types.h"

#define DECAF_memory_rw(_env, _vaddr, _buf, _len, _write) \
        panda_virtual_memory_rw(_env, _vaddr, (uint8_t*) _buf, _len, _write)
#define DECAF_read_mem(_env, _vaddr, _buf, _len) \
        panda_virtual_memory_rw(_env, _vaddr, (uint8_t*) _buf, _len, 0)

#define DECAF_write_mem(_env, _vaddr, _buf, _len) \
        panda_virtual_memory_rw(_env, _vaddr, (uint8_t*)_buf, _len, 1)
#define DECAF_read_mem_with_pgd(_env, _pgd, _vaddr, _buf, _len) \
        DECAF_memory_rw_with_pgd(_env, _pgd, _vaddr, _buf, _len, 0)

#define DECAF_read_mem_with_cr3(_env, _pgd, _vaddr, _len, _buf) \
        DECAF_read_mem_with_pgd(_env, _pgd, _vaddr, _len, _buf)

#define DECAF_write_mem_with_pgd(_env, _pgd, _vaddr, _buf, _len) \
        DECAF_memory_rw_with_pgd(_env, _pgd, _vaddr, _buf, _len, 1)

#define DECAF_write_mem_with_cr3(_env, _pgd, _vaddr, _len, _buf) \
        DECAF_write_mem_with_pgd(_env, _pgd, _vaddr, _len, _buf)

target_ulong DECAF_getESP(CPUState* env);
target_ulong DECAF_get_phys_addr_with_pgd(CPUState* env, target_ulong pgd, gva_t addr);
DECAF_errno_t DECAF_memory_rw_with_pgd(CPUState* env, target_ulong pgd, gva_t addr, void *buf,
                            int len, int is_write);




int DECAF_read_mem_until(CPUState* env, gva_t vaddr, void* buf, size_t len);

#endif