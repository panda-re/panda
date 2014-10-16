/**
 * Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public 
 * License along with this program; if not, write to the Free 
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 * MA 02111-1307 USA
**/

/*
 * DECAF_main.c
 *
 *  Created on: Oct 14, 2012
 *      Author: lok
 */

#include "panda_wrapper.h"
int DECAF_read_mem_until(CPUState* env, gva_t vaddr, void* buf, size_t len)
{
  int i = 0;
  int ret = 0;

  if (buf == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  for (i = 0; i < len; i++)
  {
    ret = DECAF_read_mem(env, vaddr + i, buf + i, 1);
    if (ret != 0)
    {
      break;
    }
  }
  return (i);
}

DECAF_errno_t DECAF_memory_rw_with_pgd(CPUState* env, target_asid_t pgd, gva_t addr, void *buf, int len, int is_write)
{
  if (env == NULL)
  {
#ifdef DECAF_NO_FAIL_SAFE
    return (INV_ADDR);
#else
    env = cpu_single_env ? cpu_single_env : first_cpu;
#endif
  }

  int l;
  gpa_t page, phys_addr;

  while (len > 0) {
      page = addr & TARGET_PAGE_MASK;
      phys_addr = DECAF_get_phys_addr_with_pgd(env, pgd, page);
      if (phys_addr == -1)
          return -1;
      l = (page + TARGET_PAGE_SIZE) - addr;
      if (l > len)
          l = len;
      cpu_physical_memory_rw(phys_addr + (addr & ~TARGET_PAGE_MASK),
                             (uint8_t*)buf, l, is_write);
      len -= l;
      buf = (uint8_t*)buf + l;
      addr += l;
  }
  return 0;
}


#if defined(TARGET_ARM)

target_ulong DECAF_getESP(CPUState* env){
  if (env == NULL)
  {
    return (INV_ADDR);
  }
  return (env->regs[13]);
}
target_ulong DECAF_get_phys_addr_with_pgd(CPUState* env, target_asid_t pgd, gva_t addr)
{

  if (env == NULL)
  {
#ifdef DECAF_NO_FAIL_SAFE
    return (INV_ADDR);
#else
    env = cpu_single_env ? cpu_single_env : first_cpu;
#endif
  }


  target_ulong old = env->cp15.c2_base0;
  target_ulong old1 = env->cp15.c2_base1;
  target_ulong phys_addr;

  env->cp15.c2_base0 = pgd;
  env->cp15.c2_base1 = pgd;

  phys_addr = cpu_get_phys_page_debug(env, addr & TARGET_PAGE_MASK);

  env->cp15.c2_base0 = old;
  env->cp15.c2_base1 = old1;

  return (phys_addr | (addr & (~TARGET_PAGE_MASK)));
}
#define rPC 4
#define rFP 5
#define rGLUE 6
#define rINST 7
#define rIBASE 8

inline target_ulong getDalvikPC(CPUState* env)
{
  return (env->regs[rPC]);
}

inline target_ulong getDalvikFP(CPUState* env)
{
  return (env->regs[rFP]);
}

inline target_ulong getDalvikGLUE(CPUState* env)
{
  return (env->regs[rGLUE]);
}

inline target_ulong getDalvikINST(CPUState* env)
{
  return (env->regs[rINST]);
}

inline target_ulong getDalvikIBASE(CPUState* env)
{
  return (env->regs[rIBASE]);
}


#elif defined(TARGET_I386)
target_ulong DECAF_getESP(CPUState* env){
  if (env == NULL)
  {
    return (INV_ADDR);
  }

  return (env->regs[R_ESP]);

}

target_ulong DECAF_get_phys_addr_with_pgd(CPUState* env, target_asid_t pgd, gva_t addr)
{

  if (env == NULL)
  {
#ifdef DECAF_NO_FAIL_SAFE
    return (INV_ADDR);
#else
    env = cpu_single_env ? cpu_single_env : first_cpu;
#endif
  }

  target_ulong saved_cr3 = env->cr[3];
  uint32_t phys_addr;

  env->cr[3] = pgd;
  phys_addr = cpu_get_phys_page_debug(env, addr & TARGET_PAGE_MASK);

  env->cr[3] = saved_cr3;
  return (phys_addr | (addr & (~TARGET_PAGE_MASK)));
}
#else
#error Fail
#endif
