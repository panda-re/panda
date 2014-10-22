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
 * read_linux.c
 *
 * Copied from read_linux.c from 
 *
 *  Created on: Aug 31, 2011
 *      Author: lok
 */

/*
 * This tool depends on having a proper kernelinfo.conf file when
 * running DECAF. The file can be obtained by either populating the
 * values manually, or inserting a probe kernel module in the guest VM
 * kernel to extract them. The module along with further instructions
 * can be found in kernelinfo directory.
 */

#include "config.h"
#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#include <libgen.h>
#include <unistd.h>
#include <errno.h>

#include "linux_vmi_types.h"
#include "DECAF_linux_vmi.h"

gva_t taskaddr = 0;
int sizeof_task_struct = 0;
int task_struct_stack_offset = 4;
int task_struct_tasks_offset = 0;
int task_struct_pid_offset = 0;
int task_struct_tgid_offset = 0;
int task_struct_group_leader_offset = 0;
int task_struct_thread_group_offset = 0;
int task_struct_real_parent_offset = 0;
int task_struct_mm_offset = 0;
int task_struct_real_cred_offset = 0;
int task_struct_cred_offset = 0;
int cred_uid_offset = 0;
int cred_gid_offset = 0;
int cred_euid_offset = 0;
int cred_egid_offset = 0;
int mm_struct_mm_arg_start_offset = 0;
int mm_struct_start_brk_offset = 0;
int mm_struct_brk_offset = 0;
int mm_struct_start_stack_offset = 0;
int mm_struct_pgd_offset = 0;
int task_struct_comm_offset = 0;
int size_of_task_struct_comm = 0;
int vm_area_struct_vm_start_offset = 0;
int vm_area_struct_vm_end_offset = 0;
int vm_area_struct_vm_next_offset = 0;
int vm_area_struct_vm_file_offset = 0;
int vm_area_struct_vm_flags_offset = 0;
int file_f_dentry_offset = 0;
int file_vfsmnt_offset = 0;
int dentry_d_name_offset = 0;
int dentry_d_iname_offset = 0;
int dentry_d_parent_offset = 0;
int thread_info_task_offset = 0;
int file_f_path_offset = 0;
int path_dentry_offset = 0;
int path_mount_offset = 0;
int vfsmount_mnt_root_offset = 0;

gva_t DECAF_get_current_task_struct(CPUState* env)
{
  gva_t threadinfo = 0;
  gva_t curtask = 0;
  if (env == NULL)
  {
    return (0);
  }

  threadinfo = DECAF_getESP(env) & ~8191;
  DECAF_read_mem(env, threadinfo + thread_info_task_offset, &curtask, 4);
  return (curtask);
}

gva_t DECAF_get_current_process(CPUState* env)
{
  gva_t task = DECAF_get_current_task_struct(env);
  if (task == 0)
  {
    return (0);
  }
  return (DECAF_get_group_leader(env, task));
}

gva_t DECAF_get_next_task_struct(CPUState* env, gva_t addr)
{
  gva_t retval;
  if (addr == 0) //LOK: Added here to give the init_task
  {
    return (taskaddr);
  }
  else
  {
    // default is kernel 2.6
    gva_t next;
    if (DECAF_read_mem(env, addr + task_struct_tasks_offset, &next, sizeof(gva_t)) != 0)
    {
      return (0);
    }

    if (next == 0)
    {
      return (0);
    }
    retval = next - task_struct_tasks_offset;
  }

  return retval;
}

gva_t DECAF_get_prev_task_struct(CPUState* env, gva_t addr)
{
  gva_t retval;

  if (addr == 0) //LOK: Added here to give the init_task
  {
    return (taskaddr);
  }
  else
  {
    gva_t next;

    if (DECAF_read_mem(env, addr + task_struct_tasks_offset + sizeof(gva_t), &next, sizeof(gva_t)) != 0)
    {
      return (0);
    }

    if (next == 0)
    {
      return (0);
    }
    retval = next - task_struct_tasks_offset;
  }

  return retval;
}

target_asid_t DECAF_get_pgd(CPUState* env, gva_t addr)
{
  gva_t mmaddr;
  target_asid_t pgd;
  DECAF_read_mem(env, addr + task_struct_mm_offset, &mmaddr, sizeof(mmaddr));
  if (0 == mmaddr)
    DECAF_read_mem(env, addr + task_struct_mm_offset + sizeof(mmaddr),
                &mmaddr, sizeof(mmaddr));

  if (0 != mmaddr)
    DECAF_read_mem(env, mmaddr + mm_struct_pgd_offset, &pgd, sizeof(pgd));
  else
    memset(&pgd, 0, sizeof(pgd));

  return pgd;
}

int DECAF_get_name(CPUState* env, gva_t addr, char *buf, int size)
{
  return (DECAF_read_mem(env, addr + task_struct_comm_offset,
                buf, (size < size_of_task_struct_comm) ? size : size_of_task_struct_comm));
}

int DECAF_get_arg_name(CPUState* env, gva_t addr, char* buf, int size)
{
  gva_t mmaddr = 0;
  gva_t argstart = 0;
  target_asid_t pgd = 0;
  DECAF_read_mem(env, addr + task_struct_mm_offset, &mmaddr, sizeof(mmaddr));
  if (mmaddr == 0)
  {
    return (-1);
  }
  else
  {
    DECAF_read_mem(env, mmaddr + mm_struct_pgd_offset, &pgd, sizeof(pgd));
    DECAF_read_mem(env, mmaddr + mm_struct_mm_arg_start_offset, &argstart, sizeof(argstart));
    if (argstart != 0 && pgd != 0)
    {
      return (DECAF_read_mem_with_pgd(env, pgd & ~0xC0000000, argstart, buf, size));
    }
    else
    {
      return (-1);
    }
  }
}

gva_t DECAF_get_first_mmap(CPUState* env, gva_t task_addr)
{
  gva_t mmaddr = 0;
  gva_t mmap = 0;
  //DECAF_memory_rw_with_pgd(env, pgd, task_addr + task_struct_mm_offset, &mmaddr, sizeof(maddr), 0);
  DECAF_read_mem(env, task_addr + task_struct_mm_offset, &mmaddr, sizeof(mmaddr));
  //printf("Found mm_struct at 0x%X\n", mmaddr);
  if (0 != mmaddr)
  {
    DECAF_read_mem(env, mmaddr, &mmap, sizeof(mmap));
  }

  return mmap;
}

void DECAF_get_dentry_iname(CPUState* env, gva_t dentry_addr, char* name, int size)
{
  if (name == NULL)
  {
    return;
  }
  //there is something called DNAME_INLINE_LEN which is used, this can be it,
  // looks like max size is 40, so we should use that
  uint32_t DNAME_INLINE_LEN = 40;

  if (DECAF_memory_rw(env, dentry_addr + dentry_d_iname_offset, name, (size < DNAME_INLINE_LEN) ? size : DNAME_INLINE_LEN, 0) == 0)
  {
    name[(size < DNAME_INLINE_LEN) ? size - 1 : DNAME_INLINE_LEN - 1] = '\0';
  }
  else
  {
    name[0] = '\0';
  }
}

void DECAF_get_dentry_dname(CPUState* env, gva_t dentry_addr, char *name, int size)
{
  if (name == NULL)
  {
    return;
  }
  //a qstr is a data structure that looks like
  //long hash
  //long len
  //char* name

  gva_t len = 0;
  gva_t qstr_name = 0;

  name[0] = '\0';

  if ( (DECAF_memory_rw(env, dentry_addr + dentry_d_name_offset + sizeof(gva_t), &len,  sizeof(gva_t), 0) == -1)
      || (DECAF_memory_rw(env, dentry_addr + dentry_d_name_offset + sizeof(gva_t) + sizeof(gva_t), &qstr_name,  sizeof(gva_t), 0) == -1)
      )
  {
    return;
  }

  if (DECAF_memory_rw(env, qstr_name, name, (size < len) ? size : len, 0) == -1)
  {
    return;
  }
  //printf("found %uX bytes at 0x%X in dentry at 0x%X of name %s\n", len, dentry_addr + dentry_d_name_offset, dentry_addr, name);
  name[(size < len) ? size - 1 : len] = '\0';
}

static gva_t PANDA_get_dentry(CPUState* env, gva_t addr){
    gva_t dentry = 0;
    if(file_f_dentry_offset > 0){
        gva_t vmfile = 0;
        if (DECAF_memory_rw(env, addr + vm_area_struct_vm_file_offset, &vmfile, sizeof(vmfile), 0) == -1
            || DECAF_memory_rw(env, vmfile + file_f_dentry_offset, &dentry, sizeof(dentry), 0) == -1
            )
        {
            return 0 ;
        }
    } else {
        gva_t vmfile = 0;
        /* gva_t vmpath = 0; */
         if (DECAF_memory_rw(env, addr + vm_area_struct_vm_file_offset, &vmfile, sizeof(vmfile), 0) == -1
            || DECAF_memory_rw(env, vmfile + file_f_path_offset/*, &vmpath, sizeof(vmpath), 0) == -1
            || DECAF_memory_rw(env, vmpath*/ + path_dentry_offset, &dentry, sizeof(dentry), 0) == -1
            )
             return 0;
    }
    return dentry;
}

static gva_t PANDA_get_vfsmnt(CPUState* env, gva_t addr){
    gva_t vfsmnt = 0;
    if(file_f_dentry_offset > 0){
        gva_t vmfile = 0;
        if (DECAF_memory_rw(env, addr + vm_area_struct_vm_file_offset, &vmfile, sizeof(vmfile), 0) == -1
            || DECAF_memory_rw(env, vmfile + file_vfsmnt_offset, &vfsmnt, sizeof(vfsmnt), 0) == -1
            )
        {
            return 0 ;
        }
    } else {
        gva_t vmfile = 0;
        gva_t vmpath = 0;
         if (DECAF_memory_rw(env, addr + vm_area_struct_vm_file_offset, &vmfile, sizeof(vmfile), 0) == -1
            || DECAF_memory_rw(env, vmfile + file_f_path_offset, &vmpath, sizeof(vmpath), 0) == -1
            || DECAF_memory_rw(env, vmpath + path_mount_offset, &vfsmnt, sizeof(vfsmnt), 0) == -1
            )
             return 0;
    }
    return vfsmnt;
}

void DECAF_get_mod_iname(CPUState* env, gva_t addr, char* name, int size)
{

  gva_t dentry = PANDA_get_dentry(env, addr);
  name[0] = '\0';

  if (dentry == 0)
  {
     return;
  }

  DECAF_get_dentry_iname(env, dentry, name, size);
}

void DECAF_get_mod_dname(CPUState* env, gva_t addr, char *name, int size)
{
  //a qstr is a data structure that looks like
  //long hash
  //long len
  //char* name

  gva_t dentry = PANDA_get_dentry(env, addr);

  name[0] = '\0';

  if (dentry == 0)
  {
     return;
  }

  DECAF_get_dentry_dname(env, dentry, name, size);
}

/**
 * Concatenates two paths, dest is the parent and src is the current
 * idea is that dest will be dest/src after this function call
 * the number of src characters copied is returned
 */
inline size_t my_pathcat(char* dest, size_t destsize, const char* src)
{
  if ( (dest == NULL) || (src == NULL) )
  {
    return (0);
  }

  size_t i = strlen(dest);
  size_t j = 0;

  if ( (i < destsize) && (src[j] != '\0') )
  {
    dest[i] = '/';
    i++;
  }

  for ( ; (i < destsize) && (src[j] != '\0'); i++, j++)
  {
    dest[i] = src[j];
  }

  if (i < destsize)
  {
    dest[i] = '\0';
  }
  else
  {
    dest[destsize -1] = '\0';
  }

  return (j);
}

void DECAF_get_dentry_full_iname_path(CPUState* env, gva_t dentry_addr, char* name, int size)
{
  //do post order recursion?
  char temp[128] = "";
  if (name == NULL)
  {
    return;
  }

  name[0] = '\0';

  DECAF_get_dentry_iname(env, dentry_addr, temp, 128);

  if ( (temp[0] == '\0') || ((temp[0] == '/') && (temp[1] == '\0')) )
  {
    return;
  }

  gva_t parent = DECAF_get_dentry_d_parent(env, dentry_addr);
  if (parent == 0)
  {
    return;
  }

  //get parent's name here
  DECAF_get_dentry_full_iname_path(env, parent, name, size);

  //now append the current name
  my_pathcat(name, size, temp);
}

void DECAF_get_dentry_full_dname_path(CPUState* env, gva_t dentry_addr, char* name, int size, gva_t vfs_addr)
{
  //do post order recursion?
  char temp[128] = "";
  if (name == NULL)
  {
    return;
  }

  name[0] = '\0';

  DECAF_get_dentry_dname(env, dentry_addr, temp, 128);

  if ( (temp[0] == '\0') || ((temp[0] == '/') && (temp[1] == '\0')) )
  {
    return;
  }
  //printf("found initial dentry name %s\n", temp);

  gva_t parent = DECAF_get_dentry_d_parent(env, dentry_addr);
  if (parent == 0)
  {
    return;
  }
  // check if dentry_addr == vfsmnt.mnt_root
  //vfsmnt = file.f_path.vfsmnt
  gva_t mnt_root;
  DECAF_memory_rw(env, vfs_addr + vfsmount_mnt_root_offset, &mnt_root, sizeof(mnt_root), 0);
  if (dentry_addr == mnt_root){
     printf("MATCHING DENTRY AND ROOT\n"); 
  }

  //get parent's name here
  DECAF_get_dentry_full_dname_path(env, parent, name, size, vfs_addr);

  //now append the current name
  my_pathcat(name, size, temp);
}

void DECAF_get_mod_full_iname(CPUState* env, gva_t addr, char* name, int size)
{
  gva_t dentry = PANDA_get_dentry(env, addr);
    name[0] = '\0';

  if (dentry == 0)
  {
     return;
  }

  DECAF_get_dentry_full_iname_path(env, dentry, name, size);
}

void DECAF_get_mod_full_dname(CPUState* env, gva_t addr, char *name, int size)
{
  //a qstr is a data structure that looks like
  //long hash
  //long len
  //char* name
  //printf("Getting dnames for vm_area_struct at 0x%X\n", addr);
  gva_t dentry = PANDA_get_dentry(env, addr);
  gva_t vfsmnt = PANDA_get_vfsmnt(env, addr);
  
  name[0] = '\0';

  if (0 == dentry)
  {
     return;
  }

  DECAF_get_dentry_full_dname_path(env, dentry, name, size, vfsmnt);
}

#define KERNELINFO_DEFAULT_FILENAME "kernelinfo.conf"
#define BUFFER_SIZE 1024
#define VMI_INIT_SCANFMT "%[^,],%x,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d"
#ifdef PANDROID
	/*
	 * Declare functions that set compiled-in values for Android.
	 * XXX: These values should be moved in a configuration file.
	 */
#ifdef PANDROID_4_2
	int PANDROID_set_vars_jb4_2(void);
#else
	int PANDROID_set_vars(void);
#endif
#endif

int DECAF_linux_vmi_init_with_string(const char* pattern)
{
    int nexpected = 0;
    int nactual = 0;
    char version[128];
    int i;

    /* count the number of items expected to be scanned */
    for (i=0; VMI_INIT_SCANFMT[i]!='\0'; i++) {
        if (VMI_INIT_SCANFMT[i] == '%') {
            if (VMI_INIT_SCANFMT[i+1] != '\0' && VMI_INIT_SCANFMT[i+1] == '%')
                /* %% */
                i++;
            else
                nexpected++;
        }
    }

    errno = 0;
    nactual = sscanf(pattern, VMI_INIT_SCANFMT,
        version,
/* 0*/  (unsigned int *)&taskaddr,
        &sizeof_task_struct,
        &task_struct_tasks_offset,
        &task_struct_pid_offset,
        &task_struct_tgid_offset,
/* 5*/  &task_struct_group_leader_offset,
        &task_struct_thread_group_offset,
        &task_struct_real_parent_offset,
        &task_struct_mm_offset,
        &task_struct_stack_offset,
/*10*/  &task_struct_real_cred_offset,
        &task_struct_cred_offset,
        &cred_uid_offset,
        &cred_gid_offset,
        &cred_euid_offset,
/*15*/  &cred_egid_offset,
        &mm_struct_pgd_offset,
        &mm_struct_mm_arg_start_offset,
        &mm_struct_start_brk_offset,
        &mm_struct_brk_offset,
/*20*/  &mm_struct_start_stack_offset,
        &task_struct_comm_offset,
        &size_of_task_struct_comm,
        &vm_area_struct_vm_start_offset,
        &vm_area_struct_vm_end_offset,
/*25*/  &vm_area_struct_vm_next_offset,
        &vm_area_struct_vm_file_offset,
        &vm_area_struct_vm_flags_offset,
        &file_f_dentry_offset,
        &dentry_d_name_offset,
/*30*/  &dentry_d_iname_offset,
        &dentry_d_parent_offset,
        &thread_info_task_offset
    );

    if (nactual == nexpected)
        /* success */
        return 0;
    else if (errno != 0)
        /* -1 for scanf failure */
        return -1;
    else
        /* (positive) number of items not scanned */
        return nexpected-nactual;
}

/**
 * @name    Initializes DECAF for guest VM Introspection.
 *
 * Reads kernel struct offset and size information from a file.
 * The file name should be named "kernelinfo.conf" (currently
 * non configurable).
 *
 * @retval   0   Success.
 * @retval  -1   Error while parsing file contents.
 * @retval n>0   n items couln't be read from input file.
 */
int DECAF_linux_vmi_init(void)
{
    int i = 0;
    int retval = -1;
    int started = 0;
    int isbcomment = 0;
    int islcomment = 0;
    char pattern[BUFFER_SIZE];

#ifdef PANDROID
    /*
     * Use compiled-in values for Android.
     * XXX: The called functions should be moved in a configuration
     * file and read from there.
     */
#ifdef PANDROID_4_2
    PANDROID_set_vars_jb4_2();
#else
    PANDROID_set_vars();
#endif
    return 0;
#endif

    FILE * fd = fopen(KERNELINFO_DEFAULT_FILENAME, "ro");
    if (fd == NULL) return -1;

again:
    i = started = isbcomment = islcomment = 0;
    while (i < BUFFER_SIZE) {

        pattern[i] = fgetc(fd);
        if(pattern[i] == EOF) break;

        /* comment handling */
        switch(pattern[i]) {
            case '/':
                /* search for block/line comments start */
                pattern[i] = fgetc(fd);
                if(pattern[i] == '*')
                    isbcomment += 1;
                else if(pattern[i] == '/')
                    islcomment = 1;
                break;
            case '*':
                /* search for block comments end */
                pattern[i] = fgetc(fd);
                if(pattern[i] == '/')
                    isbcomment -= 1;
                break;
            case '\n':
                /* reset line comment flag */
                islcomment = 0;
                break;
        }

        /* skip when in a comment */
        if(isbcomment || islcomment) continue;

        /* pattern block start */
        if(pattern[i] == '{') {
            assert(!started || isbcomment || islcomment);
            started = 1;
            continue;
        }

        /* pattern block end (nested blocks not considered) */
        if(pattern[i] == '}') {
            pattern[i] = '\0';
            retval = DECAF_linux_vmi_init_with_string(pattern);

            if (retval == 0)
                /* end loop - all offsets successfully scanned */
                break;
            else
                /* retry with the remaining file */
                goto again;
        }

        /* not in a block - ignore character */
        if(!started) continue;

        /* character added to the pattern buffer */
        if(isdigit(pattern[i]) || isalpha(pattern[i]) || pattern[i] == ','
                || pattern[i] == '_' || pattern[i] == '.' || pattern[i] == '-')
            i++;
    }

    fclose(fd);
    return retval;
}








/*******************************************************************
 * Only stuff to be removed from this point on...                  *
 *******************************************************************/
#ifdef PANDROID
    /*
     * Functions for setting compiled-in values for Android.
     * XXX: The values in these functions should be moved in a
     * configuration file and read from there.
     */
#ifdef PANDROID_4_2
int PANDROID_set_vars_jb4_2(void){  //"Android-x86 Gingerbread", /* entry name */
       taskaddr = 0xC0336E08; /* task struct root */
       sizeof_task_struct =1000; /* size of task_struct */
       task_struct_tasks_offset =448; /* offset of task_struct list */
       task_struct_pid_offset =492; /* offset of pid */
       task_struct_tgid_offset =496; /* offset of tgid */
       task_struct_group_leader_offset =524; /* offset of group_leader */
       task_struct_thread_group_offset =580; /* offset of thread_group */
       task_struct_real_parent_offset =500; /* offset of real_parent */
       task_struct_mm_offset = 456; /* offset of mm */
       task_struct_stack_offset =4; /* offset of stack */
       task_struct_real_cred_offset = 704; /* offset of real_cred */
       task_struct_cred_offset = 708; /* offset of cred */
       cred_uid_offset = 4; /* offset of uid cred */
       cred_gid_offset = 8; /* offset of gid cred */
       cred_euid_offset = 20; /* offset of euid cred */
       cred_egid_offset = 24; /* offset of egid cred */
       mm_struct_pgd_offset = 36; /* offset of pgd in mm */
       mm_struct_mm_arg_start_offset =148; /* offset of arg_start in mm */
       mm_struct_start_brk_offset = 136; /* offset of start_brk in mm */
       mm_struct_brk_offset = 140; /* offset of brk in mm */
       mm_struct_start_stack_offset= 144; /* offset of start_stack in mm */
       task_struct_comm_offset =724; /* offset of comm */
       size_of_task_struct_comm = 16; /* size of comm */
       vm_area_struct_vm_start_offset = 4; /* offset of vm_start in vma */
       vm_area_struct_vm_end_offset = 8; /* offset of vm_end in vma */
       vm_area_struct_vm_next_offset =  12; /* offset of vm_next in vma */
       vm_area_struct_vm_file_offset = 72; /* offset of vm_file in vma */
       vm_area_struct_vm_flags_offset = 20; /* offset of vm_flags in vma */
       file_f_dentry_offset= 12; /* offset of dentry in file */
       dentry_d_name_offset =  28; /* offset of d_name in dentry */
       dentry_d_iname_offset = 88; /* offset of d_iname in dentry */
       dentry_d_parent_offset =24; /* offset of d_parent in dentry */
       thread_info_task_offset = 12; /* offset of task in thread_info */
       return 0;

}
#else
int PANDROID_set_vars(void){
    taskaddr = 0xc0310fa0;
    sizeof_task_struct = 1000;
    task_struct_stack_offset = 4;
    task_struct_comm_offset = 724;
    task_struct_pid_offset = 492;
    task_struct_tasks_offset = 448;
    task_struct_tgid_offset = 496;
    task_struct_group_leader_offset = 524;
    task_struct_thread_group_offset = 580;
    task_struct_real_parent_offset = 500;
    task_struct_mm_offset = 456;
    task_struct_real_cred_offset = 704;
    task_struct_cred_offset = 708;
    cred_uid_offset = 4;
    cred_gid_offset = 8;
    cred_euid_offset = 20;
    cred_egid_offset = 24;
    mm_struct_pgd_offset = 36;
    mm_struct_mm_arg_start_offset = 148;
    mm_struct_start_brk_offset = 136;
    mm_struct_brk_offset = 140;
    mm_struct_start_stack_offset= 144;
    size_of_task_struct_comm = 16;
    vm_area_struct_vm_start_offset = 4;
    vm_area_struct_vm_end_offset = 8;
    vm_area_struct_vm_next_offset =  12;
    vm_area_struct_vm_file_offset = 72;
    vm_area_struct_vm_flags_offset = 20;
    file_f_dentry_offset = -1;
    file_f_path_offset = 8;
    path_dentry_offset = 4;
    dentry_d_name_offset = 28;
    dentry_d_iname_offset = 88;
    dentry_d_parent_offset = 24;
    thread_info_task_offset = 12;
    path_mount_offset = 0;
    vfsmount_mnt_root_offset = 16;
    file_vfsmnt_offset = -1;
    return 0;
}
#endif /* #ifdef PANDROID_4_2 */
#endif /* #ifdef PANDROID */



#if 0 //goldfish_audio.c example
static int __init goldfish_audio_init(void)
{
  int ret;

  struct vm_area_struct vma;
  struct file filestruct;
  struct dentry dentrystr;
  struct cred credstruct;
  struct thread_info ti;

  printk(KERN_INFO
      "    {  \"%s\", /* entry name */\n"
      "       0x%08lX, /* task struct root */\n"
      "       %d, /* size of task_struct */\n"
      "       %d, /* offset of task_struct list */\n"
      "       %d, /* offset of pid */\n"
      "       %d, /* offset of tgid */\n"
      "       %d, /* offset of group_leader */\n"
      "       %d, /* offset of thread_group */\n"
      "       %d, /* offset of real_parent */\n"
      "       %d, /* offset of mm */\n"
      "       %d, /* offset of stack */\n"
      "       %d, /* offset of real_cred */\n"
      "       %d, /* offset of cred */\n"
      "       %d, /* offset of uid cred */\n"
      "       %d, /* offset of gid cred */\n"
      "       %d, /* offset of euid cred */\n"
      "       %d, /* offset of egid cred */\n"
      "       %d, /* offset of pgd in mm */\n"
      "       %d, /* offset of arg_start in mm */\n"
      "       %d, /* offset of start_brk in mm */\n"
      "       %d, /* offset of brk in mm */\n"
      "       %d, /* offset of start_stack in mm */\n",

      "Android-x86 Gingerbread",
      (long)&init_task,
      sizeof(init_task),
      (int)&init_task.tasks - (int)&init_task,
      (int)&init_task.pid - (int)&init_task,
      (int)&init_task.tgid - (int)&init_task,
      (int)&init_task.group_leader - (int)&init_task,
      (int)&init_task.thread_group - (int)&init_task,
      (int)&init_task.real_parent - (int)&init_task,
      (int)&init_task.mm - (int)&init_task,
      (int)&init_task.stack - (int)&init_task,
      (int)&init_task.real_cred - (int)&init_task,
      (int)&init_task.cred - (int)&init_task,
      (int)&credstruct.uid - (int)&credstruct,
      (int)&credstruct.gid - (int)&credstruct,
      (int)&credstruct.euid - (int)&credstruct,
      (int)&credstruct.egid - (int)&credstruct,
      (int)&init_task.mm->pgd - (int)init_task.mm,
      (int)&init_task.mm->arg_start - (int)init_task.mm,
      (int)&init_task.mm->start_brk - (int)init_task.mm,
      (int)&init_task.mm->brk - (int)init_task.mm,
      (int)&init_task.mm->start_stack - (int)init_task.mm
  );

  printk(KERN_INFO
      "       %d, /* offset of comm */\n"
      "       %d, /* size of comm */\n"
      "       %d, /* offset of vm_start in vma */\n"
      "       %d, /* offset of vm_end in vma */\n"
      "       %d, /* offset of vm_next in vma */\n"
      "       %d, /* offset of vm_file in vma */\n"
      "       %d, /* offset of vm_flags in vma */\n"
      "       %d, /* offset of dentry in file */\n"
      "       %d, /* offset of d_name in dentry */\n"
      "       %d, /* offset of d_iname in dentry */\n"
      "       %d, /* offset of d_parent in dentry */\n"
      "       %d, /* offset of task in thread_info */\n"
      "    },\n",

      (int)&init_task.comm - (int)&init_task,
      sizeof(init_task.comm),
      (int)&vma.vm_start - (int)&vma,
      (int)&vma.vm_end - (int)&vma,
      (int)&vma.vm_next - (int)&vma,
      (int)&vma.vm_file - (int)&vma,
      (int)&vma.vm_flags - (int)&vma,
      (int)&filestruct.f_dentry - (int)&filestruct,
      (int)&dentrystr.d_name - (int)&dentrystr,
      (int)&dentrystr.d_iname - (int)&dentrystr,
      (int)&dentrystr.d_parent - (int)&dentrystr,
      (int)&ti.task - (int)&ti
    );


  ret = platform_driver_register(&goldfish_audio_driver);
  if (ret < 0)
  {
    printk("platform_driver_register returned %d\n", ret);
    return ret;
  }

  return ret;
}
#endif

