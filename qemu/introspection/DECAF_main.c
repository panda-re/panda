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
#define DECAF_PANDA_WRAPPER
#ifndef DECAF_PANDA_WRAPPER
#include <dlfcn.h>
#include "sysemu.h"

#include "introspection/DECAF_config.h"

#include "introspection/DECAF_main.h"
#include "introspection/DECAF_main_internal.h"
#include "introspection/DECAF_vm_compress.h"
#include "introspection/DECAF_cmds.h"
//#include "DECAF_shared/procmod.h" //remove this later

int should_monitor = 1;

plugin_interface_t *decaf_plugin = NULL;
static void *plugin_handle = NULL;
static char decaf_plugin_path[PATH_MAX] = "";
static FILE *decaflog = NULL;

#include "introspection/DECAF_mon_cmds_defs.h"

mon_cmd_t DECAF_mon_cmds[] = {
  #include "DECAF_mon_cmds.h"
  {NULL, NULL, },
};

mon_cmd_t DECAF_info_cmds[] = {
  #include "DECAF_info_cmds.h"
  {NULL, NULL, },
};

gpa_t DECAF_get_phys_addr(CPUState* env, gva_t addr)
{
    int mmu_idx, index;
    gpa_t phys_addr;

    if (env == NULL)
    {
  #ifdef DECAF_NO_FAIL_SAFE
      return(INV_ADDR);
  #else
      env = cpu_single_env ? cpu_single_env : first_cpu;
  #endif
    }

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = cpu_mmu_index(env);
    if (__builtin_expect(env->tlb_table[mmu_idx][index].addr_read !=
                         (addr & TARGET_PAGE_MASK), 0)) {
	if(__builtin_expect(env->tlb_table[mmu_idx][index].addr_code !=
		(addr & TARGET_PAGE_MASK), 0)) {
		phys_addr = cpu_get_phys_page_debug(env, addr & TARGET_PAGE_MASK);
		if (phys_addr == -1)
		    return -1;
		phys_addr += addr & (TARGET_PAGE_SIZE - 1);
		return phys_addr;
	}
    }
#if 0                           //not sure if we need it --Heng Yin
    pd = env->tlb_table[mmu_idx][index].addr_read & ~TARGET_PAGE_MASK;
    if (pd > IO_MEM_ROM && !(pd & IO_MEM_ROMD)) {
        cpu_abort(env,
                  "Trying to execute code outside RAM or ROM at 0x"
                  TARGET_FMT_lx "\n", addr);
    }
#endif
    return (gpa_t) qemu_ram_addr_from_host_nofail (
		(void*)((addr & TARGET_PAGE_MASK) + 
		env->tlb_table[mmu_idx][index].addend));
}




DECAF_errno_t DECAF_memory_rw(CPUState* env, gva_t addr, void *buf, int len, int is_write)
{
    int l;
    gpa_t page, phys_addr;

    if (env == NULL)
    {
  #ifdef DECAF_NO_FAIL_SAFE
      return(INV_ADDR);
  #else
      env = cpu_single_env ? cpu_single_env : first_cpu;
  #endif
    }

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        phys_addr = DECAF_get_phys_addr(env, page);
        if (phys_addr == -1 || phys_addr > ram_size) {
            return -1;
        }
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;

        cpu_physical_memory_rw(phys_addr + (addr & ~TARGET_PAGE_MASK),
                   buf, l, is_write);

        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}

DECAF_errno_t DECAF_memory_rw_with_pgd(CPUState* env, gpa_t pgd, gva_t addr, void *buf, int len, int is_write)
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
                             buf, l, is_write);
      len -= l;
      buf += l;
      addr += l;
  }
  return 0;
}

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

static TranslationBlock *DECAF_tb_find_slow(CPUState *env, target_ulong pc) {
	TranslationBlock *tb, **ptb1;
	unsigned int h;
	tb_page_addr_t phys_pc, phys_page1;
	target_ulong virt_page2;

	tb_invalidated_flag = 0;

//DECAF_printf("DECAF_tb_find_slow: phys_pc=%08x\n", phys_pc);

	for (h = 0; h < CODE_GEN_PHYS_HASH_SIZE; h++) {
		ptb1 = &tb_phys_hash[h];
		for (;;) {
			tb = *ptb1;
			if (!tb)
				break;
			if (tb->pc + tb->cs_base == pc) {
				goto found;
			}
			ptb1 = &tb->phys_hash_next;
		}
	}

	not_found:
	//DECAF_printf("DECAF_tb_find_slow: not found!\n");
	return NULL ;

	found:
	//DECAF_printf("DECAF_tb_find_slow: found! pc=%08x size=%08x\n",tb->pc, tb->size);
	return tb;
}

#if 0
static TranslationBlock *DECAF_tb_find_slow(CPUState *env,
                                      gva_t pc,
                                      gva_t cs_base,
                                      uint64_t flags)
{
    TranslationBlock *tb, **ptb1;
    unsigned int h;
    tb_page_addr_t phys_pc, phys_page1;
    gva_t virt_page2;

    tb_invalidated_flag = 0;

    /* find translated block using physical mappings */
#ifdef QEMU_ANDROID_GINGERBREAD // I don't know why the change
    phys_pc = get_phys_addr_code(env, pc);
#else
    phys_pc = get_page_addr_code(env, pc);
#endif
    //LOK: if its not in the mappings then we can short circuit this whole process
    if (phys_pc == -1) //they use -1 (INV_ADDR) as well.
    {
      return (NULL);
    }

    phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_phys_hash_func(phys_pc);
    ptb1 = &tb_phys_hash[h];
    for(;;) {
        tb = *ptb1;
        if (!tb)
            goto not_found;
        if (tb->pc == pc &&
            tb->page_addr[0] == phys_page1 &&
            tb->cs_base == cs_base &&
            tb->flags == flags) {
            /* check next page if needed */
            if (tb->page_addr[1] != -1) {
                tb_page_addr_t phys_page2;

                virt_page2 = (pc & TARGET_PAGE_MASK) +
                    TARGET_PAGE_SIZE;
#ifdef QEMU_ANDROID_GINGERBREAD
                phys_page2 = get_phys_addr_code(env, virt_page2);
#else
                phys_page2 = get_page_addr_code(env, virt_page2);
#endif
                if (tb->page_addr[1] == phys_page2)
                    goto found;
            } else {
                goto found;
            }
        }
        ptb1 = &tb->phys_hash_next;
    }

 not_found:

#if 0 //LOK: Instead of calling gen_code - we just return NULL
   /* if no translated code available, then translate it now */
    tb = tb_gen_code(env, pc, cs_base, flags, 0);
#endif

  return (NULL);

 found:

#if 0 //LOK: Similarly we don't want to mess around with the cache or anything
  // so we just return
    /* Move the last found TB to the head of the list */
    if (likely(*ptb1)) {
        *ptb1 = tb->phys_hash_next;
        tb->phys_hash_next = tb_phys_hash[h];
        tb_phys_hash[h] = tb;
    }
    /* we add the TB in the virtual pc hash table */
    env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
#endif

    return tb;
}

#endif 

// This is the same as tb_find_fast except we invalidate at the end
void DECAF_flushTranslationBlock_env(CPUState *env, gva_t addr)
{
    TranslationBlock *tb;
    gva_t cs_base, pc;
    int flags;

    if (env == NULL)
    {
#ifdef DECAF_NO_FAIL_SAFE
      return;
#else
      env = cpu_single_env ? cpu_single_env : first_cpu;
#endif

    }

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
//    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
//    tb = env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
//    if (unlikely(!tb || tb->pc != pc || tb->cs_base != cs_base ||
//                 tb->flags != flags)) {
//        tb = DECAF_tb_find_slow(env, pc, cs_base, flags);
//    }
tb = DECAF_tb_find_slow(env, addr);
    if (tb == NULL)
    {
      return;
    }

    //this is what we added
    tb_phys_invalidate(tb, -1);
}

void DECAF_flushTranslationPage_env(CPUState* env, gva_t addr)
{
  target_phys_addr_t p_addr;

  if (env == NULL)
  {
#ifdef DECAF_NO_FAIL_SAFE
    return;
#else
    env = cpu_single_env ? cpu_single_env : first_cpu;
#endif
  }

#if 0 // From decaf main
  p_addr = cpu_get_phys_page_debug(env, addr);
  if (p_addr != -1)
  {
    p_addr &= TARGET_PAGE_MASK;
    tb_invalidate_phys_page_range(p_addr, p_addr + TARGET_PAGE_SIZE, 0); //not sure if this will work, but might as well try it
  }

#else

	TranslationBlock *tb = DECAF_tb_find_slow(env, addr);
	if (tb) {
		tb_invalidate_phys_page_range(tb->page_addr[0],
				tb->page_addr[0] + TARGET_PAGE_SIZE, 0);
	}

#endif
}

int do_load_plugin(Monitor *mon, const QDict *qdict, QObject **ret_data)
{
    DECAF_do_load_plugin_internal(mon, qdict_get_str(qdict, "filename"));
    return (0);
}

void DECAF_do_load_plugin_internal(Monitor *mon, const char *plugin_path)
{
    plugin_interface_t *(*init_plugin) (void);
    char *error;

    if (decaf_plugin_path[0]) {
        monitor_printf(mon, "%s has already been loaded! \n", plugin_path);
        return;
    }

    plugin_handle = dlopen(plugin_path, RTLD_NOW);
    if (NULL == plugin_handle) {
        // AWH
        char tempbuf[128];
        strncpy(tempbuf, dlerror(), 127);
        monitor_printf(mon, "%s\n", tempbuf);
        fprintf(stderr, "%s COULD NOT BE LOADED - ERR = [%s]\n",
                plugin_path, tempbuf);
        //assert(0);
        return;
    }

    dlerror();

    init_plugin = dlsym(plugin_handle, "init_plugin");
    if ((error = dlerror()) != NULL) {
        fprintf(stderr, "%s\n", error);
        dlclose(plugin_handle);
        plugin_handle = NULL;
        return;
    }

    decaf_plugin = init_plugin();

    if (NULL == decaf_plugin) {
        monitor_printf(mon, "fail to initialize the plugin!\n");
        dlclose(plugin_handle);
        plugin_handle = NULL;
        return;
    }

    decaflog = fopen("decaf.log", "w");
    assert(decaflog != NULL);

    if (decaf_plugin->bdrv_open) 
    {
        BlockInterfaceType interType = IF_NONE;
        int index = 0;
        DriveInfo *drvInfo = NULL;
        for (interType = IF_NONE; interType < IF_COUNT; interType++)
        {
          index = 0;
          do
          {
            //LOK: Older qemu versions don't have this function
            // so we just inline the new definition - it 
            // gets pretty involved
#ifndef QEMU_ANDROID_GINGERBREAD
            drvInfo = drive_get_by_index(interType, index);
#else
            int _bus_id = 0;
            int _unit_id = 0;
            int _max_devs = 0;
            //static const int if_max_devs[IF_COUNT] = {
            // [IF_IDE] = 2,
            // [IF_SCSI] = 7,
            //}
            if (interType == IF_IDE)
            {
              _max_devs = 2;
            }
            else if (interType == IF_SCSI)
            {
              _max_devs = 7;
            }
            //static int drive_index_to_bus_id(BlockInterfaceType type, int index)
            //{
            //    int max_devs = if_max_devs[type];
            //    return max_devs ? index / max_devs : 0;
            //}
            _bus_id = _max_devs ? index / _max_devs : 0;
            //static int drive_index_to_unit_id(BlockInterfaceType type, int index)
            //{
            //    int max_devs = if_max_devs[type];
            //    return max_devs ? index % max_devs : index;
            //}
            _unit_id = _max_devs ? index % _max_devs : index;

            drvInfo = drive_get(interType, 
                                //drive_index_to_bus_id(interType, index),
                                _bus_id,
                                //drive_index_to_uint_id(interType, index));
                                _unit_id);
#endif
            if (drvInfo && drvInfo->bdrv)
              decaf_plugin->bdrv_open(interType, index, drvInfo->bdrv);
            index++;
          } while (drvInfo);
        }
    }

    strncpy(decaf_plugin_path, plugin_path, PATH_MAX);
    monitor_printf(mon, "%s is loaded successfully!\n", plugin_path);
}

int do_unload_plugin(Monitor *mon, const QDict *qdict, QObject **ret_data)
{
    if (decaf_plugin_path[0]) {
        decaf_plugin->plugin_cleanup();
        fclose(decaflog);
        decaflog = NULL;

        //Flush all the callbacks that the plugin might have registered for
        //hookapi_flush_hooks(decaf_plugin_path);
        // NOT NEEDED HERE!! cleanup_insn_cbs();
//LOK: Created a new callback interface for procmod
        //        loadmainmodule_notify = createproc_notify = removeproc_notify = loadmodule_notify = NULL;

        dlclose(plugin_handle);
        plugin_handle = NULL;
        decaf_plugin = NULL;

#if 0 //LOK: Removed // AWH TAINT_ENABLED
        taintcheck_cleanup();
#endif
        monitor_printf(default_mon, "%s is unloaded!\n", decaf_plugin_path);
        decaf_plugin_path[0] = 0;
    }
    else
    {
        monitor_printf(default_mon, "Can't unload plugin because no plugin was loaded!\n");
    }

    return (0);
}


void DECAF_stop_vm(void)
{
/*  CPUState *env = cpu_single_env? cpu_single_env: mon_get_cpu();
  env->exception_index = EXCP_HLT;
  longjmp(env->jmp_env, 1); */
#ifdef QEMU_ANDROID_GINGERBREAD
//LOK: In the QEMU version in gingerbread, we can't use RUN_STATE_PAUSED - not
// introduced yet
    vm_stop(EXCP_INTERRUPT);
#else
    vm_stop(RUN_STATE_PAUSED);
#endif
}

void DECAF_start_vm(void)
{
    vm_start();
}

void DECAF_loadvm(void *opaque)
{
    char **loadvm_args = opaque;
    if (loadvm_args[0]) {
#ifdef QEMU_ANDROID_GINGERBREAD
        do_loadvm(default_mon, loadvm_args[0]);
#else
        load_vmstate(loadvm_args[0]);
#endif
        free(loadvm_args[0]);
        loadvm_args[0] = NULL;
    }

    if (loadvm_args[1]) {
        DECAF_do_load_plugin_internal(default_mon, loadvm_args[1]);
        free(loadvm_args[1]);
        loadvm_args[1] = NULL;
    }

    if (loadvm_args[2]) {
        DECAF_after_loadvm(loadvm_args[2]);
        free(loadvm_args[2]);
        loadvm_args[2] = NULL;
    }
}

static FILE *guestlog = NULL;

static void DECAF_save(QEMUFile * f, void *opaque)
{
    size_t len = strlen(decaf_plugin_path) + 1;
    qemu_put_be32(f, len);
    qemu_put_buffer(f, (const uint8_t *)decaf_plugin_path, len); // AWH - cast

    //save guest.log
    //we only save guest.log when no plugin is loaded
    if (len == 1) {
        FILE *fp = fopen("guest.log", "r");
        size_t size;
        if (!fp) {
            fprintf(stderr, "cannot open guest.log!\n");
            return;
        }

        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        qemu_put_be32(f, size);
        rewind(fp);
        if (size > 0) {
            DECAF_CompressState_t state;
            if (DECAF_compress_open(&state, f) < 0)
                return;

            while (!feof(fp)) {
                uint8_t buf[4096];
                size_t res = fread(buf, 1, sizeof(buf), fp);
                DECAF_compress_buf(&state, buf, res);
            }

            DECAF_compress_close(&state);
        }
        fclose(fp);
    }

    qemu_put_be32(f, 0x12345678);       //terminator
}

static int DECAF_load(QEMUFile * f, void *opaque, int version_id)
{
    size_t len = qemu_get_be32(f);
    char tmp_plugin_path[PATH_MAX];

    if (plugin_handle)
    {
      do_unload_plugin(NULL, NULL, NULL); // AWH - Added NULLs
    }
    qemu_get_buffer(f, (uint8_t *)tmp_plugin_path, len); // AWH - cast
    if (tmp_plugin_path[len - 1] != 0)
        return -EINVAL;

    //load guest.log
    if (len == 1) {
        fclose(guestlog);
        if (!(guestlog = fopen("guest.log", "w"))) {
            fprintf(stderr, "cannot open guest.log for write!\n");
            return -EINVAL;
        }

        size_t file_size = qemu_get_be32(f);
        uint8_t buf[4096];
        size_t i;
        DECAF_CompressState_t state;
        if (DECAF_decompress_open(&state, f) < 0)
            return -EINVAL;

        for (i = 0; i < file_size;) {
            size_t len =
                (sizeof(buf) <
                 file_size - i) ? sizeof(buf) : file_size - i;
            if (DECAF_decompress_buf(&state, buf, len) < 0)
                return -EINVAL;

            fwrite(buf, 1, len, guestlog);
            i += len;
        }
        DECAF_decompress_close(&state);
        fflush(guestlog);
    }

    if (len > 1)
        DECAF_do_load_plugin_internal(default_mon, tmp_plugin_path);

    uint32_t terminator = qemu_get_be32(f);
    if (terminator != 0x12345678)
        return -EINVAL;

    return 0;
}


extern void init_hookapi(void);
extern void function_map_init(void);
extern void DECAF_callback_init(void);


void DECAF_init(void)
{
  DECAF_callback_init();

  //DECAF_virtdev_init();

    // AWH - change in API, added NULL as first parm
   /* Aravind - NOTE: TEMU_save *must* be called before function_map_save and TEMU_load must be called
    * before function_map_load for function maps to load properly during loadvm.
    * This is because, TEMU_load restores guest.log, which is read into function map.
    */
    REGISTER_SAVEVM(NULL, "TEMU", 0, 1, DECAF_save, DECAF_load, NULL);
  
    DECAF_vm_compress_init();

    //init_hookapi();

    DS_init(); 
    /** Replaced these wih DroidScope's Versions
    function_map_init();
    procmod_init();
    **/
}


/*
 * NIC related functions
 */

void DECAF_nic_receive(const uint8_t * buf, int size, int cur_pos,
                      int start, int stop)
{
    if (decaf_plugin && decaf_plugin->nic_recv)
        decaf_plugin->nic_recv((uint8_t *) buf, size, cur_pos, start, stop);
}


void DECAF_nic_send(gva_t addr, int size, uint8_t * buf)
{
    if (decaf_plugin && decaf_plugin->nic_send)
        decaf_plugin->nic_send(addr, size, buf);
}


void DECAF_nic_out(gva_t addr, int size)
{
    if (!DECAF_emulation_started)
        return;
#if 0 //LOK: Removed // AWH TAINT_ENABLED
    taintcheck_nic_out(addr, size);
#endif
}


void DECAF_nic_in(gva_t addr, int size)
{
    if (!DECAF_emulation_started)
        return;
#if 0 //LOK: Removed // AWH TAINT_ENABLED
    taintcheck_nic_in(addr, size);
#endif
}

#if 0 //LOK: Removed - why is this here in the first place?
/*
 * keyboard related functions
 */
void *DECAF_KbdState = NULL;

void DECAF_read_keystroke(void *s)
{
    if (s != DECAF_KbdState)
        return;

    if (decaf_plugin && decaf_plugin->send_keystroke)
        decaf_plugin->send_keystroke(cpu_single_env->tempidx);
}

static void DECAF_virtdev_write_data(void *opaque, gva_t addr,
                target_ulong val)
{
        static char syslogline[GUEST_MESSAGE_LEN];
        static int pos = 0;

        if (pos >= GUEST_MESSAGE_LEN - 2)
                pos = GUEST_MESSAGE_LEN;

        if ((syslogline[pos++] = (char) val) == 0) {
                handle_guest_message(syslogline);
                fprintf(guestlog, "%s", syslogline);
                fflush(guestlog);
                pos = 0;
        }
}


void DECAF_virtdev_init(void)
{
        int res = register_ioport_write(0x68, 1, 1, DECAF_virtdev_write_data, NULL);
        if (res) {
                fprintf(stderr, "failure on initializing TEMU virtual device\n");
                exit(-1);
        }
#if !defined(_REPLAY_) || defined(_RECORD_)
        if (!(guestlog = fopen("guest.log", "w"))) {
                fprintf(stderr, "failure on opening guest.log \n");
                exit(-1);
        }
#endif
}

#endif 

void DECAF_after_loadvm(const char *param)
{
    if (decaf_plugin && decaf_plugin->after_loadvm)
        decaf_plugin->after_loadvm(param);
}

int DECAF_bdrv_pread(void *bs, int64_t offset, void *buf, int count)
{
    return bdrv_pread((BlockDriverState *) bs, offset, buf, count);
}

#else // DECAF or PANDA backend: PANDA
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

DECAF_errno_t DECAF_memory_rw_with_pgd(CPUState* env, gpa_t pgd, gva_t addr, void *buf, int len, int is_write)
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
target_ulong DECAF_get_phys_addr_with_pgd(CPUState* env, target_ulong pgd, gva_t addr)
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

target_ulong DECAF_get_phys_addr_with_pgd(CPUState* env, target_ulong pgd, gva_t addr)
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
#endif // DECAF or PANDA backend
