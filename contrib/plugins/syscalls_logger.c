#include <stdio.h>
#include <qemu-plugin.h>
#include <plugin-qpp.h>
#include "syscalls.h"
#include "osi_linux/osi_types.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "syscalls_logger";
#include "osi.h"
 
void log_syscall(gpointer evdata, gpointer udata);

void log_syscall(gpointer evdata, gpointer udata)
{
  uint64_t pc = ((uint64_t*)evdata)[0];
  uint64_t callno = ((uint64_t*)evdata)[1];
  g_autoptr(GString) report = g_string_new("Syscall at ");
  g_string_append_printf(report, "pc %lx: number %ld.", pc, callno);
  OsiProc *p = get_current_process_qpp();
  if (p != NULL) {
    g_string_append_printf(report, ": %lx: %ld. Process '%s', pid %d, ppid %d, asid %lx\n", pc, callno, p->name, p->pid, p->ppid, p->asid);
    qemu_plugin_outs(report->str);
  }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv)
{
  qemu_plugin_reg_callback("syscalls", "on_all_sys_enter", log_syscall);
  return 0;
}
