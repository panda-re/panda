// for direct access to -d logginf flags
// unsigned is a lie, but it's the way QEMU treats it
extern unsigned int qemu_loglevel;
extern FILE* qemu_logfile;

MemoryRegion *get_system_memory(void);