#ifndef __FILE_TAINT_H_
#define __FILE_TAINT_H_

typedef void (* on_file_byte_read_t)(CPUState *cpu, target_ulong virt_addr, uint32_t file_offset);

#endif
