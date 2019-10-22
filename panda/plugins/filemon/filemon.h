
#ifndef __FILEMON_H__
#define __FILEMON_H__

typedef void (*on_file_read_t)(target_ulong pid, target_ulong tid, target_ulong fid,
                               target_ulong size, target_ulong buffer, uint64_t start_pos);

typedef void (*on_file_write_t)(target_ulong pid, target_ulong tid, target_ulong fid,
                                target_ulong size, target_ulong buffer, uint64_t start_pos);



#endif
