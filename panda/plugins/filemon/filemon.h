
#ifndef __FILEMON_H__
#define __FILEMON_H__

PPP_CB_TYPEDEF(void, on_file_read, target_ulong pid, target_ulong tid, target_ulong fid, target_ulong size, target_ulong buffer, uint64_t start_pos);

PPP_CB_TYPEDEF(void, on_file_write, target_ulong pid, target_ulong tid, target_ulong fid,  target_ulong size, target_ulong buffer, uint64_t start_pos);



#endif
