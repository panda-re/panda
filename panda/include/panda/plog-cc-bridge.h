/**
 * This file declares C++ Pandalog functions that are called from C code
 * The global PandaLog is created in plog-cc.cpp
 *
 */

#ifdef __cplusplus
extern "C" {
#endif
// global C++ PandaLog initialization function that is called in vl.c
void pandalog_init(const char *fname);

// Closes global C++ pandalog in common.c
void pandalog_cc_close(void);

//Interface for plog.c to pass a packed protobuf entry to C++ pandalog
void pandalog_write_packed(size_t entry_size, unsigned char* buf);

// Interface for plog.c to read an entry
unsigned char* pandalog_read_packed(void);

void pandalog_cc_init_read(const char* path);
void pandalog_cc_init_read_bwd(const char* path);
void pandalog_cc_init_write(const char* path);

void pandalog_cc_seek(uint64_t instr);

#ifdef __cplusplus
}
#endif
