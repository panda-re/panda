/**
 * This file declares C++ Pandalog functions that can be called from C code
 * These are just wrappers for the actual C++ implementation
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

// Open C++ pandalog for read
void pandalog_cc_init_read(const char* path);

//Open for read backwards
void pandalog_cc_init_read_bwd(const char* path);

//Open C++ pandalog for write
void pandalog_cc_init_write(const char* path);

//Seek to an instr
void pandalog_cc_seek(uint64_t instr);

#ifdef __cplusplus
}
#endif
