/**
 * This file simply declares a global C++ PandaLog initialization function that is called in vl.c
 * The global PandaLog is created in plog-cc.cpp
 *
 */

#ifdef __cplusplus
extern "C" {
#endif
void pandalog_init(const char *fname);
void pandalog_cc_close(void);
#ifdef __cplusplus
}
#endif
