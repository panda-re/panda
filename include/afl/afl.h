#ifndef __AFL_QEMU_COMMON
#define __AFL_QEMU_COMMON

#define DEBUG_AFL 0

#define AFL_DPRINTF(fmt, ...) do {                                          \
        if (DEBUG_AFL) {                                           \
            fprintf(stderr, fmt, ## __VA_ARGS__);      \
            fflush(stderr);                                             \
        }                                                               \
    } while (0)
extern const char *aflFile;
extern unsigned long aflPanicAddr;
extern unsigned long aflDmesgAddr;

extern int aflEnableTicks;
extern int aflStart;
extern int aflGotLog;
extern target_ulong afl_start_code, afl_end_code;
extern unsigned char afl_fork_child;
extern int afl_wants_cpu_to_stop;

void afl_setup(void);
void afl_forkserver(CPUArchState*);

void afl_persistent_start(void);
void afl_persistent_stop(void);
extern unsigned char is_persistent;
extern unsigned int afl_persistent_cnt;

void afl_request_tsl(target_ulong, target_ulong, uint32_t, TranslationBlock*, int, char cmd);

enum tsl_cmd {
    TRANSLATE = 0,
    IS_CHAIN = 1,
    EXIT_TSL = 2, // needed for persistent mode
    START_AFL = 3,
    STOP_AFL = 4
};


#endif
