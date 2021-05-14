#ifndef __AFL_QEMU_COMMON
#define __AFL_QEMU_COMMON

#include <arpa/inet.h>

#define AFL_MAX_INPUT (4096)

#define AFL_DPRINTF(fmt, ...) do {                                          \
        if (unlikely(aflDebug)) {                                           \
            fprintf(stderr, "[AFLDEBUG] " fmt, ## __VA_ARGS__);      \
            fflush(stderr);                                             \
        }                                                               \
    } while (0)

#define AFL_PERSISTENT_TRACELOG

#define AFL_MAX_STATE_ADDR 256
#define AFL_MAX_PANIC_ADDR 256

extern const char *aflFile;
extern const char *aflOutFile;
extern unsigned long aflPanicAddr[AFL_MAX_PANIC_ADDR];
extern unsigned long aflStateAddr[AFL_MAX_STATE_ADDR];
extern uint8_t aflStateAddrEntries;
extern uint8_t aflPanicAddrEntries;

extern int aflEnableTicks;
extern int aflStart;
extern int aflDebug;
extern int aflGotLog;
extern int aflFastExit;
extern target_ulong afl_start_code, afl_end_code;
extern unsigned char afl_fork_child;
extern int afl_wants_cpu_to_stop;

void afl_setup(void);
void afl_forkserver(CPUArchState*);

void afl_persistent_start(void);
void afl_persistent_stop(void);
extern unsigned char is_persistent;
extern unsigned int afl_persistent_cnt;

/* big_endian32(length); Value */
extern uint8_t *afl_persistent_cache;
extern uint8_t *afl_persistent_cache_pos;

/* Location where the persistent crash logs get stored */
extern char *afl_persistent_crash_log_dir;

/* returns the start of the current testcase (length value) */
static inline uint8_t *afl_persistent_cache_cur_input(void);
static inline uint8_t *afl_persistent_cache_cur_input(void) {
    return afl_persistent_cache_pos + sizeof(uint32_t);
}

/* Get the length of the current/last input */
static inline uint32_t afl_persistent_cache_cur_input_len(void);
static inline uint32_t afl_persistent_cache_cur_input_len(void) {
    return ntohl(*(uint32_t *)afl_persistent_cache_pos);
}


/* returns the end of the current testcase */
static inline uint8_t *afl_persistent_cache_calc_next_pos(void);
static inline uint8_t *afl_persistent_cache_calc_next_pos(void) {
    if (unlikely(!afl_persistent_cache_pos)) {
        return afl_persistent_cache;
    }
    return afl_persistent_cache_pos + sizeof(uint32_t) +
        afl_persistent_cache_cur_input_len();
}

/* The complete length */
static inline ptrdiff_t afl_persistent_cache_len(void);
static inline ptrdiff_t afl_persistent_cache_len(void) {
    return afl_persistent_cache_calc_next_pos() - afl_persistent_cache;
}

void afl_request_tsl(target_ulong, target_ulong, uint32_t, TranslationBlock*, int, char cmd);

enum tsl_cmd {
    TRANSLATE = 0,
    IS_CHAIN = 1,
    EXIT_TSL = 2, // needed for persistent mode
    START_AFL = 3,
    STOP_AFL = 4
};

extern unsigned char *afl_area_ptr;
extern unsigned int afl_inst_rms;

#if (defined(__x86_64__) || defined(__i386__)) && defined(AFL_QEMU_NOT_ZERO)
#define INC_AFL_AREA(loc)           \
  asm volatile(                     \
      "incb (%0, %1, 1)\n"          \
      "adcb $0, (%0, %1, 1)\n"      \
      : /* no out */                \
      : "r"(afl_area_ptr), "r"(loc) \
      : "memory", "eax")
#else
#define INC_AFL_AREA(loc) afl_area_ptr[loc]++
#endif



#endif
