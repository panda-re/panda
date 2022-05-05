// XXX lots of shared code here could be factored out
#include "afl/afl.h"

#include "afl/types.h"
extern u8 * shared_buf;
extern u32 *shared_buf_len;
extern u8   sharedmem_fuzzing;
CPUState *aflCurrentCPU;

void gen_aflBBlock(target_ulong pc);

static target_ulong startForkserver(CPUArchState *env, target_ulong enableTicks)
{
    int pid = getpid();
    AFL_DPRINTF("pid %d: startForkServer\n", pid);
    if(afl_fork_child) {
        /*
         * we've already started a fork server. perhaps a test case
         * accidentally triggered startForkserver again.  Exit the
         * test case without error.
         */
        exit(0);
    }
#ifdef CONFIG_USER_ONLY
    /* we're running in the main thread, get right to it! */
    afl_setup();
    afl_forkserver(env);
#else
    /*
     * we're running in a cpu thread. we'll exit the cpu thread
     * and notify the iothread.  The iothread will run the forkserver
     * and in the child will restart the cpu thread which will continue
     * execution.
     * N.B. We assume a single cpu here!
     */
    aflEnableTicks = enableTicks;
    afl_wants_cpu_to_stop = 1;
    aflCurrentCPU = current_cpu;
#endif
    return 0;
}


typedef struct state_patch_entry {
    uint8_t addr;
    uint8_t val;
} spe_t;

/* writes persistent log, if needed */
static void afl_maybe_add_to_persistent_log(uint8_t *buf, size_t len) {
    if (!len) {
        /* We don't need support for 0 len testcases here,
        they could only be emitted by custom mutators like grammar fuzzers. */
        return;
    }
    if (afl_persistent_crash_log_dir) {
        afl_persistent_cache_pos = afl_persistent_cache_calc_next_pos();
        *(u32 *)afl_persistent_cache_pos = htonl(len);
        memcpy(afl_persistent_cache_cur_input(), buf, len);
    }
}

/* copy work into ptr[0..sz].  Assumes memory range is locked. */
static target_ulong getWork(CPUArchState *env, target_ulong ptr, target_ulong sz)
{
    target_ulong retsz;
    FILE *fp;


    AFL_DPRINTF("pid %d: getWork " TARGET_FMT_lx " " TARGET_FMT_lx "\n",
            getpid(), ptr, sz);
    assert(aflStart == 0);

    if (sharedmem_fuzzing) {
        AFL_DPRINTF("pid %d: getWork from shmem (%d)\n",
            getpid(), *shared_buf_len);
        /* make sure the size doesn't exceed the max size for this target */
        *shared_buf_len = *shared_buf_len > AFL_MAX_INPUT ? AFL_MAX_INPUT : *shared_buf_len;
        afl_maybe_add_to_persistent_log(shared_buf, *shared_buf_len);

        cpu_physical_memory_rw(ptr, shared_buf, *shared_buf_len, 1);
        return *shared_buf_len;
    }
    if (aflReplayFile) {

        AFL_DPRINTF("Replaying next testcase trace from %20s", aflReplayFile);

        if (!afl_persistent_cache) {

            fp = fopen(aflReplayFile, "rb");

            if (fp == NULL) {
                AFL_DPRINTF("Unable to open fuzz input file %s\n", aflReplayFile);
                perror(aflReplayFile);
                return 0;
            }

            fseek(fp, 0L, SEEK_END);
            uint32_t flen = ftell(fp);
            AFL_DPRINTF("Read %ud bytes from %s\n", flen, aflReplayFile);
            fseek(fp, 0L, SEEK_SET);
            /* Alloc one additional last 0 length element for EOF. */
            afl_persistent_cache = calloc(sizeof(char), flen + sizeof(uint32_t));
            if (!afl_persistent_cache) {
                AFL_DPRINTF("Could not get mem");
                perror("persistent_cache");
                fclose(fp);
                return 0;
            }

            if (fread(afl_persistent_cache, sizeof(char), flen, fp) < flen) {
                AFL_DPRINTF("Short read, something went wrong!");
                free(afl_persistent_cache);
                fclose(fp);
                return 0;
            }
            // TODO Free the afl_persistent_cache at some point?
            fclose(fp);

            afl_persistent_cache_pos = afl_persistent_cache;

            AFL_DPRINTF("Read %u bytes successfully. Starting trace replay.\n", flen);

        }

        AFL_DPRINTF("Replaying packet from %s\n", aflReplayFile);

        uint32_t len = afl_persistent_cache_cur_input_len();
        if (!len) {
            AFL_DPRINTF("We finished replaying the Log. No crash this time. CYA.\n");
            exit(0);
        }

        // Shannon has one contigous address space, so we can directly write physmem
        cpu_physical_memory_rw(ptr, afl_persistent_cache_cur_input() , len, 1);
        afl_persistent_cache_pos = afl_persistent_cache_calc_next_pos();
        return len;
    }


    AFL_DPRINTF("pid %d: getWork from %20s\n",
            getpid(), aflFile);

    fp = fopen(aflFile, "rb");

    if (fp == NULL) {
      AFL_DPRINTF("Unable to open fuzz input file %s\n", aflFile);
      perror(aflFile);
      return 0;
    }

#if 0 // legacy triforce afl byte-by-byte input rw. To be replaced.
    unsigned char ch;
    retsz = 0;
    while(retsz < sz) {
        if(fread(&ch, 1, 1, fp) == 0)
            break;
        cpu_stb_data(env, ptr, ch);
        retsz ++;
        ptr ++;
    }
#else
    uint8_t buffer[AFL_MAX_INPUT]; //testcase max size for shannon
    uint8_t * bufptr = buffer;

    retsz = fread (buffer, 1, sz, fp);

    if (retsz == 0) {
      assert(!ferror(fp));
      return 0;
    }

    afl_maybe_add_to_persistent_log(bufptr, retsz);

    // Shannon has one contigous address space, so we can directly write physmem
    cpu_physical_memory_rw(ptr, bufptr, retsz, 1);

#endif
    fclose(fp);
    return retsz;
}

static target_ulong startWork(CPUArchState *env, target_ulong start, target_ulong end)
{
    AFL_DPRINTF("pid %d: startWork " TARGET_FMT_lx " - " TARGET_FMT_lx"\n",
            getpid(), start, end);


    afl_start_code = start;
    afl_end_code   = end;
    aflGotLog = 0;
    aflStart = 1;
    afl_request_tsl(NULL, 0, 0, 0, 0, 0, START_AFL);
    if (is_persistent)
        afl_persistent_start();
    return 0;
}

static target_ulong doneWork(CPUArchState *env, target_ulong val)
{
    //target_ulong new_state;
    AFL_DPRINTF("pid %d: doneWork " TARGET_FMT_lx "\n", getpid(), val);
    assert(aflStart == 1);
/* detecting logging as crashes hasnt been helpful and
   has occasionally been a problem.  We'll leave it to
   a post-analysis phase to look over dmesg output for
   our corpus.
 */
#ifdef LETSNOT
    if(aflGotLog)
        exit(64 | val);
#endif
    afl_request_tsl(NULL, 0, 0, 0, 0, 0, STOP_AFL);

    if (is_persistent || aflReplayFile) {
        /* Go to the next round, if we're fuzzing in persistent,
        or we are replaying a trace */
        aflStart = 0; /* Stop capturing coverage */
        afl_persistent_stop();
    } else {
        if (aflFastExit)
          _exit(val);
        else
          exit(val);
    }
    return 0;
}

// TODO not tested
static target_ulong qputs(target_ulong val)
{
    char buff[20];
    time_t now = time(NULL);
    strftime(buff, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));

    FILE *fd = fopen("qemu_log", "a");
    int writed = fprintf(fd, "%s\t0x%x\n", buff, val);
    fclose(fd);
    return writed;
}

target_ulong helper_aflCall(CPUArchState *env, target_ulong code, target_ulong a0, target_ulong a1);
uint32_t helper_aflCall32(CPUArchState *env, uint32_t code, uint32_t a0, uint32_t a1);

uint32_t helper_aflCall32(CPUArchState *env, uint32_t code, uint32_t a0, uint32_t a1) {
    return (uint32_t)helper_aflCall(env, code, a0, a1);
}

target_ulong helper_aflCall(CPUArchState *env, target_ulong code, target_ulong a0, target_ulong a1) {
    switch(code) {
    case 1: return (uint32_t)startForkserver(env, a0);
    case 2: return (uint32_t)getWork(env, a0, a1);
    case 3: return (uint32_t)startWork(env, a0, a1);
    case 4: return (uint32_t)doneWork(env, a0);
    case 5: return (uint32_t)qputs(a0);
    default: return -1;
    }
}

void helper_aflInterceptLog(CPUArchState *env);
void helper_aflInterceptPanic(void);

void helper_aflInterceptLog(CPUArchState *env)
{
    if(!aflStart)
        return;
    aflGotLog = 1;

#ifdef NOTYET
    static FILE *fp = NULL;
    if(fp == NULL) {
        fp = fopen("logstore.txt", "a");
        if(fp) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            fprintf(fp, "\n----\npid %d time %ld.%06ld\n", getpid(), (u_long)tv.tv_sec, (u_long)tv.tv_usec);
        }
    }
    if(!fp)
        return;

    target_ulong stack = env->regs[R_ESP];
    //target_ulong level = env->regs[R_ESI]; // arg 2
    target_ulong ptext = cpu_ldq_data(env, stack  0x8); // arg7
    target_ulong len   = cpu_ldq_data(env, stack  0x10) & 0xffff; // arg8
    const char *msg = peekStrZ(env, ptext, len);
    fprintf(fp, "%s\n", msg);
#endif
}

void helper_aflInterceptPanic(void)
{
    if(!aflStart && !afl_panic_exit_always)
        return;


#ifdef AFL_PERSISTENT_TRACELOG
    /* In persistent mode, write out a trace of all messages we received */

    if (afl_persistent_crash_log_dir) {

        AFL_DPRINTF("Hooray we found a crash! writing crashlog");

        int ret;
        char *digest;

        if (!qcrypto_hash_supports(QCRYPTO_HASH_ALG_MD5)) {
            /* not really anything we can do, but print a warning for strace */
            printf("MD5 hashing not supported! Can't write trace :(");
            abort();

        }

        ret = qcrypto_hash_digest(QCRYPTO_HASH_ALG_MD5,
                                    (char *)afl_persistent_cache_cur_input(),
                                    afl_persistent_cache_cur_input_len(),
                                    &digest,
                                    NULL);
        g_assert(ret == 0);


        char path[PATH_MAX];

        snprintf(path, PATH_MAX, "%s/%s-%lu.buftrace", afl_persistent_crash_log_dir,
                digest, (unsigned long)time(NULL));

        g_free(digest);
        digest = NULL;

        FILE *f = fopen(path, "wb");

        if (!f) {
            perror(path);
            abort();
        }

        if (fwrite(afl_persistent_cache, sizeof(char),
            afl_persistent_cache_len(), f)
                < afl_persistent_cache_len()) {
            perror(path);
        }

        fclose(f);

    }

#endif
    // always abort as AFL needs to receive this signal to detect a crash
    abort();
}

void gen_aflBBlock(target_ulong pc)
{

    for (int i = 0; i < aflPanicAddrEntries; i++) {
        if(pc == aflPanicAddr[i]) {
            gen_helper_aflInterceptPanic();
            break;
        }
    }
    //if(pc == aflDmesgAddr)
        //gen_helper_aflInterceptLog(cpu_env);
}

