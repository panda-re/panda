#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include "qemu/osdep.h"
#include "cpu.h"

#include "exec/memory.h"
#include "exec/exec-all.h"
#include "io/channel-file.h"
#include "migration/migration.h"
#include "migration/qemu-file.h"
#include "sysemu/sysemu.h"

#include "panda/rr/rr_log.h"
#include "panda/common.h"
#include "qemu/memfd.h"

#if defined CONFIG_LINUX && !defined CONFIG_MEMFD
#include <sys/syscall.h>
#include <asm/unistd.h>
static int memfd_create(const char *name, unsigned int flags)
{
#ifdef __NR_memfd_create
    return syscall(__NR_memfd_create, name, flags);
#else
    return -1;
#endif
}
#endif

#include "panda/checkpoint.h"

static QLIST_HEAD(, Checkpoint) checkpoints = QLIST_HEAD_INITIALIZER(checkpoints);

extern RR_log_entry *rr_queue_head;

extern unsigned long long rr_number_of_log_entries[RR_LAST];
extern unsigned long long rr_size_of_log_entries[RR_LAST];
extern unsigned long long rr_max_num_queue_entries;

typedef struct Checkpoint {
    uint64_t guest_instr_count;
    size_t nondet_log_position;

    unsigned long long number_of_log_entries[RR_LAST];
    unsigned long long size_of_log_entries[RR_LAST];
    unsigned long long max_num_queue_entries;

    unsigned next_progress;

    int memfd;

    size_t memfd_usage;

    QLIST_ENTRY(Checkpoint) next;
} Checkpoint;

static size_t total_usage = 0;

/*
 * Perform replay checkpoint which we can later rewind to.
 *
 * Returns: checkpoint ID for later resume.
 */
void *panda_checkpoint(void) {
    assert(rr_in_replay());

    uint64_t instr_count = rr_get_guest_instr_count();

    /* Find last existing checkpoint before this point */
    Checkpoint *base = NULL;
    Checkpoint *check = NULL;
    QLIST_FOREACH(check, &checkpoints, next) {
        if (check->guest_instr_count > instr_count) break;
        base = check;
    }

    Checkpoint *checkpoint = (Checkpoint *)malloc(sizeof(Checkpoint));

    if (base) {
        QLIST_INSERT_AFTER(base, checkpoint, next);
    } else {
        QLIST_INSERT_HEAD(&checkpoints, checkpoint, next);
    }

    checkpoint->guest_instr_count = instr_count;
    checkpoint->nondet_log_position = rr_queue_head
        ? rr_queue_head->header.file_pos
        : rr_nondet_log->bytes_read;

    memcpy(checkpoint->number_of_log_entries, rr_number_of_log_entries,
            sizeof(rr_number_of_log_entries));
    memcpy(checkpoint->size_of_log_entries, rr_size_of_log_entries,
            sizeof(rr_size_of_log_entries));
    checkpoint->max_num_queue_entries = rr_max_num_queue_entries;
    checkpoint->next_progress = rr_next_progress;

    checkpoint->memfd = memfd_create("checkpoint", 0);
    assert(checkpoint->memfd >= 0);

    QIOChannelFile *iochannel = qio_channel_file_new_fd(checkpoint->memfd);
    QEMUFile *file = qemu_fopen_channel_output(QIO_CHANNEL(iochannel));

    global_state_store_running();
    qemu_savevm_state(file, NULL);

    qemu_fflush(file);
    checkpoint->memfd_usage = lseek(checkpoint->memfd, 0, SEEK_CUR);
    total_usage += checkpoint->memfd_usage;

    printf("Created checkpoint @ %lu. Size %.1f MB. Total usage %.1f GB\n",
            instr_count, ((float) checkpoint->memfd_usage) / (1 << 20),
            ((float) total_usage) / (1 << 30));

    return checkpoint;
}

void panda_restart(void *opaque) {
    assert(rr_in_replay());

    Checkpoint *checkpoint = (Checkpoint *)opaque;

    lseek(checkpoint->memfd, 0, SEEK_SET);

    QIOChannelFile *iochannel = qio_channel_file_new_fd(checkpoint->memfd);
    QEMUFile *file = qemu_fopen_channel_input(QIO_CHANNEL(iochannel));
    qemu_system_reset(VMRESET_SILENT);
    migration_incoming_state_new(file);

    int snapshot_ret = qemu_loadvm_state(file);
    assert(snapshot_ret >= 0);

    migration_incoming_state_destroy();

    first_cpu->rr_guest_instr_count = checkpoint->guest_instr_count;
    first_cpu->panda_guest_pc = panda_current_pc(first_cpu);
    rr_nondet_log->bytes_read = checkpoint->nondet_log_position;
    fseek(rr_nondet_log->fp, checkpoint->nondet_log_position, SEEK_SET);
    rr_queue_head = rr_queue_tail = NULL;

    memcpy(rr_number_of_log_entries, checkpoint->number_of_log_entries,
            sizeof(rr_number_of_log_entries));
    memcpy(rr_size_of_log_entries, checkpoint->size_of_log_entries,
            sizeof(rr_size_of_log_entries));
    rr_max_num_queue_entries = checkpoint->max_num_queue_entries;
    rr_next_progress = checkpoint->next_progress;

    if (qemu_in_vcpu_thread() && first_cpu->jmp_env) {
        cpu_loop_exit(first_cpu);
    }
}
