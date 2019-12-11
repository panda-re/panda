/*
 * PANDA Checkpoint API
 * Author: Ray Wang		raywang@mit.edu
 *
 * Provides functions to take, store, and restore replay checkpoints
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include "qemu/osdep.h"
#include "cpu.h"

#include "exec/exec-all.h"
#include "exec/memory.h"
#include "io/channel-file.h"
#include "migration/migration.h"
#include "migration/qemu-file.h"
#include "sysemu/cpus.h"
#include "sysemu/sysemu.h"

#include "panda/rr/rr_log.h"
#include "panda/common.h"
#include "qemu/memfd.h"

#if !defined(CONFIG_MEMFD)
#if defined CONFIG_LINUX && defined(__NR_memfd_create)
#include <sys/syscall.h>
#include <asm/unistd.h>
static int memfd_create(const char *name, unsigned int flags) {
    return syscall(__NR_memfd_create, name, flags);
}
#else
static int memfd_create(const char *name, unsigned int flags) {
    assert(false && "memfd_create not supported on your platform");
    return -1;
}
#endif
#endif

#include "panda/checkpoint.h"

extern RR_log_entry *rr_queue_head;
Checkpoint* checkpoints[MAX_CHECKPOINTS] = {NULL}; 

extern unsigned long long rr_number_of_log_entries[RR_LAST];
extern unsigned long long rr_size_of_log_entries[RR_LAST];
extern unsigned long long rr_max_num_queue_entries;
static size_t total_usage = 0;
static size_t next_checkpoint_num = 0;

/*
 * Returns closest checkpoint containing target_instr_count 
 * If target is start of a checkpoint, returns prev checkpoint num
 * Return -1 if not found
 */
int get_closest_checkpoint_num(uint64_t target_instr_count) {

    // Check base cases 
    if (checkpoints[next_checkpoint_num-1]->guest_instr_count < target_instr_count) {
        return next_checkpoint_num;
    } 

    if (target_instr_count == 0) {
        return 1;
    }

    for (int i = 1; i < next_checkpoint_num; i++) {
        if (checkpoints[i-1]->guest_instr_count < target_instr_count && target_instr_count <= checkpoints[i]->guest_instr_count) {
            return i; 
        }
    }

    return -1;

}

size_t get_num_checkpoints(void) {
    return next_checkpoint_num;
}

/*
 * Gets checkpoint from array by idx.
 * If idx <= 0, return last one
 */
Checkpoint* get_checkpoint(int num) {
    if (num <= 0) {
        return checkpoints[next_checkpoint_num-1]; 
    } else if (num <= next_checkpoint_num) {
        return checkpoints[num-1];
    }

    return NULL;
}

/*
 * Perform replay checkpoint which we can later rewind to.
 *
 * Returns: checkpoint ID for later resume.
 */
void *panda_checkpoint(void) {
    assert(rr_in_replay());

    if (next_checkpoint_num >= MAX_CHECKPOINTS) { 
        printf("panda_checkpoint: Cannot make any more checkpoints!\n");
        return NULL;
    }

    uint64_t instr_count = rr_get_guest_instr_count();

    /* Find last existing checkpoint before this point */
    //Checkpoint *check = NULL;
    //for (int i = 0; i < next_checkpoint_num; i++) {
        //check = checkpoints[i];
        //if (check->guest_instr_count > instr_count) break;
    //}

    Checkpoint *checkpoint = (Checkpoint *)malloc(sizeof(Checkpoint));

    // TODO: Do we want to insert checkpoint in list in order?
    checkpoints[next_checkpoint_num] = checkpoint;
    next_checkpoint_num++;
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

    printf("Created checkpoint @ %" PRIu64 ". Size %.1f MB. Total usage %.1f GB\n",
            instr_count, ((float) checkpoint->memfd_usage) / (1 << 20),
            ((float) total_usage) / (1 << 30));

    return checkpoint;
}


void panda_restore_by_num(int num) {
    if (num <= 0) {
        panda_restore(checkpoints[next_checkpoint_num-1]); 
    } else if (num <= next_checkpoint_num) {
        if (checkpoints[num-1] != NULL) {
            panda_restore(checkpoints[num-1]);
        }
    }
}

void panda_restore(void *opaque) {
    assert(rr_in_replay());
    
    Checkpoint *checkpoint = (Checkpoint *)opaque;
    printf("Restarting checkpoint @ instr count %" PRIu64 "\n", checkpoint->guest_instr_count);
        
    lseek(checkpoint->memfd, 0, SEEK_SET);

    QIOChannelFile *iochannel = qio_channel_file_new_fd(checkpoint->memfd);
    QEMUFile *file = qemu_fopen_channel_input(QIO_CHANNEL(iochannel));
    qemu_system_reset(VMRESET_SILENT);
    MigrationIncomingState* mis = migration_incoming_get_current();
    mis->from_src_file = file;

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

    // XXX: first_cpu->jmp_env always evaluate to true - says clang
    if (qemu_in_vcpu_thread() && first_cpu->jmp_env) {
        cpu_loop_exit(first_cpu);
    }
}
