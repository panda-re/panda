#include "panda/rr/rr_log.h"

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

#define MAX_CHECKPOINTS 256
extern Checkpoint* checkpoints[MAX_CHECKPOINTS];

/*void* search_checkpoints(uint64_t target_instr);*/
size_t get_num_checkpoints(void);
int get_closest_checkpoint_num(uint64_t instr_count);
Checkpoint* get_checkpoint(int num);
void* panda_checkpoint(void);
void panda_restore_by_num(int num);
void panda_restore(void *opaque);
