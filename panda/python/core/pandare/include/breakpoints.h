// Manully created. Sorry. Didn't know how to deal with the QTAILQ stuff with cffi

typedef struct {
    struct CPUBreakpoint *tqe_next;       /* next element */
    struct CPUBreakpoint **tqe_prev;      /* address of previous next element */
} CPUBreakpoint_qtailq;

typedef struct CPUBreakpoint {
    vaddr pc;
    uint64_t rr_instr_count;
    int flags; /* BP_* */
    CPUBreakpoint_qtailq entry; // Was a QTAILQ(CPUBreakpoint)
} CPUBreakpoint;

int cpu_breakpoint_insert(CPUState *cpu, vaddr pc, int flags, CPUBreakpoint **breakpoint);

int cpu_breakpoint_remove(CPUState *cpu, vaddr pc, int flags);
