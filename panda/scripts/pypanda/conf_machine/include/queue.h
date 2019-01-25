typedef struct DUMMY_Q_ENTRY DUMMY_Q_ENTRY;
typedef struct DUMMY_Q DUMMY_Q;

struct DUMMY_Q_ENTRY {
        struct { struct DUMMY_Q_ENTRY *tqe_next; struct DUMMY_Q_ENTRY * *tqe_prev; } next;
};

struct DUMMY_Q {
        struct DUMMY_Q_HEAD { struct DUMMY_Q_ENTRY *tqh_first; struct DUMMY_Q_ENTRY * *tqh_last; } head;
};
