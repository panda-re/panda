typedef uint64_t target_ulong;
/**
* assumptions.h. The sad truth of a not truly auto-generated file.
* If something has gone wrong it's probably in here.
*/

typedef uint64_t ram_addr_t;
extern ram_addr_t ram_size; //gives us the ram_size variable
typedef uint64_t tb_page_addr_t;
typedef uint64_t hwaddr;
typedef uint64_t MemTxResult;
typedef uint8_t Int128[16]; 
typedef uint64_t vaddr;
typedef uint8_t sigjmp_buf[200];
typedef uint8_t pthread_mutex_t[40];
typedef enum {
   IOMMU_NONE = 0,
   IOMMU_RO   = 1,
   IOMMU_WO   = 2,
   IOMMU_RW   = 3,
} IOMMUAccessFlags;
typedef enum {
    IOMMU_NOTIFIER_NONE = 0,
    IOMMU_NOTIFIER_UNMAP = 0x1,
    IOMMU_NOTIFIER_MAP = 0x2,
} IOMMUNotifierFlag;
enum QemuOptType {
    QEMU_OPT_STRING = 0,  
    QEMU_OPT_BOOL,        
    QEMU_OPT_NUMBER,      
    QEMU_OPT_SIZE, 
};
enum device_endian {
    DEVICE_NATIVE_ENDIAN,
    DEVICE_BIG_ENDIAN,
    DEVICE_LITTLE_ENDIAN,
};
typedef void CPUWriteMemoryFunc(void *opaque, hwaddr addr, uint32_t value);
typedef uint32_t CPUReadMemoryFunc(void *opaque, hwaddr addr);
typedef uint64_t CPUArchIdList;
typedef uint8_t FPReg[16];
typedef char flag;
typedef struct {
	uint64_t low;
	uint16_t high;
} floatx80; 
typedef uint32_t float32;
typedef uint64_t float64;
typedef uint32_t FeatureWordArray[18];
typedef struct {
    uint64_t base;
    uint64_t mask;
} MTRRVar;
typedef enum TPRAccess {
    TPR_ACCESS_READ,
    TPR_ACCESS_WRITE,
} TPRAccess;
typedef struct {
    uint64_t raw_tcr;
    uint32_t mask;
    uint32_t base_mask;
} TCR;
typedef uint32_t TCGMemOp;
typedef uint32_t QEMUClockType;
typedef void QEMUTimerCB(void *opaque);
typedef void QEMUTimerListNotifyCB(void *opaque, QEMUClockType type);
typedef uint32_t (*dcr_read_cb)(void *opaque, int dcrn);
typedef void (*dcr_write_cb)(void *opaque, int dcrn, uint32_t val);
typedef uint32_t powerpc_mmu_t;
typedef uint32_t powerpc_excp_t;
typedef uint32_t powerpc_input_t;
typedef void RCUCBFunc(struct rcu_head *head);
typedef uint8_t ZMMReg[64];
typedef uint8_t MMXReg[8];
typedef uint8_t ppc_avr_t[16];
typedef uint8_t ppc_tlb_t[8];
typedef uint64_t hax_fd;
struct hax_vcpu_state {
    hax_fd fd;
    int vcpu_id;
    struct hax_tunnel *tunnel;
    unsigned char *iobuf;
};
typedef struct hax_state hax_global;
typedef struct hax_vcpu_state hax_vcpu_state;
typedef uint64_t pthread_t;
typedef uint8_t pthread_cond_t[48]; 
typedef void * run_on_cpu_func;
typedef uint64_t run_on_cpu_data;
typedef int gdb_reg_cb;
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint64_t __u64;
struct GHashTable {};
typedef struct GHashTable GHashTable;
typedef void IOEventHandler(void *opaque, int event);
typedef void IOReadHandler(void *opaque, const uint8_t *buf, int size);
typedef int IOCanReadHandler(void *opaque);
typedef uint32_t guint;
typedef uint32_t QType; // actually an enum
typedef void ReadLineCompletionFunc(void *opaque, const char *cmdline);
typedef void ReadLineFlushFunc(void *opaque);
typedef void ReadLineFunc(void *opaque, const char *str,void *readline_opaque);
typedef void ReadLinePrintfFunc(void *opaque,const char *fmt, ...);
typedef uint8_t MonitorQMP[72];
typedef void BlockCompletionFunc(void *opaque, int ret);
typedef uint8_t QDict[4120];
typedef uint8_t mon_cmd_t[56];
typedef char gchar;
typedef uint8_t fpr_t[16];
enum mips_mmu_types {
    MMU_TYPE_NONE,
    MMU_TYPE_R4000,
    MMU_TYPE_RESERVED,
    MMU_TYPE_FMT,
    MMU_TYPE_R3000,
    MMU_TYPE_R6000,
    MMU_TYPE_R8000
};
struct QemuThread;
typedef struct QemuThread QemuThread;
struct QemuThread {
	pthread_t                  thread;               /*     0     8 */
	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};
struct QemuCond;
typedef struct QemuCond QemuCond;
struct QemuCond {
	pthread_cond_t             cond;                 /*     0    48 */
	/* size: 48, cachelines: 1, members: 1 */
	/* last cacheline: 48 bytes */
};
struct qemu_work_item;
typedef struct qemu_work_item qemu_work_item;
struct qemu_work_item {
	struct qemu_work_item *    next;                 /*     0     8 */
	run_on_cpu_func            func;                 /*     8     8 */
	run_on_cpu_data            data;                 /*    16     8 */
	_Bool                      free;                 /*    24     1 */
	_Bool                      exclusive;            /*    25     1 */
	_Bool                      done;                 /*    26     1 */
	/* size: 32, cachelines: 1, members: 6 */
	/* padding: 5 */
	/* last cacheline: 32 bytes */
};
struct GDBRegisterState;
typedef struct GDBRegisterState GDBRegisterState;
struct GDBRegisterState {
	int                        base_reg;             /*     0     4 */
	int                        num_regs;             /*     4     4 */
	gdb_reg_cb                 get_reg;              /*     8     8 */
	gdb_reg_cb                 set_reg;              /*    16     8 */
	const char  *              xml;                  /*    24     8 */
	struct GDBRegisterState *  next;                 /*    32     8 */
	/* size: 40, cachelines: 1, members: 6 */
	/* last cacheline: 40 bytes */
};
struct TranslationBlock;
typedef struct TranslationBlock TranslationBlock;
struct TranslationBlock {
	target_ulong               pc;                   /*     0     8 */
	target_ulong               cs_base;              /*     8     8 */
	uint32_t                   flags;                /*    16     4 */
	uint16_t                   size;                 /*    20     2 */
	uint16_t                   icount;               /*    22     2 */
	uint32_t                   cflags;               /*    24     4 */
	uint16_t                   invalid;              /*    28     2 */
	uint8_t                    was_split;            /*    30     1 */
	/* XXX 1 byte hole, try to pack */
	void *                     tc_ptr;               /*    32     8 */
	uint8_t *                  tc_search;            /*    40     8 */
	struct TranslationBlock *  orig_tb;              /*    48     8 */
	struct TranslationBlock *  page_next[2];         /*    56    16 */
	/* --- cacheline 1 boundary (64 bytes) was 8 bytes ago --- */
	tb_page_addr_t             page_addr[2];         /*    72    16 */
	uint16_t                   jmp_reset_offset[2];  /*    88     4 */
	uint16_t                   jmp_insn_offset[2];   /*    92     4 */
	uintptr_t                  jmp_list_next[2];     /*    96    16 */
	uintptr_t                  jmp_list_first;       /*   112     8 */
	uint8_t *                  llvm_tc_ptr;          /*   120     8 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	uint8_t *                  llvm_tc_end;          /*   128     8 */
	struct TranslationBlock *  llvm_tb_next[2];      /*   136    16 */
	uint8_t *                  llvm_asm_ptr;         /*   152     8 */
	char                       llvm_fn_name[64];     /*   160    64 */
	/* size: 224, cachelines: 4, members: 22 */
	/* sum members: 223, holes: 1, sum holes: 1 */
	/* last cacheline: 32 bytes */
};
struct Object;
typedef struct Object Object;
struct Object {
	void * klass;
	void * free;
	void * properties;
	uint32_t ref;
	void * parent;
	};
struct CharBackend;
typedef struct CharBackend CharBackend;
struct Chardev;
typedef struct Chardev Chardev;
struct CharBackend {
	Chardev *                  chr;                  /*     0     8 */
	IOEventHandler *           chr_event;            /*     8     8 */
	IOCanReadHandler *         chr_can_read;         /*    16     8 */
	IOReadHandler *            chr_read;             /*    24     8 */
	void *                     opaque;               /*    32     8 */
	int                        tag;                  /*    40     4 */
	int                        fe_open;              /*    44     4 */
	/* size: 48, cachelines: 1, members: 7 */
	/* last cacheline: 48 bytes */
};
struct QemuMutex;
typedef struct QemuMutex QemuMutex;
struct QemuMutex {
	pthread_mutex_t            lock;                 /*     0    40 */
	/* size: 40, cachelines: 1, members: 1 */
	/* last cacheline: 40 bytes */
};
struct QemuOptDesc;
typedef struct QemuOptDesc QemuOptDesc;
struct QemuOptDesc {
	const char  *              name;                 /*     0     8 */
	enum QemuOptType   type;                         /*     8     4 */
	/* XXX 4 bytes hole, try to pack */
	const char  *              help;                 /*    16     8 */
	const char  *              def_value_str;        /*    24     8 */
	/* size: 32, cachelines: 1, members: 4 */
	/* sum members: 28, holes: 1, sum holes: 4 */
	/* last cacheline: 32 bytes */
};
struct Location;
typedef struct Location Location;
struct Location {
	int                        num;                  /*     4     4 */
	const void  *              ptr;                  /*     8     8 */
	struct Location *          prev;                 /*    16     8 */
	/* size: 24, cachelines: 1, members: 4 */
	/* last cacheline: 24 bytes */
};
struct HotplugHandler;
typedef struct HotplugHandler HotplugHandler;
struct HotplugHandler {
	Object                     Parent;               /*     0    40 */
	/* size: 40, cachelines: 1, members: 1 */
	/* last cacheline: 40 bytes */
};
struct RAMBlock;
typedef struct RAMBlock RAMBlock;
struct RAMBlock {
	struct rcu_head    rcu;                          /*     0    16 */
	struct MemoryRegion *      mr;                   /*    16     8 */
	uint8_t *                  host;                 /*    24     8 */
	ram_addr_t                 offset;               /*    32     8 */
	ram_addr_t                 used_length;          /*    40     8 */
	ram_addr_t                 max_length;           /*    48     8 */
	void                       (*resized)(const char  *, uint64_t, void *); /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	uint32_t                   flags;                /*    64     4 */
	char                       idstr[256];           /*    68   256 */
	/* XXX 4 bytes hole, try to pack */
	/* --- cacheline 5 boundary (320 bytes) was 8 bytes ago --- */
	struct {
		struct RAMBlock *  le_next;              /*   328     8 */
		struct RAMBlock * * le_prev;             /*   336     8 */
	} next;                                          /*   328    16 */
	struct {
		struct RAMBlockNotifier * lh_first;      /*   344     8 */
	} ramblock_notifiers;                            /*   344     8 */
	int                        fd;                   /*   352     4 */
	/* XXX 4 bytes hole, try to pack */
	size_t                     page_size;            /*   360     8 */
	/* size: 368, cachelines: 6, members: 13 */
	/* sum members: 360, holes: 2, sum holes: 8 */
	/* last cacheline: 48 bytes */
};
struct MemTxAttrs;
typedef struct MemTxAttrs MemTxAttrs;
struct MemTxAttrs {
	unsigned int               unspecified:1;        /*     0: 0  4 */
	unsigned int               secure:1;             /*     0: 1  4 */
	unsigned int               user:1;               /*     0: 2  4 */
	unsigned int               requester_id:16;      /*     0: 3  4 */
	/* size: 4, cachelines: 1, members: 4 */
	/* bit_padding: 13 bits */
	/* last cacheline: 4 bytes */
};
struct Notifier;
typedef struct Notifier Notifier;
struct Notifier {
	void                       (*notify)(Notifier *, void *); /*     0     8 */
	struct {
		struct Notifier *  le_next;              /*     8     8 */
		struct Notifier * * le_prev;             /*    16     8 */
	} node;                                          /*     8    16 */
	/* size: 24, cachelines: 1, members: 2 */
	/* last cacheline: 24 bytes */
};
struct QObject;
typedef struct QObject QObject;
struct QObject {
	QType                      type;                 /*     0     4 */
	/* XXX 4 bytes hole, try to pack */
	size_t                     refcnt;               /*     8     8 */
	/* size: 16, cachelines: 1, members: 2 */
	/* sum members: 12, holes: 1, sum holes: 4 */
	/* last cacheline: 16 bytes */
};
struct MemoryRegionMmio;
typedef struct MemoryRegionMmio MemoryRegionMmio;
struct MemoryRegionMmio {
	CPUReadMemoryFunc *        read[3];              /*     0    24 */
	CPUWriteMemoryFunc *       write[3];             /*    24    24 */
	/* size: 48, cachelines: 1, members: 2 */
	/* last cacheline: 48 bytes */
};
struct AddrRange;
typedef struct AddrRange AddrRange;
struct AddrRange {
	Int128                     start;                /*     0    16 */
	Int128                     size;                 /*    16    16 */
	/* size: 32, cachelines: 1, members: 2 */
	/* last cacheline: 32 bytes */
};
struct EventNotifier;
typedef struct EventNotifier EventNotifier;
struct EventNotifier {
	int                        rfd;                  /*     0     4 */
	int                        wfd;                  /*     4     4 */
	/* size: 8, cachelines: 1, members: 2 */
	/* last cacheline: 8 bytes */
};
struct ARMGenericTimer;
typedef struct ARMGenericTimer ARMGenericTimer;
struct ARMGenericTimer {
	uint64_t                   cval;                 /*     0     8 */
	uint64_t                   ctl;                  /*     8     8 */
	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};
struct float_status;
typedef struct float_status float_status;
struct float_status {
	signed char                float_detect_tininess; /*     0     1 */
	signed char                float_rounding_mode;  /*     1     1 */
	uint8_t                    float_exception_flags; /*     2     1 */
	signed char                floatx80_rounding_precision; /*     3     1 */
	flag                       flush_to_zero;        /*     4     1 */
	flag                       flush_inputs_to_zero; /*     5     1 */
	flag                       default_nan_mode;     /*     6     1 */
	flag                       snan_bit_is_one;      /*     7     1 */
	/* size: 8, cachelines: 1, members: 8 */
	/* last cacheline: 8 bytes */
};
struct AccelState;
typedef struct AccelState AccelState;
struct AccelState {
	Object                     parent_obj;           /*     0    40 */
	/* size: 40, cachelines: 1, members: 1 */
	/* last cacheline: 40 bytes */
};
struct ReadLineState;
typedef struct ReadLineState ReadLineState;
struct ReadLineState {
	char                       cmd_buf[4096];        /*     0  4096 */
	/* --- cacheline 64 boundary (4096 bytes) --- */
	int                        cmd_buf_index;        /*  4096     4 */
	int                        cmd_buf_size;         /*  4100     4 */
	char                       last_cmd_buf[4096];   /*  4104  4096 */
	/* --- cacheline 128 boundary (8192 bytes) was 8 bytes ago --- */
	int                        last_cmd_buf_index;   /*  8200     4 */
	int                        last_cmd_buf_size;    /*  8204     4 */
	int                        esc_state;            /*  8208     4 */
	int                        esc_param;            /*  8212     4 */
	char *                     history[64];          /*  8216   512 */
	/* --- cacheline 136 boundary (8704 bytes) was 24 bytes ago --- */
	int                        hist_entry;           /*  8728     4 */
	/* XXX 4 bytes hole, try to pack */
	ReadLineCompletionFunc *   completion_finder;    /*  8736     8 */
	char *                     completions[256];     /*  8744  2048 */
	/* --- cacheline 168 boundary (10752 bytes) was 40 bytes ago --- */
	int                        nb_completions;       /* 10792     4 */
	int                        completion_index;     /* 10796     4 */
	ReadLineFunc *             readline_func;        /* 10800     8 */
	void *                     readline_opaque;      /* 10808     8 */
	/* --- cacheline 169 boundary (10816 bytes) --- */
	int                        read_password;        /* 10816     4 */
	char                       prompt[256];          /* 10820   256 */
	/* XXX 4 bytes hole, try to pack */
	/* --- cacheline 173 boundary (11072 bytes) was 8 bytes ago --- */
	ReadLinePrintfFunc *       printf_func;          /* 11080     8 */
	ReadLineFlushFunc *        flush_func;           /* 11088     8 */
	void *                     opaque;               /* 11096     8 */
	/* size: 11104, cachelines: 174, members: 21 */
	/* sum members: 11096, holes: 2, sum holes: 8 */
	/* last cacheline: 32 bytes */
};
struct CPUTLBEntry;
typedef struct CPUTLBEntry CPUTLBEntry;
struct CPUTLBEntry {
	union {
		struct {
			target_ulong addr_read;          /*     0     8 */
			target_ulong addr_write;         /*     8     8 */
			target_ulong addr_code;          /*    16     8 */
			uintptr_t  addend;               /*    24     8 */
		};                                       /*     0    32 */
		uint8_t            dummy[32];            /*     0    32 */
	};                                               /*     0    32 */
	/* size: 32, cachelines: 1, members: 1 */
	/* last cacheline: 32 bytes */
};
struct CPUIOTLBEntry;
typedef struct CPUIOTLBEntry CPUIOTLBEntry;
struct CPUIOTLBEntry {
	hwaddr                     addr;                 /*     0     8 */
	MemTxAttrs                 attrs;                /*     8     4 */
	/* size: 16, cachelines: 1, members: 2 */
	/* padding: 4 */
	/* last cacheline: 16 bytes */
};
struct CPUWatchpoint;
typedef struct CPUWatchpoint CPUWatchpoint;
struct CPUWatchpoint {
	vaddr                      virtaddr;             /*     0     8 */
	vaddr                      len;                  /*     8     8 */
	vaddr                      hitaddr;              /*    16     8 */
	MemTxAttrs                 hitattrs;             /*    24     4 */
	int                        flags;                /*    28     4 */
	struct {
		struct CPUWatchpoint * tqe_next;         /*    32     8 */
		struct CPUWatchpoint * * tqe_prev;       /*    40     8 */
	} entry;                                         /*    32    16 */
	/* size: 48, cachelines: 1, members: 6 */
	/* last cacheline: 48 bytes */
};
struct icount_decr_u16;
typedef struct icount_decr_u16 icount_decr_u16;
struct icount_decr_u16 {
	uint16_t                   low;                  /*     0     2 */
	uint16_t                   high;                 /*     2     2 */
	/* size: 4, cachelines: 1, members: 2 */
	/* last cacheline: 4 bytes */
};
struct breakpoints_head;
typedef struct breakpoints_head breakpoints_head;
struct breakpoints_head {
	struct CPUBreakpoint *     tqh_first;            /*     0     8 */
	struct CPUBreakpoint * *   tqh_last;             /*     8     8 */
	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};
struct watchpoints_head;
typedef struct watchpoints_head watchpoints_head;
struct watchpoints_head {
	struct CPUWatchpoint *     tqh_first;            /*     0     8 */
	struct CPUWatchpoint * *   tqh_last;             /*     8     8 */
	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};
struct QemuOptHead;
typedef struct QemuOptHead QemuOptHead;
struct QemuOptHead {
	struct QemuOpt *           tqh_first;            /*     0     8 */
	struct QemuOpt * *         tqh_last;             /*     8     8 */
	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};
struct ChildrenHead;
typedef struct ChildrenHead ChildrenHead;
struct ChildrenHead {
	struct BusChild *          tqh_first;            /*     0     8 */
	struct BusChild * *        tqh_last;             /*     8     8 */
	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};
struct rcu_head;
typedef struct rcu_head rcu_head;
struct rcu_head {
	struct rcu_head *          next;                 /*     0     8 */
	RCUCBFunc *                func;                 /*     8     8 */
	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};
struct memory_listeners_as;
typedef struct memory_listeners_as memory_listeners_as;
struct memory_listeners_as {
	struct MemoryListener *    tqh_first;            /*     0     8 */
	struct MemoryListener * *  tqh_last;             /*     8     8 */
	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};
struct subregions;
typedef struct subregions subregions;
struct subregions {
	struct MemoryRegion *      tqh_first;            /*     0     8 */
	struct MemoryRegion * *    tqh_last;             /*     8     8 */
	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};
struct coalesced_ranges;
typedef struct coalesced_ranges coalesced_ranges;
struct coalesced_ranges {
	struct CoalescedMemoryRange * tqh_first;         /*     0     8 */
	struct CoalescedMemoryRange * * tqh_last;        /*     8     8 */
	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};
struct AddressSpace;
typedef struct AddressSpace AddressSpace;
struct MemoryRegion;
typedef struct MemoryRegion MemoryRegion;
struct MemoryListener;
typedef struct MemoryListener MemoryListener;
struct AddressSpace {
	struct rcu_head    rcu;                          /*     0    16 */
	char *                     name;                 /*    16     8 */
	MemoryRegion *             root;                 /*    24     8 */
	int                        ref_count;            /*    32     4 */
	_Bool                      malloced;             /*    36     1 */
	/* XXX 3 bytes hole, try to pack */
	struct FlatView *          current_map;          /*    40     8 */
	int                        ioeventfd_nb;         /*    48     4 */
	/* XXX 4 bytes hole, try to pack */
	struct MemoryRegionIoeventfd * ioeventfds;       /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	struct AddressSpaceDispatch * dispatch;          /*    64     8 */
	struct AddressSpaceDispatch * next_dispatch;     /*    72     8 */
	MemoryListener             dispatch_listener;    /*    80   160 */
	/* --- cacheline 3 boundary (192 bytes) was 48 bytes ago --- */
	struct memory_listeners_as listeners;            /*   240    16 */
	/* --- cacheline 4 boundary (256 bytes) --- */
	struct {
		struct AddressSpace * tqe_next;          /*   256     8 */
		struct AddressSpace * * tqe_prev;        /*   264     8 */
	} address_spaces_link;                           /*   256    16 */
	/* size: 272, cachelines: 5, members: 13 */
	/* sum members: 265, holes: 2, sum holes: 7 */
	/* last cacheline: 16 bytes */
};
struct CPUAddressSpace;
typedef struct CPUAddressSpace CPUAddressSpace;
struct CPUState;
typedef struct CPUState CPUState;
struct CPUAddressSpace {
	CPUState *                 cpu;                  /*     0     8 */
	AddressSpace *             as;                   /*     8     8 */
	struct AddressSpaceDispatch * memory_dispatch;   /*    16     8 */
	MemoryListener             tcg_as_listener;      /*    24   160 */
	/* size: 184, cachelines: 3, members: 4 */
	/* last cacheline: 56 bytes */
};
struct QemuOptsList;
typedef struct QemuOptsList QemuOptsList;
struct QemuOptsList {
	const char  *              name;                 /*     0     8 */
	const char  *              implied_opt_name;     /*     8     8 */
	_Bool                      merge_lists;          /*    16     1 */
	/* XXX 7 bytes hole, try to pack */
	struct {
		struct QemuOpts *  tqh_first;            /*    24     8 */
		struct QemuOpts * * tqh_last;            /*    32     8 */
	} head;                                          /*    24    16 */
	QemuOptDesc                desc[];               /*    40     0 */
	/* size: 40, cachelines: 1, members: 5 */
	/* sum members: 33, holes: 1, sum holes: 7 */
	/* last cacheline: 40 bytes */
};
struct IOMMUTLBEntry;
typedef struct IOMMUTLBEntry IOMMUTLBEntry;
struct IOMMUTLBEntry {
	AddressSpace *             target_as;            /*     0     8 */
	hwaddr                     iova;                 /*     8     8 */
	hwaddr                     translated_addr;      /*    16     8 */
	hwaddr                     addr_mask;            /*    24     8 */
	IOMMUAccessFlags           perm;                 /*    32     4 */
	/* size: 40, cachelines: 1, members: 5 */
	/* padding: 4 */
	/* last cacheline: 40 bytes */
};
struct MemoryRegionIOMMUOps;
typedef struct MemoryRegionIOMMUOps MemoryRegionIOMMUOps;
struct MemoryRegionIOMMUOps {
	IOMMUTLBEntry              (*translate)(MemoryRegion *, hwaddr, _Bool); /*     0     8 */
	uint64_t                   (*get_min_page_size)(MemoryRegion *); /*     8     8 */
	void                       (*notify_flag_changed)(MemoryRegion *, IOMMUNotifierFlag, IOMMUNotifierFlag); /*    16     8 */
	/* size: 24, cachelines: 1, members: 3 */
	/* last cacheline: 24 bytes */
};
struct MemoryRegionOps;
typedef struct MemoryRegionOps MemoryRegionOps;
struct MemoryRegionOps {
	uint64_t                   (*read)(void *, hwaddr, unsigned int); /*     0     8 */
	void                       (*write)(void *, hwaddr, uint64_t, unsigned int); /*     8     8 */
	MemTxResult                (*read_with_attrs)(void *, hwaddr, uint64_t *, unsigned int, MemTxAttrs); /*    16     8 */
	MemTxResult                (*write_with_attrs)(void *, hwaddr, uint64_t, unsigned int, MemTxAttrs); /*    24     8 */
	enum device_endian endianness;                   /*    32     4 */
	/* XXX 4 bytes hole, try to pack */
	struct {
		unsigned int       min_access_size;      /*    40     4 */
		unsigned int       max_access_size;      /*    44     4 */
		_Bool              unaligned;            /*    48     1 */
		/* XXX 7 bytes hole, try to pack */
		_Bool              (*accepts)(void *, hwaddr, unsigned int, _Bool); /*    56     8 */
	} valid;                                         /*    40    24 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	struct {
		unsigned int       min_access_size;      /*    64     4 */
		unsigned int       max_access_size;      /*    68     4 */
		_Bool              unaligned;            /*    72     1 */
	} impl;                                          /*    64    12 */
	/* XXX last struct has 3 bytes of padding */
	/* XXX 4 bytes hole, try to pack */
	const MemoryRegionMmio     old_mmio;             /*    80    48 */
	/* size: 128, cachelines: 2, members: 8 */
	/* sum members: 120, holes: 2, sum holes: 8 */
	/* paddings: 1, sum paddings: 3 */
};
struct MemoryRegionIoeventfd;
typedef struct MemoryRegionIoeventfd MemoryRegionIoeventfd;
struct MemoryRegionIoeventfd {
	AddrRange                  addr;                 /*     0    32 */
	_Bool                      match_data;           /*    32     1 */
	/* XXX 7 bytes hole, try to pack */
	uint64_t                   data;                 /*    40     8 */
	EventNotifier *            e;                    /*    48     8 */
	/* size: 64, cachelines: 1, members: 4 */
	/* sum members: 49, holes: 1, sum holes: 7 */
	/* padding: 8 */
};
struct MemoryRegion;
typedef struct MemoryRegion MemoryRegion;
struct MemoryRegion {
	Object                     parent_obj;           /*     0    40 */
	_Bool                      romd_mode;            /*    40     1 */
	_Bool                      ram;                  /*    41     1 */
	_Bool                      subpage;              /*    42     1 */
	_Bool                      readonly;             /*    43     1 */
	_Bool                      rom_device;           /*    44     1 */
	_Bool                      flush_coalesced_mmio; /*    45     1 */
	_Bool                      global_locking;       /*    46     1 */
	uint8_t                    dirty_log_mask;       /*    47     1 */
	RAMBlock *                 ram_block;            /*    48     8 */
	Object *                   owner;                /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	const MemoryRegionIOMMUOps  * iommu_ops;         /*    64     8 */
	const MemoryRegionOps  *   ops;                  /*    72     8 */
	void *                     opaque;               /*    80     8 */
	MemoryRegion *             container;            /*    88     8 */
	Int128                     size;                 /*    96    16 */
	hwaddr                     addr;                 /*   112     8 */
	void                       (*destructor)(MemoryRegion *); /*   120     8 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	uint64_t                   align;                /*   128     8 */
	_Bool                      terminates;           /*   136     1 */
	_Bool                      ram_device;           /*   137     1 */
	_Bool                      enabled;              /*   138     1 */
	_Bool                      warning_printed;      /*   139     1 */
	uint8_t                    vga_logging_count;    /*   140     1 */
	/* XXX 3 bytes hole, try to pack */
	MemoryRegion *             alias;                /*   144     8 */
	hwaddr                     alias_offset;         /*   152     8 */
	int32_t                    priority;             /*   160     4 */
	/* XXX 4 bytes hole, try to pack */
	struct subregions  subregions;                   /*   168    16 */
	struct {
		struct MemoryRegion * tqe_next;          /*   184     8 */
		/* --- cacheline 3 boundary (192 bytes) --- */
		struct MemoryRegion * * tqe_prev;        /*   192     8 */
	} subregions_link;                               /*   184    16 */
	struct coalesced_ranges coalesced;               /*   200    16 */
	const char  *              name;                 /*   216     8 */
	unsigned int               ioeventfd_nb;         /*   224     4 */
	/* XXX 4 bytes hole, try to pack */
	MemoryRegionIoeventfd *    ioeventfds;           /*   232     8 */
	struct {
		struct IOMMUNotifier * lh_first;         /*   240     8 */
	} iommu_notify;                                  /*   240     8 */
	IOMMUNotifierFlag          iommu_notify_flags;   /*   248     4 */
	/* size: 256, cachelines: 4, members: 35 */
	/* sum members: 241, holes: 3, sum holes: 11 */
	/* padding: 4 */
};
struct MemoryRegionSection;
typedef struct MemoryRegionSection MemoryRegionSection;
struct MemoryRegionSection {
	MemoryRegion *             mr;                   /*     0     8 */
	AddressSpace *             address_space;        /*     8     8 */
	hwaddr                     offset_within_region; /*    16     8 */
	/* XXX 8 bytes hole, try to pack */
	Int128                     size;                 /*    32    16 */
	hwaddr                     offset_within_address_space; /*    48     8 */
	_Bool                      readonly;             /*    56     1 */
	/* size: 64, cachelines: 1, members: 6 */
	/* sum members: 49, holes: 1, sum holes: 8 */
	/* padding: 7 */
};
struct MemoryListener;
typedef struct MemoryListener MemoryListener;
struct MemoryListener {
	void                       (*begin)(MemoryListener *); /*     0     8 */
	void                       (*commit)(MemoryListener *); /*     8     8 */
	void                       (*region_add)(MemoryListener *, MemoryRegionSection *); /*    16     8 */
	void                       (*region_del)(MemoryListener *, MemoryRegionSection *); /*    24     8 */
	void                       (*region_nop)(MemoryListener *, MemoryRegionSection *); /*    32     8 */
	void                       (*log_start)(MemoryListener *, MemoryRegionSection *, int, int); /*    40     8 */
	void                       (*log_stop)(MemoryListener *, MemoryRegionSection *, int, int); /*    48     8 */
	void                       (*log_sync)(MemoryListener *, MemoryRegionSection *); /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	void                       (*log_global_start)(MemoryListener *); /*    64     8 */
	void                       (*log_global_stop)(MemoryListener *); /*    72     8 */
	void                       (*eventfd_add)(MemoryListener *, MemoryRegionSection *, _Bool, uint64_t, EventNotifier *); /*    80     8 */
	void                       (*eventfd_del)(MemoryListener *, MemoryRegionSection *, _Bool, uint64_t, EventNotifier *); /*    88     8 */
	void                       (*coalesced_mmio_add)(MemoryListener *, MemoryRegionSection *, hwaddr, hwaddr); /*    96     8 */
	void                       (*coalesced_mmio_del)(MemoryListener *, MemoryRegionSection *, hwaddr, hwaddr); /*   104     8 */
	unsigned int               priority;             /*   112     4 */
	/* XXX 4 bytes hole, try to pack */
	AddressSpace *             address_space;        /*   120     8 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	struct {
		struct MemoryListener * tqe_next;        /*   128     8 */
		struct MemoryListener * * tqe_prev;      /*   136     8 */
	} link;                                          /*   128    16 */
	struct {
		struct MemoryListener * tqe_next;        /*   144     8 */
		struct MemoryListener * * tqe_prev;      /*   152     8 */
	} link_as;                                       /*   144    16 */
	/* size: 160, cachelines: 3, members: 18 */
	/* sum members: 156, holes: 1, sum holes: 4 */
	/* last cacheline: 32 bytes */
};
struct QString;
typedef struct QString QString;
struct QString {
	QObject                    base;                 /*     0    16 */
	char *                     string;               /*    16     8 */
	size_t                     length;               /*    24     8 */
	size_t                     capacity;             /*    32     8 */
	/* size: 40, cachelines: 1, members: 4 */
	/* last cacheline: 40 bytes */
};
struct QemuOpts;
typedef struct QemuOpts QemuOpts;
struct QemuOpts {
	char *                     id;                   /*     0     8 */
	QemuOptsList *             list;                 /*     8     8 */
	Location                   loc;                  /*    16    24 */
	struct QemuOptHead head;                         /*    40    16 */
	struct {
		struct QemuOpts *  tqe_next;             /*    56     8 */
		/* --- cacheline 1 boundary (64 bytes) --- */
		struct QemuOpts * * tqe_prev;            /*    64     8 */
	} next;                                          /*    56    16 */
	/* size: 72, cachelines: 2, members: 5 */
	/* last cacheline: 8 bytes */
};
struct DeviceState;
typedef struct DeviceState DeviceState;
struct BusState;
typedef struct BusState BusState;
struct DeviceState {
	Object                     parent_obj;           /*     0    40 */
	const char  *              id;                   /*    40     8 */
	_Bool                      realized;             /*    48     1 */
	_Bool                      pending_deleted_event; /*    49     1 */
	/* XXX 6 bytes hole, try to pack */
	QemuOpts *                 opts;                 /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	int                        hotplugged;           /*    64     4 */
	/* XXX 4 bytes hole, try to pack */
	BusState *                 parent_bus;           /*    72     8 */
	struct {
		struct NamedGPIOList * lh_first;         /*    80     8 */
	} gpios;                                         /*    80     8 */
	struct {
		struct BusState *  lh_first;             /*    88     8 */
	} child_bus;                                     /*    88     8 */
	int                        num_child_bus;        /*    96     4 */
	int                        instance_id_alias;    /*   100     4 */
	int                        alias_required_for_version; /*   104     4 */
	/* size: 112, cachelines: 2, members: 12 */
	/* sum members: 98, holes: 2, sum holes: 10 */
	/* padding: 4 */
	/* last cacheline: 48 bytes */
};
struct Chardev;
typedef struct Chardev Chardev;
struct Chardev {
	Object                     parent_obj;           /*     0    40 */
	QemuMutex                  chr_write_lock;       /*    40    40 */
	/* --- cacheline 1 boundary (64 bytes) was 16 bytes ago --- */
	CharBackend *              be;                   /*    80     8 */
	char *                     label;                /*    88     8 */
	char *                     filename;             /*    96     8 */
	int                        logfd;                /*   104     4 */
	int                        be_open;              /*   108     4 */
	guint                      fd_in_tag;            /*   112     4 */
	/* XXX 4 bytes hole, try to pack */
	long unsigned int          features[1];          /*   120     8 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	struct {
		struct Chardev *   tqe_next;             /*   128     8 */
		struct Chardev * * tqe_prev;             /*   136     8 */
	} next;                                          /*   128    16 */
	/* size: 144, cachelines: 3, members: 10 */
	/* sum members: 140, holes: 1, sum holes: 4 */
	/* last cacheline: 16 bytes */
};
struct MachineState;
typedef struct MachineState MachineState;
struct MachineState {
	Object                     parent_obj;           /*     0    40 */
	Notifier                   sysbus_notifier;      /*    40    24 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	char *                     accel;                /*    64     8 */
	_Bool                      kernel_irqchip_allowed; /*    72     1 */
	_Bool                      kernel_irqchip_required; /*    73     1 */
	_Bool                      kernel_irqchip_split; /*    74     1 */
	/* XXX 1 byte hole, try to pack */
	int                        kvm_shadow_mem;       /*    76     4 */
	char *                     dtb;                  /*    80     8 */
	char *                     dumpdtb;              /*    88     8 */
	int                        phandle_start;        /*    96     4 */
	/* XXX 4 bytes hole, try to pack */
	char *                     dt_compatible;        /*   104     8 */
	_Bool                      dump_guest_core;      /*   112     1 */
	_Bool                      mem_merge;            /*   113     1 */
	_Bool                      usb;                  /*   114     1 */
	_Bool                      usb_disabled;         /*   115     1 */
	_Bool                      igd_gfx_passthru;     /*   116     1 */
	/* XXX 3 bytes hole, try to pack */
	char *                     firmware;             /*   120     8 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	_Bool                      iommu;                /*   128     1 */
	_Bool                      suppress_vmdesc;      /*   129     1 */
	_Bool                      enforce_config_section; /*   130     1 */
	_Bool                      enable_graphics;      /*   131     1 */
	int                        board_id;             /*   132     4 */
	char *                     mem_map_str;          /*   136     8 */
	ram_addr_t                 ram_size;             /*   144     8 */
	ram_addr_t                 maxram_size;          /*   152     8 */
	uint64_t                   ram_slots;            /*   160     8 */
	const char  *              boot_order;           /*   168     8 */
	char *                     kernel_filename;      /*   176     8 */
	char *                     kernel_cmdline;       /*   184     8 */
	/* --- cacheline 3 boundary (192 bytes) --- */
	char *                     initrd_filename;      /*   192     8 */
	const char  *              cpu_model;            /*   200     8 */
	AccelState *               accelerator;          /*   208     8 */
	CPUArchIdList *            possible_cpus;        /*   216     8 */
	/* size: 224, cachelines: 4, members: 33 */
	/* sum members: 216, holes: 3, sum holes: 8 */
	/* last cacheline: 32 bytes */
};
struct Monitor;
typedef struct Monitor Monitor;
struct Monitor {
	CharBackend                chr;                  /*     0    48 */
	int                        reset_seen;           /*    48     4 */
	int                        flags;                /*    52     4 */
	int                        suspend_cnt;          /*    56     4 */
	_Bool                      skip_flush;           /*    60     1 */
	/* XXX 3 bytes hole, try to pack */
	/* --- cacheline 1 boundary (64 bytes) --- */
	QemuMutex                  out_lock;             /*    64    40 */
	QString *                  outbuf;               /*   104     8 */
	guint                      out_watch;            /*   112     4 */
	int                        mux_out;              /*   116     4 */
	ReadLineState *            rs;                   /*   120     8 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	MonitorQMP                 qmp;                  /*   128    72 */
	/* --- cacheline 3 boundary (192 bytes) was 8 bytes ago --- */
	CPUState *                 mon_cpu;              /*   200     8 */
	BlockCompletionFunc *      password_completion_cb; /*   208     8 */
	void *                     password_opaque;      /*   216     8 */
	mon_cmd_t *                cmd_table;            /*   224     8 */
	struct {
		struct mon_fd_t *  lh_first;             /*   232     8 */
	} fds;                                           /*   232     8 */
	struct {
		struct Monitor *   le_next;              /*   240     8 */
		struct Monitor * * le_prev;              /*   248     8 */
	} entry;                                         /*   240    16 */
	/* size: 256, cachelines: 4, members: 17 */
	/* sum members: 253, holes: 1, sum holes: 3 */
};
struct BusState;
typedef struct BusState BusState;
struct BusState {
	Object                     obj;                  /*     0    40 */
	DeviceState *              parent;               /*    40     8 */
	char *                     name;                 /*    48     8 */
	HotplugHandler *           hotplug_handler;      /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	int                        max_index;            /*    64     4 */
	_Bool                      realized;             /*    68     1 */
	/* XXX 3 bytes hole, try to pack */
	struct ChildrenHead children;                    /*    72    16 */
	struct {
		struct BusState *  le_next;              /*    88     8 */
		struct BusState * * le_prev;             /*    96     8 */
	} sibling;                                       /*    88    16 */
	/* size: 104, cachelines: 2, members: 8 */
	/* sum members: 101, holes: 1, sum holes: 3 */
	/* last cacheline: 40 bytes */
};
struct CPUARMState;
typedef struct CPUARMState CPUARMState;
struct CPUARMState {
	uint32_t                   regs[16];             /*     0    64 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	uint64_t                   xregs[32];            /*    64   256 */
	/* --- cacheline 5 boundary (320 bytes) --- */
	uint64_t                   pc;                   /*   320     8 */
	uint32_t                   pstate;               /*   328     4 */
	uint32_t                   aarch64;              /*   332     4 */
	uint32_t                   uncached_cpsr;        /*   336     4 */
	uint32_t                   spsr;                 /*   340     4 */
	uint64_t                   banked_spsr[8];       /*   344    64 */
	/* --- cacheline 6 boundary (384 bytes) was 24 bytes ago --- */
	uint32_t                   banked_r13[8];        /*   408    32 */
	uint32_t                   banked_r14[8];        /*   440    32 */
	/* --- cacheline 7 boundary (448 bytes) was 24 bytes ago --- */
	uint32_t                   usr_regs[5];          /*   472    20 */
	uint32_t                   fiq_regs[5];          /*   492    20 */
	/* --- cacheline 8 boundary (512 bytes) --- */
	uint32_t                   CF;                   /*   512     4 */
	uint32_t                   VF;                   /*   516     4 */
	uint32_t                   NF;                   /*   520     4 */
	uint32_t                   ZF;                   /*   524     4 */
	uint32_t                   QF;                   /*   528     4 */
	uint32_t                   GE;                   /*   532     4 */
	uint32_t                   thumb;                /*   536     4 */
	uint32_t                   condexec_bits;        /*   540     4 */
	uint64_t                   daif;                 /*   544     8 */
	uint64_t                   elr_el[4];            /*   552    32 */
	/* --- cacheline 9 boundary (576 bytes) was 8 bytes ago --- */
	uint64_t                   sp_el[4];             /*   584    32 */
	struct {
		uint32_t           c0_cpuid;             /*   616     4 */
		/* XXX 4 bytes hole, try to pack */
		union {
			struct {
				uint64_t _unused_csselr0; /*   624     8 */
				uint64_t csselr_ns;      /*   632     8 */
				/* --- cacheline 10 boundary (640 bytes) --- */
				uint64_t _unused_csselr1; /*   640     8 */
				uint64_t csselr_s;       /*   648     8 */
			};                               /*   624    32 */
			uint64_t   csselr_el[4];         /*   624    32 */
		};                                       /*   624    32 */
		/* --- cacheline 10 boundary (640 bytes) was 16 bytes ago --- */
		union {
			struct {
				uint64_t _unused_sctlr;  /*   656     8 */
				uint64_t sctlr_ns;       /*   664     8 */
				uint64_t hsctlr;         /*   672     8 */
				uint64_t sctlr_s;        /*   680     8 */
			};                               /*   656    32 */
			uint64_t   sctlr_el[4];          /*   656    32 */
		};                                       /*   656    32 */
		uint64_t           cpacr_el1;            /*   688     8 */
		uint64_t           cptr_el[4];           /*   696    32 */
		/* --- cacheline 11 boundary (704 bytes) was 24 bytes ago --- */
		uint32_t           c1_xscaleauxcr;       /*   728     4 */
		/* XXX 4 bytes hole, try to pack */
		uint64_t           sder;                 /*   736     8 */
		uint32_t           nsacr;                /*   744     4 */
		/* XXX 4 bytes hole, try to pack */
		union {
			struct {
				uint64_t _unused_ttbr0_0; /*   752     8 */
				uint64_t ttbr0_ns;       /*   760     8 */
				/* --- cacheline 12 boundary (768 bytes) --- */
				uint64_t _unused_ttbr0_1; /*   768     8 */
				uint64_t ttbr0_s;        /*   776     8 */
			};                               /*   752    32 */
			uint64_t   ttbr0_el[4];          /*   752    32 */
		};                                       /*   752    32 */
		/* --- cacheline 12 boundary (768 bytes) was 16 bytes ago --- */
		union {
			struct {
				uint64_t _unused_ttbr1_0; /*   784     8 */
				uint64_t ttbr1_ns;       /*   792     8 */
				uint64_t _unused_ttbr1_1; /*   800     8 */
				uint64_t ttbr1_s;        /*   808     8 */
			};                               /*   784    32 */
			uint64_t   ttbr1_el[4];          /*   784    32 */
		};                                       /*   784    32 */
		uint64_t           vttbr_el2;            /*   816     8 */
		TCR                tcr_el[4];            /*   824    64 */
		/* --- cacheline 13 boundary (832 bytes) was 56 bytes ago --- */
		TCR                vtcr_el2;             /*   888    16 */
		/* --- cacheline 14 boundary (896 bytes) was 8 bytes ago --- */
		uint32_t           c2_data;              /*   904     4 */
		uint32_t           c2_insn;              /*   908     4 */
		union {
			struct {
				uint64_t dacr_ns;        /*   912     8 */
				uint64_t dacr_s;         /*   920     8 */
			};                               /*   912    16 */
			struct {
				uint64_t dacr32_el2;     /*   912     8 */
			};                               /*   912     8 */
		};                                       /*   912    16 */
		uint32_t           pmsav5_data_ap;       /*   928     4 */
		uint32_t           pmsav5_insn_ap;       /*   932     4 */
		uint64_t           hcr_el2;              /*   936     8 */
		uint64_t           scr_el3;              /*   944     8 */
		union {
			struct {
				uint64_t ifsr_ns;        /*   952     8 */
				/* --- cacheline 15 boundary (960 bytes) --- */
				uint64_t ifsr_s;         /*   960     8 */
			};                               /*   952    16 */
			struct {
				uint64_t ifsr32_el2;     /*   952     8 */
			};                               /*   952     8 */
		};                                       /*   952    16 */
		/* --- cacheline 15 boundary (960 bytes) was 8 bytes ago --- */
		union {
			struct {
				uint64_t _unused_dfsr;   /*   968     8 */
				uint64_t dfsr_ns;        /*   976     8 */
				uint64_t hsr;            /*   984     8 */
				uint64_t dfsr_s;         /*   992     8 */
			};                               /*   968    32 */
			uint64_t   esr_el[4];            /*   968    32 */
		};                                       /*   968    32 */
		uint32_t           c6_region[8];         /*  1000    32 */
		/* --- cacheline 16 boundary (1024 bytes) was 8 bytes ago --- */
		union {
			struct {
				uint64_t _unused_far0;   /*  1032     8 */
				uint32_t dfar_ns;        /*  1040     4 */
				uint32_t ifar_ns;        /*  1044     4 */
				uint32_t dfar_s;         /*  1048     4 */
				uint32_t ifar_s;         /*  1052     4 */
				uint64_t _unused_far3;   /*  1056     8 */
			};                               /*  1032    32 */
			uint64_t   far_el[4];            /*  1032    32 */
		};                                       /*  1032    32 */
		uint64_t           hpfar_el2;            /*  1064     8 */
		uint64_t           hstr_el2;             /*  1072     8 */
		union {
			struct {
				uint64_t _unused_par_0;  /*  1080     8 */
				/* --- cacheline 17 boundary (1088 bytes) --- */
				uint64_t par_ns;         /*  1088     8 */
				uint64_t _unused_par_1;  /*  1096     8 */
				uint64_t par_s;          /*  1104     8 */
			};                               /*  1080    32 */
			uint64_t   par_el[4];            /*  1080    32 */
		};                                       /*  1080    32 */
		/* --- cacheline 17 boundary (1088 bytes) was 24 bytes ago --- */
		uint32_t           c6_rgnr;              /*  1112     4 */
		uint32_t           c9_insn;              /*  1116     4 */
		uint32_t           c9_data;              /*  1120     4 */
		/* XXX 4 bytes hole, try to pack */
		uint64_t           c9_pmcr;              /*  1128     8 */
		uint64_t           c9_pmcnten;           /*  1136     8 */
		uint32_t           c9_pmovsr;            /*  1144     4 */
		uint32_t           c9_pmuserenr;         /*  1148     4 */
		/* --- cacheline 18 boundary (1152 bytes) --- */
		uint64_t           c9_pmselr;            /*  1152     8 */
		uint64_t           c9_pminten;           /*  1160     8 */
		union {
			struct {
				uint64_t _unused_mair_0; /*  1168     8 */
				uint32_t mair0_ns;       /*  1176     4 */
				uint32_t mair1_ns;       /*  1180     4 */
				uint64_t _unused_mair_1; /*  1184     8 */
				uint32_t mair0_s;        /*  1192     4 */
				uint32_t mair1_s;        /*  1196     4 */
			};                               /*  1168    32 */
			uint64_t   mair_el[4];           /*  1168    32 */
		};                                       /*  1168    32 */
		union {
			struct {
				uint64_t _unused_vbar;   /*  1200     8 */
				uint64_t vbar_ns;        /*  1208     8 */
				/* --- cacheline 19 boundary (1216 bytes) --- */
				uint64_t hvbar;          /*  1216     8 */
				uint64_t vbar_s;         /*  1224     8 */
			};                               /*  1200    32 */
			uint64_t   vbar_el[4];           /*  1200    32 */
		};                                       /*  1200    32 */
		/* --- cacheline 19 boundary (1216 bytes) was 16 bytes ago --- */
		uint32_t           mvbar;                /*  1232     4 */
		struct {
			uint32_t   fcseidr_ns;           /*  1236     4 */
			uint32_t   fcseidr_s;            /*  1240     4 */
		};                                       /*  1236     8 */
		/* XXX 4 bytes hole, try to pack */
		union {
			struct {
				uint64_t _unused_contextidr_0; /*  1248     8 */
				uint64_t contextidr_ns;  /*  1256     8 */
				uint64_t _unused_contextidr_1; /*  1264     8 */
				uint64_t contextidr_s;   /*  1272     8 */
			};                               /*  1248    32 */
			uint64_t   contextidr_el[4];     /*  1248    32 */
		};                                       /*  1248    32 */
		/* --- cacheline 20 boundary (1280 bytes) --- */
		union {
			struct {
				uint64_t tpidrurw_ns;    /*  1280     8 */
				uint64_t tpidrprw_ns;    /*  1288     8 */
				uint64_t htpidr;         /*  1296     8 */
				uint64_t _tpidr_el3;     /*  1304     8 */
			};                               /*  1280    32 */
			uint64_t   tpidr_el[4];          /*  1280    32 */
		};                                       /*  1280    32 */
		uint64_t           tpidrurw_s;           /*  1312     8 */
		uint64_t           tpidrprw_s;           /*  1320     8 */
		uint64_t           tpidruro_s;           /*  1328     8 */
		union {
			uint64_t   tpidruro_ns;          /*  1336     8 */
			uint64_t   tpidrro_el[1];        /*  1336     8 */
		};                                       /*  1336     8 */
		/* --- cacheline 21 boundary (1344 bytes) --- */
		uint64_t           c14_cntfrq;           /*  1344     8 */
		uint64_t           c14_cntkctl;          /*  1352     8 */
		uint32_t           cnthctl_el2;          /*  1360     4 */
		/* XXX 4 bytes hole, try to pack */
		uint64_t           cntvoff_el2;          /*  1368     8 */
		ARMGenericTimer    c14_timer[4];         /*  1376    64 */
		/* --- cacheline 22 boundary (1408 bytes) was 32 bytes ago --- */
		uint32_t           c15_cpar;             /*  1440     4 */
		uint32_t           c15_ticonfig;         /*  1444     4 */
		uint32_t           c15_i_max;            /*  1448     4 */
		uint32_t           c15_i_min;            /*  1452     4 */
		uint32_t           c15_threadid;         /*  1456     4 */
		uint32_t           c15_config_base_address; /*  1460     4 */
		uint32_t           c15_diagnostic;       /*  1464     4 */
		uint32_t           c15_power_diagnostic; /*  1468     4 */
		/* --- cacheline 23 boundary (1472 bytes) --- */
		uint32_t           c15_power_control;    /*  1472     4 */
		/* XXX 4 bytes hole, try to pack */
		uint64_t           dbgbvr[16];           /*  1480   128 */
		/* --- cacheline 25 boundary (1600 bytes) was 8 bytes ago --- */
		uint64_t           dbgbcr[16];           /*  1608   128 */
		/* --- cacheline 27 boundary (1728 bytes) was 8 bytes ago --- */
		uint64_t           dbgwvr[16];           /*  1736   128 */
		/* --- cacheline 29 boundary (1856 bytes) was 8 bytes ago --- */
		uint64_t           dbgwcr[16];           /*  1864   128 */
		/* --- cacheline 31 boundary (1984 bytes) was 8 bytes ago --- */
		uint64_t           mdscr_el1;            /*  1992     8 */
		uint64_t           oslsr_el1;            /*  2000     8 */
		uint64_t           mdcr_el2;             /*  2008     8 */
		uint64_t           mdcr_el3;             /*  2016     8 */
		uint64_t           c15_ccnt;             /*  2024     8 */
		uint64_t           pmccfiltr_el0;        /*  2032     8 */
		uint64_t           vpidr_el2;            /*  2040     8 */
		/* --- cacheline 32 boundary (2048 bytes) --- */
		uint64_t           vmpidr_el2;           /*  2048     8 */
	} cp15;                                          /*   616  1440 */
	struct {
		uint32_t           other_sp;             /*  2056     4 */
		uint32_t           vecbase;              /*  2060     4 */
		uint32_t           basepri;              /*  2064     4 */
		uint32_t           control;              /*  2068     4 */
		uint32_t           ccr;                  /*  2072     4 */
		uint32_t           cfsr;                 /*  2076     4 */
		uint32_t           hfsr;                 /*  2080     4 */
		uint32_t           dfsr;                 /*  2084     4 */
		uint32_t           mmfar;                /*  2088     4 */
		uint32_t           bfar;                 /*  2092     4 */
		int                exception;            /*  2096     4 */
	} v7m;                                           /*  2056    44 */
	/* XXX 4 bytes hole, try to pack */
	struct {
		uint32_t           syndrome;             /*  2104     4 */
		uint32_t           fsr;                  /*  2108     4 */
		/* --- cacheline 33 boundary (2112 bytes) --- */
		uint64_t           vaddress;             /*  2112     8 */
		uint32_t           target_el;            /*  2120     4 */
	} exception;                                     /*  2104    24 */
	/* XXX last struct has 4 bytes of padding */
	uint32_t                   teecr;                /*  2128     4 */
	uint32_t                   teehbr;               /*  2132     4 */
	struct {
		float64            regs[64];             /*  2136   512 */
		/* --- cacheline 41 boundary (2624 bytes) was 24 bytes ago --- */
		uint32_t           xregs[16];            /*  2648    64 */
		/* --- cacheline 42 boundary (2688 bytes) was 24 bytes ago --- */
		int                vec_len;              /*  2712     4 */
		int                vec_stride;           /*  2716     4 */
		uint32_t           scratch[8];           /*  2720    32 */
		/* --- cacheline 43 boundary (2752 bytes) --- */
		float_status       fp_status;            /*  2752     8 */
		float_status       standard_fp_status;   /*  2760     8 */
	} vfp;                                           /*  2136   632 */
	uint64_t                   exclusive_addr;       /*  2768     8 */
	uint64_t                   exclusive_val;        /*  2776     8 */
	uint64_t                   exclusive_high;       /*  2784     8 */
	struct {
		uint64_t           regs[16];             /*  2792   128 */
		/* --- cacheline 45 boundary (2880 bytes) was 40 bytes ago --- */
		uint64_t           val;                  /*  2920     8 */
		uint32_t           cregs[16];            /*  2928    64 */
	} iwmmxt;                                        /*  2792   200 */
	/* --- cacheline 46 boundary (2944 bytes) was 48 bytes ago --- */
	struct CPUBreakpoint *     cpu_breakpoint[16];   /*  2992   128 */
	/* --- cacheline 48 boundary (3072 bytes) was 48 bytes ago --- */
	struct CPUWatchpoint *     cpu_watchpoint[16];   /*  3120   128 */
	/* --- cacheline 50 boundary (3200 bytes) was 48 bytes ago --- */
		                              /*  3248     0 */
	CPUTLBEntry                tlb_table[7][256];    /*  3248 57344 */
	/* --- cacheline 946 boundary (60544 bytes) was 48 bytes ago --- */
	CPUTLBEntry                tlb_v_table[7][8];    /* 60592  1792 */
	/* --- cacheline 974 boundary (62336 bytes) was 48 bytes ago --- */
	CPUIOTLBEntry              iotlb[7][256];        /* 62384 28672 */
	/* --- cacheline 1422 boundary (91008 bytes) was 48 bytes ago --- */
	CPUIOTLBEntry              iotlb_v[7][8];        /* 91056   896 */
	/* --- cacheline 1436 boundary (91904 bytes) was 48 bytes ago --- */
	target_ulong               tlb_flush_addr;       /* 91952     8 */
	target_ulong               tlb_flush_mask;       /* 91960     8 */
	/* --- cacheline 1437 boundary (91968 bytes) --- */
	target_ulong               vtlb_index;           /* 91968     8 */
	uint64_t                   features;             /* 91976     8 */
	struct {
		uint32_t *         drbar;                /* 91984     8 */
		uint32_t *         drsr;                 /* 91992     8 */
		uint32_t *         dracr;                /* 92000     8 */
	} pmsav7;                                        /* 91984    24 */
	void *                     nvic;                 /* 92008     8 */
	const struct arm_boot_info  * boot_info;         /* 92016     8 */
	void *                     gicv3state;           /* 92024     8 */
	/* size: 92032, cachelines: 1438, members: 48 */
	/* sum members: 92028, holes: 1, sum holes: 4 */
	/* paddings: 1, sum paddings: 4 */
};
struct CPUState;
typedef struct CPUState CPUState;
struct CPUState {
	DeviceState                parent_obj;           /*     0   112 */
	/* --- cacheline 1 boundary (64 bytes) was 48 bytes ago --- */
	int                        nr_cores;             /*   112     4 */
	int                        nr_threads;           /*   116     4 */
	int                        numa_node;            /*   120     4 */
	/* XXX 4 bytes hole, try to pack */
	/* --- cacheline 2 boundary (128 bytes) --- */
	struct QemuThread *        thread;               /*   128     8 */
	int                        thread_id;            /*   136     4 */
	uint32_t                   host_tid;             /*   140     4 */
	_Bool                      running;              /*   144     1 */
	_Bool                      has_waiter;           /*   145     1 */
	/* XXX 6 bytes hole, try to pack */
	struct QemuCond *          halt_cond;            /*   152     8 */
	_Bool                      thread_kicked;        /*   160     1 */
	_Bool                      created;              /*   161     1 */
	_Bool                      stop;                 /*   162     1 */
	_Bool                      stopped;              /*   163     1 */
	_Bool                      unplug;               /*   164     1 */
	_Bool                      crash_occurred;       /*   165     1 */
	_Bool                      exit_request;         /*   166     1 */
	/* XXX 1 byte hole, try to pack */
	uint32_t                   interrupt_request;    /*   168     4 */
	int                        singlestep_enabled;   /*   172     4 */
	int64_t                    icount_budget;        /*   176     8 */
	int64_t                    icount_extra;         /*   184     8 */
	/* --- cacheline 3 boundary (192 bytes) --- */
	sigjmp_buf                 jmp_env;              /*   192   200 */
	/* --- cacheline 6 boundary (384 bytes) was 8 bytes ago --- */
	QemuMutex                  work_mutex;           /*   392    40 */
	struct qemu_work_item *    queued_work_first;    /*   432     8 */
	struct qemu_work_item *    queued_work_last;     /*   440     8 */
	/* --- cacheline 7 boundary (448 bytes) --- */
	CPUAddressSpace *          cpu_ases;             /*   448     8 */
	int                        num_ases;             /*   456     4 */
	/* XXX 4 bytes hole, try to pack */
	AddressSpace *             as;                   /*   464     8 */
	MemoryRegion *             memory;               /*   472     8 */
	CPUARMState *                     env_ptr;              /*   480     8 */
	struct TranslationBlock *  tb_jmp_cache[4096];   /*   488 32768 */
	/* --- cacheline 519 boundary (33216 bytes) was 40 bytes ago --- */
	struct GDBRegisterState *  gdb_regs;             /* 33256     8 */
	int                        gdb_num_regs;         /* 33264     4 */
	int                        gdb_num_g_regs;       /* 33268     4 */
	struct {
		struct CPUState *  tqe_next;             /* 33272     8 */
		/* --- cacheline 520 boundary (33280 bytes) --- */
		struct CPUState * * tqe_prev;            /* 33280     8 */
	} node;                                          /* 33272    16 */
	struct breakpoints_head breakpoints;             /* 33288    16 */
	struct watchpoints_head watchpoints;             /* 33304    16 */
	CPUWatchpoint *            watchpoint_hit;       /* 33320     8 */
	_Bool                      watchpoints_disabled; /* 33328     1 */
	/* XXX 7 bytes hole, try to pack */
	void *                     opaque;               /* 33336     8 */
	/* --- cacheline 521 boundary (33344 bytes) --- */
	uintptr_t                  mem_io_pc;            /* 33344     8 */
	vaddr                      mem_io_vaddr;         /* 33352     8 */
	int                        kvm_fd;               /* 33360     4 */
	_Bool                      kvm_vcpu_dirty;       /* 33364     1 */
	/* XXX 3 bytes hole, try to pack */
	struct KVMState *          kvm_state;            /* 33368     8 */
	struct kvm_run *           kvm_run;              /* 33376     8 */
	long unsigned int *        trace_dstate;         /* 33384     8 */
	int                        cpu_index;            /* 33392     4 */
	uint32_t                   halted;               /* 33396     4 */
	union {
		uint32_t           u32;                  /* 33400     4 */
		icount_decr_u16    u16;                  /* 33400     4 */
	} icount_decr;                                   /* 33400     4 */
	uint32_t                   can_do_io;            /* 33404     4 */
	/* --- cacheline 522 boundary (33408 bytes) --- */
	int32_t                    exception_index;      /* 33408     4 */
	/* XXX 4 bytes hole, try to pack */
	uint64_t                   rr_guest_instr_count; /* 33416     8 */
	vaddr                      panda_guest_pc;       /* 33424     8 */
	uint8_t                    reverse_flags;        /* 33432     1 */
	/* XXX 7 bytes hole, try to pack */
	uint64_t                   last_gdb_instr;       /* 33440     8 */
	uint64_t                   last_bp_hit_instr;    /* 33448     8 */
	uint64_t                   temp_rr_bp_instr;     /* 33456     8 */
	_Bool                      throttle_thread_scheduled; /* 33464     1 */
	/* XXX 3 bytes hole, try to pack */
	uint32_t                   tcg_exit_req;         /* 33468     4 */
	/* --- cacheline 523 boundary (33472 bytes) --- */
	_Bool                      hax_vcpu_dirty;       /* 33472     1 */
	/* XXX 7 bytes hole, try to pack */
	struct hax_vcpu_state *    hax_vcpu;             /* 33480     8 */
	uint16_t                   pending_tlb_flush;    /* 33488     2 */
	/* size: 33496, cachelines: 524, members: 63 */
	/* sum members: 33444, holes: 10, sum holes: 46 */
	/* padding: 6 */
	/* last cacheline: 24 bytes */
};
