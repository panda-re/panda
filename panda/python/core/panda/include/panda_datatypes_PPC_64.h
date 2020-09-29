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
typedef uint8_t ZMMReg[40];
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
	/* --- cacheline 3 boundary (192 bytes) was 32 bytes ago --- */
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
	enum QemuOptType           type;                 /*     8     4 */
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
	struct rcu_head            rcu;                  /*     0    16 */
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
struct CPUIOTLBEntry;
typedef struct CPUIOTLBEntry CPUIOTLBEntry;
struct CPUIOTLBEntry {
	hwaddr                     addr;                 /*     0     8 */
	MemTxAttrs                 attrs;                /*     8     4 */
	/* size: 16, cachelines: 1, members: 2 */
	/* padding: 4 */
	/* last cacheline: 16 bytes */
};
struct ppc_slb_t;
typedef struct ppc_slb_t ppc_slb_t;
struct ppc_slb_t {
	uint64_t                   esid;                 /*     0     8 */
	uint64_t                   vsid;                 /*     8     8 */
	const struct ppc_one_seg_page_size  * sps;       /*    16     8 */
	/* size: 24, cachelines: 1, members: 3 */
	/* last cacheline: 24 bytes */
};
struct ppc_spr_t;
typedef struct ppc_spr_t ppc_spr_t;
struct DisasContext;
typedef struct DisasContext DisasContext;
struct ppc_spr_t {
	void                       (*uea_read)(DisasContext *, int, int); /*     0     8 */
	void                       (*uea_write)(DisasContext *, int, int); /*     8     8 */
	void                       (*oea_read)(DisasContext *, int, int); /*    16     8 */
	void                       (*oea_write)(DisasContext *, int, int); /*    24     8 */
	void                       (*hea_read)(DisasContext *, int, int); /*    32     8 */
	void                       (*hea_write)(DisasContext *, int, int); /*    40     8 */
	const char  *              name;                 /*    48     8 */
	target_ulong               default_value;        /*    56     8 */
	/* size: 64, cachelines: 1, members: 8 */
};
struct QEMUTimer;
typedef struct QEMUTimer QEMUTimer;
struct QEMUTimerList;
typedef struct QEMUTimerList QEMUTimerList;
struct QEMUTimer {
	int64_t                    expire_time;          /*     0     8 */
	QEMUTimerList *            timer_list;           /*     8     8 */
	QEMUTimerCB *              cb;                   /*    16     8 */
	void *                     opaque;               /*    24     8 */
	QEMUTimer *                next;                 /*    32     8 */
	int                        scale;                /*    40     4 */
	/* size: 48, cachelines: 1, members: 6 */
	/* padding: 4 */
	/* last cacheline: 48 bytes */
};
struct NotifierList;
typedef struct NotifierList NotifierList;
struct NotifierList {
	struct {
		struct Notifier *  lh_first;             /*     0     8 */
	} notifiers;                                     /*     0     8 */
	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};
struct QemuEvent;
typedef struct QemuEvent QemuEvent;
struct QemuEvent {
	unsigned int               value;                /*     0     4 */
	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};
struct ppc_dcrn_t;
typedef struct ppc_dcrn_t ppc_dcrn_t;
struct ppc_dcrn_t {
	dcr_read_cb                dcr_read;             /*     0     8 */
	dcr_write_cb               dcr_write;            /*     8     8 */
	void *                     opaque;               /*    16     8 */
	/* size: 24, cachelines: 1, members: 3 */
	/* last cacheline: 24 bytes */
};
struct opc_handler_t;
typedef struct opc_handler_t opc_handler_t;
struct opc_handler_t {
	uint32_t                   inval1;               /*     0     4 */
	uint32_t                   inval2;               /*     4     4 */
	uint64_t                   type;                 /*     8     8 */
	uint64_t                   type2;                /*    16     8 */
	void                       (*handler)(DisasContext *); /*    24     8 */
	/* size: 32, cachelines: 1, members: 5 */
	/* last cacheline: 32 bytes */
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
struct ppc_segment_page_sizes;
typedef struct ppc_segment_page_sizes ppc_segment_page_sizes;
struct ppc_segment_page_sizes {
	struct ppc_one_seg_page_size sps[8];             /*     0   576 */
	/* size: 576, cachelines: 9, members: 1 */
};
struct ppc_one_seg_page_size;
typedef struct ppc_one_seg_page_size ppc_one_seg_page_size;
struct ppc_one_seg_page_size {
	uint32_t                   page_shift;           /*     0     4 */
	uint32_t                   slb_enc;              /*     4     4 */
	struct ppc_one_page_size   enc[8];               /*     8    64 */
	/* size: 72, cachelines: 2, members: 3 */
	/* last cacheline: 8 bytes */
};
struct ppc_one_page_size;
typedef struct ppc_one_page_size ppc_one_page_size;
struct ppc_one_page_size {
	uint32_t                   page_shift;           /*     0     4 */
	uint32_t                   pte_enc;              /*     4     4 */
	/* size: 8, cachelines: 1, members: 2 */
	/* last cacheline: 8 bytes */
};
struct AddressSpace;
typedef struct AddressSpace AddressSpace;
struct MemoryRegion;
typedef struct MemoryRegion MemoryRegion;
struct MemoryListener;
typedef struct MemoryListener MemoryListener;
struct AddressSpace {
	struct rcu_head            rcu;                  /*     0    16 */
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
	enum device_endian         endianness;           /*    32     4 */
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
	struct subregions          subregions;           /*   168    16 */
	struct {
		struct MemoryRegion * tqe_next;          /*   184     8 */
		/* --- cacheline 3 boundary (192 bytes) --- */
		struct MemoryRegion * * tqe_prev;        /*   192     8 */
	} subregions_link;                               /*   184    16 */
	struct coalesced_ranges    coalesced;            /*   200    16 */
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
struct DisasContext;
typedef struct DisasContext DisasContext;
struct DisasContext {
	struct TranslationBlock *  tb;                   /*     0     8 */
	target_ulong               nip;                  /*     8     8 */
	uint32_t                   opcode;               /*    16     4 */
	uint32_t                   exception;            /*    20     4 */
	_Bool                      pr;                   /*    24     1 */
	_Bool                      hv;                   /*    25     1 */
	_Bool                      dr;                   /*    26     1 */
	_Bool                      le_mode;              /*    27     1 */
	_Bool                      lazy_tlb_flush;       /*    28     1 */
	_Bool                      need_access_type;     /*    29     1 */
	/* XXX 2 bytes hole, try to pack */
	int                        mem_idx;              /*    32     4 */
	int                        access_type;          /*    36     4 */
	TCGMemOp                   default_tcg_memop_mask; /*    40     4 */
	_Bool                      sf_mode;              /*    44     1 */
	_Bool                      has_cfar;             /*    45     1 */
	_Bool                      fpu_enabled;          /*    46     1 */
	_Bool                      altivec_enabled;      /*    47     1 */
	_Bool                      vsx_enabled;          /*    48     1 */
	_Bool                      spe_enabled;          /*    49     1 */
	_Bool                      tm_enabled;           /*    50     1 */
	/* XXX 5 bytes hole, try to pack */
	ppc_spr_t *                spr_cb;               /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	int                        singlestep_enabled;   /*    64     4 */
	/* XXX 4 bytes hole, try to pack */
	uint64_t                   insns_flags;          /*    72     8 */
	uint64_t                   insns_flags2;         /*    80     8 */
	/* size: 88, cachelines: 2, members: 24 */
	/* sum members: 77, holes: 3, sum holes: 11 */
	/* last cacheline: 24 bytes */
};
struct ppc_tb_t;
typedef struct ppc_tb_t ppc_tb_t;
struct ppc_tb_t {
	int64_t                    tb_offset;            /*     0     8 */
	int64_t                    atb_offset;           /*     8     8 */
	uint32_t                   tb_freq;              /*    16     4 */
	/* XXX 4 bytes hole, try to pack */
	uint64_t                   decr_next;            /*    24     8 */
	uint32_t                   decr_freq;            /*    32     4 */
	/* XXX 4 bytes hole, try to pack */
	QEMUTimer *                decr_timer;           /*    40     8 */
	uint64_t                   hdecr_next;           /*    48     8 */
	QEMUTimer *                hdecr_timer;          /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	uint64_t                   purr_load;            /*    64     8 */
	uint64_t                   purr_start;           /*    72     8 */
	void *                     opaque;               /*    80     8 */
	uint32_t                   flags;                /*    88     4 */
	/* size: 96, cachelines: 2, members: 12 */
	/* sum members: 84, holes: 2, sum holes: 8 */
	/* padding: 4 */
	/* last cacheline: 32 bytes */
};
struct QEMUClock;
typedef struct QEMUClock QEMUClock;
struct QEMUClock {
	struct {
		struct QEMUTimerList * lh_first;         /*     0     8 */
	} timerlists;                                    /*     0     8 */
	NotifierList               reset_notifiers;      /*     8     8 */
	int64_t                    last;                 /*    16     8 */
	QEMUClockType              type;                 /*    24     4 */
	_Bool                      enabled;              /*    28     1 */
	/* size: 32, cachelines: 1, members: 5 */
	/* padding: 3 */
	/* last cacheline: 32 bytes */
};
struct ppc_dcr_t;
typedef struct ppc_dcr_t ppc_dcr_t;
struct ppc_dcr_t {
	ppc_dcrn_t                 dcrn[1024];           /*     0 24576 */
	/* --- cacheline 384 boundary (24576 bytes) --- */
	int                        (*read_error)(int);   /* 24576     8 */
	int                        (*write_error)(int);  /* 24584     8 */
	/* size: 24592, cachelines: 385, members: 3 */
	/* last cacheline: 16 bytes */
};
struct QemuOpts;
typedef struct QemuOpts QemuOpts;
struct QemuOpts {
	char *                     id;                   /*     0     8 */
	QemuOptsList *             list;                 /*     8     8 */
	Location                   loc;                  /*    16    24 */
	struct QemuOptHead         head;                 /*    40    16 */
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
	struct ChildrenHead        children;             /*    72    16 */
	struct {
		struct BusState *  le_next;              /*    88     8 */
		struct BusState * * le_prev;             /*    96     8 */
	} sibling;                                       /*    88    16 */
	/* size: 104, cachelines: 2, members: 8 */
	/* sum members: 101, holes: 1, sum holes: 3 */
	/* last cacheline: 40 bytes */
};
struct QEMUTimerList;
typedef struct QEMUTimerList QEMUTimerList;
struct QEMUTimerList {
	QEMUClock *                clock;                /*     0     8 */
	QemuMutex                  active_timers_lock;   /*     8    40 */
	QEMUTimer *                active_timers;        /*    48     8 */
	struct {
		struct QEMUTimerList * le_next;          /*    56     8 */
		/* --- cacheline 1 boundary (64 bytes) --- */
		struct QEMUTimerList * * le_prev;        /*    64     8 */
	} list;                                          /*    56    16 */
	QEMUTimerListNotifyCB *    notify_cb;            /*    72     8 */
	void *                     notify_opaque;        /*    80     8 */
	QemuEvent                  timers_done_ev;       /*    88     4 */
	/* size: 96, cachelines: 2, members: 7 */
	/* padding: 4 */
	/* last cacheline: 32 bytes */
};
struct CPUPPCState;
typedef struct CPUPPCState CPUPPCState;
struct CPUPPCState {
	target_ulong               gpr[32];              /*     0   256 */
	/* --- cacheline 4 boundary (256 bytes) --- */
	target_ulong               gprh[32];             /*   256   256 */
	/* --- cacheline 8 boundary (512 bytes) --- */
	target_ulong               lr;                   /*   512     8 */
	target_ulong               ctr;                  /*   520     8 */
	uint32_t                   crf[8];               /*   528    32 */
	target_ulong               cfar;                 /*   560     8 */
	target_ulong               xer;                  /*   568     8 */
	/* --- cacheline 9 boundary (576 bytes) --- */
	target_ulong               so;                   /*   576     8 */
	target_ulong               ov;                   /*   584     8 */
	target_ulong               ca;                   /*   592     8 */
	target_ulong               ov32;                 /*   600     8 */
	target_ulong               ca32;                 /*   608     8 */
	target_ulong               reserve_addr;         /*   616     8 */
	target_ulong               reserve_val;          /*   624     8 */
	target_ulong               reserve_val2;         /*   632     8 */
	/* --- cacheline 10 boundary (640 bytes) --- */
	target_ulong               reserve_ea;           /*   640     8 */
	target_ulong               reserve_info;         /*   648     8 */
	target_ulong               msr;                  /*   656     8 */
	target_ulong               tgpr[4];              /*   664    32 */
	float_status               fp_status;            /*   696     8 */
	/* --- cacheline 11 boundary (704 bytes) --- */
	float64                    fpr[32];              /*   704   256 */
	/* --- cacheline 15 boundary (960 bytes) --- */
	target_ulong               fpscr;                /*   960     8 */
	target_ulong               nip;                  /*   968     8 */
	int                        access_type;          /*   976     4 */
	/* XXX 4 bytes hole, try to pack */
	CPUTLBEntry                tlb_table[8][256];    /*   984 65536 */
	/* --- cacheline 1039 boundary (66496 bytes) was 24 bytes ago --- */
	CPUTLBEntry                tlb_v_table[8][8];    /* 66520  2048 */
	/* --- cacheline 1071 boundary (68544 bytes) was 24 bytes ago --- */
	CPUIOTLBEntry              iotlb[8][256];        /* 68568 32768 */
	/* --- cacheline 1583 boundary (101312 bytes) was 24 bytes ago --- */
	CPUIOTLBEntry              iotlb_v[8][8];        /* 101336  1024 */
	/* --- cacheline 1599 boundary (102336 bytes) was 24 bytes ago --- */
	target_ulong               tlb_flush_addr;       /* 102360     8 */
	target_ulong               tlb_flush_mask;       /* 102368     8 */
	target_ulong               vtlb_index;           /* 102376     8 */
	ppc_slb_t                  slb[64];              /* 102384  1536 */
	/* --- cacheline 1623 boundary (103872 bytes) was 48 bytes ago --- */
	int32_t                    slb_nr;               /* 103920     4 */
	/* XXX 4 bytes hole, try to pack */
	target_ulong               sr[32];               /* 103928   256 */
	/* --- cacheline 1627 boundary (104128 bytes) was 56 bytes ago --- */
	uint32_t                   nb_BATs;              /* 104184     4 */
	/* XXX 4 bytes hole, try to pack */
	/* --- cacheline 1628 boundary (104192 bytes) --- */
	target_ulong               DBAT[2][8];           /* 104192   128 */
	/* --- cacheline 1630 boundary (104320 bytes) --- */
	target_ulong               IBAT[2][8];           /* 104320   128 */
	/* --- cacheline 1632 boundary (104448 bytes) --- */
	int32_t                    nb_tlb;               /* 104448     4 */
	int                        tlb_per_way;          /* 104452     4 */
	int                        nb_ways;              /* 104456     4 */
	int                        last_way;             /* 104460     4 */
	int                        id_tlbs;              /* 104464     4 */
	int                        nb_pids;              /* 104468     4 */
	int                        tlb_type;             /* 104472     4 */
	/* XXX 4 bytes hole, try to pack */
	ppc_tlb_t                  tlb;                  /* 104480     8 */
	target_ulong               pb[4];                /* 104488    32 */
	/* --- cacheline 1633 boundary (104512 bytes) was 8 bytes ago --- */
	_Bool                      tlb_dirty;            /* 104520     1 */
	_Bool                      kvm_sw_tlb;           /* 104521     1 */
	/* XXX 2 bytes hole, try to pack */
	uint32_t                   tlb_need_flush;       /* 104524     4 */
	target_ulong               spr[1024];            /* 104528  8192 */
	/* --- cacheline 1761 boundary (112704 bytes) was 16 bytes ago --- */
	ppc_spr_t                  spr_cb[1024];         /* 112720 65536 */
	/* --- cacheline 2785 boundary (178240 bytes) was 16 bytes ago --- */
	ppc_avr_t                  avr[32];              /* 178256   512 */
	/* --- cacheline 2793 boundary (178752 bytes) was 16 bytes ago --- */
	uint32_t                   vscr;                 /* 178768     4 */
	/* XXX 4 bytes hole, try to pack */
	uint64_t                   vsr[32];              /* 178776   256 */
	/* --- cacheline 2797 boundary (179008 bytes) was 24 bytes ago --- */
	uint64_t                   spe_acc;              /* 179032     8 */
	uint32_t                   spe_fscr;             /* 179040     4 */
	float_status               vec_status;           /* 179044     8 */
	/* XXX 4 bytes hole, try to pack */
	ppc_tb_t *                 tb_env;               /* 179056     8 */
	ppc_dcr_t *                dcr_env;              /* 179064     8 */
	/* --- cacheline 2798 boundary (179072 bytes) --- */
	int                        dcache_line_size;     /* 179072     4 */
	int                        icache_line_size;     /* 179076     4 */
	target_ulong               msr_mask;             /* 179080     8 */
	powerpc_mmu_t              mmu_model;            /* 179088     4 */
	powerpc_excp_t             excp_model;           /* 179092     4 */
	powerpc_input_t            bus_model;            /* 179096     4 */
	int                        bfd_mach;             /* 179100     4 */
	uint32_t                   flags;                /* 179104     4 */
	/* XXX 4 bytes hole, try to pack */
	uint64_t                   insns_flags;          /* 179112     8 */
	uint64_t                   insns_flags2;         /* 179120     8 */
	struct ppc_segment_page_sizes sps;               /* 179128   576 */
	/* --- cacheline 2807 boundary (179648 bytes) was 56 bytes ago --- */
	ppc_slb_t                  vrma_slb;             /* 179704    24 */
	/* --- cacheline 2808 boundary (179712 bytes) was 16 bytes ago --- */
	target_ulong               rmls;                 /* 179728     8 */
	_Bool                      ci_large_pages;       /* 179736     1 */
	/* XXX 7 bytes hole, try to pack */
	uint64_t                   vpa_addr;             /* 179744     8 */
	uint64_t                   slb_shadow_addr;      /* 179752     8 */
	uint64_t                   slb_shadow_size;      /* 179760     8 */
	uint64_t                   dtl_addr;             /* 179768     8 */
	/* --- cacheline 2809 boundary (179776 bytes) --- */
	uint64_t                   dtl_size;             /* 179776     8 */
	int                        error_code;           /* 179784     4 */
	uint32_t                   pending_interrupts;   /* 179788     4 */
	uint32_t                   irq_input_state;      /* 179792     4 */
	/* XXX 4 bytes hole, try to pack */
	void * *                   irq_inputs;           /* 179800     8 */
	target_ulong               excp_vectors[99];     /* 179808   792 */
	/* --- cacheline 2821 boundary (180544 bytes) was 56 bytes ago --- */
	target_ulong               excp_prefix;          /* 180600     8 */
	/* --- cacheline 2822 boundary (180608 bytes) --- */
	target_ulong               ivor_mask;            /* 180608     8 */
	target_ulong               ivpr_mask;            /* 180616     8 */
	target_ulong               hreset_vector;        /* 180624     8 */
	hwaddr                     mpic_iack;            /* 180632     8 */
	_Bool                      mpic_proxy;           /* 180640     1 */
	_Bool                      has_hv_mode;          /* 180641     1 */
	_Bool                      in_pm_state;          /* 180642     1 */
	/* XXX 5 bytes hole, try to pack */
	opc_handler_t *            opcodes[64];          /* 180648   512 */
	/* --- cacheline 2830 boundary (181120 bytes) was 40 bytes ago --- */
	target_ulong               hflags;               /* 181160     8 */
	target_ulong               hflags_nmsr;          /* 181168     8 */
	int                        immu_idx;             /* 181176     4 */
	int                        dmmu_idx;             /* 181180     4 */
	/* --- cacheline 2831 boundary (181184 bytes) --- */
	int                        (*check_pow)(CPUPPCState *); /* 181184     8 */
	void *                     load_info;            /* 181192     8 */
	uint8_t                    fit_period[4];        /* 181200     4 */
	uint8_t                    wdt_period[4];        /* 181204     4 */
	target_ulong               tm_gpr[32];           /* 181208   256 */
	/* XXX 8 bytes hole, try to pack */
	/* --- cacheline 2835 boundary (181440 bytes) was 32 bytes ago --- */
	ppc_avr_t                  tm_vsr[64];           /* 181472  1024 */
	/* --- cacheline 2851 boundary (182464 bytes) was 32 bytes ago --- */
	uint64_t                   tm_cr;                /* 182496     8 */
	uint64_t                   tm_lr;                /* 182504     8 */
	uint64_t                   tm_ctr;               /* 182512     8 */
	uint64_t                   tm_fpscr;             /* 182520     8 */
	/* --- cacheline 2852 boundary (182528 bytes) --- */
	uint64_t                   tm_amr;               /* 182528     8 */
	uint64_t                   tm_ppr;               /* 182536     8 */
	uint64_t                   tm_vrsave;            /* 182544     8 */
	uint32_t                   tm_vscr;              /* 182552     4 */
	/* XXX 4 bytes hole, try to pack */
	uint64_t                   tm_dscr;              /* 182560     8 */
	uint64_t                   tm_tar;               /* 182568     8 */
	/* size: 182576, cachelines: 2853, members: 112 */
	/* sum members: 182518, holes: 13, sum holes: 58 */
	/* last cacheline: 48 bytes */
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
	CPUPPCState *                     env_ptr;              /*   480     8 */
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
	struct breakpoints_head    breakpoints;          /* 33288    16 */
	struct watchpoints_head    watchpoints;          /* 33304    16 */
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
