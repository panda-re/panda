


typedef unsigned char __u_char;
typedef unsigned short int __u_short;
typedef unsigned int __u_int;
typedef unsigned long int __u_long;


typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;

typedef signed long int __int64_t;
typedef unsigned long int __uint64_t;






typedef __int8_t __int_least8_t;
typedef __uint8_t __uint_least8_t;
typedef __int16_t __int_least16_t;
typedef __uint16_t __uint_least16_t;
typedef __int32_t __int_least32_t;
typedef __uint32_t __uint_least32_t;
typedef __int64_t __int_least64_t;
typedef __uint64_t __uint_least64_t;



typedef long int __quad_t;
typedef unsigned long int __u_quad_t;







typedef long int __intmax_t;
typedef unsigned long int __uintmax_t;


typedef unsigned long int __dev_t;
typedef unsigned int __uid_t;
typedef unsigned int __gid_t;
typedef unsigned long int __ino_t;
typedef unsigned long int __ino64_t;
typedef unsigned int __mode_t;
typedef unsigned long int __nlink_t;
typedef long int __off_t;
typedef long int __off64_t;
typedef int __pid_t;
typedef struct { int __val[2]; } __fsid_t;
typedef long int __clock_t;
typedef unsigned long int __rlim_t;
typedef unsigned long int __rlim64_t;
typedef unsigned int __id_t;
typedef long int __time_t;
typedef unsigned int __useconds_t;
typedef long int __suseconds_t;

typedef int __daddr_t;
typedef int __key_t;


typedef int __clockid_t;


typedef void * __timer_t;


typedef long int __blksize_t;




typedef long int __blkcnt_t;
typedef long int __blkcnt64_t;


typedef unsigned long int __fsblkcnt_t;
typedef unsigned long int __fsblkcnt64_t;


typedef unsigned long int __fsfilcnt_t;
typedef unsigned long int __fsfilcnt64_t;


typedef long int __fsword_t;

typedef long int __ssize_t;


typedef long int __syscall_slong_t;

typedef unsigned long int __syscall_ulong_t;



typedef __off64_t __loff_t;
typedef char *__caddr_t;


typedef long int __intptr_t;


typedef unsigned int __socklen_t;




typedef int __sig_atomic_t;




typedef __int8_t int8_t;
typedef __int16_t int16_t;
typedef __int32_t int32_t;
typedef __int64_t int64_t;


typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;





typedef __int_least8_t int_least8_t;
typedef __int_least16_t int_least16_t;
typedef __int_least32_t int_least32_t;
typedef __int_least64_t int_least64_t;


typedef __uint_least8_t uint_least8_t;
typedef __uint_least16_t uint_least16_t;
typedef __uint_least32_t uint_least32_t;
typedef __uint_least64_t uint_least64_t;





typedef signed char int_fast8_t;

typedef long int int_fast16_t;
typedef long int int_fast32_t;
typedef long int int_fast64_t;
typedef unsigned char uint_fast8_t;

typedef unsigned long int uint_fast16_t;
typedef unsigned long int uint_fast32_t;
typedef unsigned long int uint_fast64_t;
typedef long int intptr_t;


typedef unsigned long int uintptr_t;
typedef __intmax_t intmax_t;
typedef __uintmax_t uintmax_t;

void qemu_init(int argc, char **argv);
int qemu_main_loop(void);
void qemu_cleanup(void);
extern int qemu_loglevel;
typedef uint64_t qemu_plugin_id_t;
typedef void (*cb_func_t) (void *evdata, void *udata);
extern int qemu_plugin_version;
extern const char *qemu_plugin_name;
typedef struct qemu_info_t {

    const char *target_name;

    struct {
        int min;
        int cur;
    } version;

    bool system_emulation;
    union {

        struct {

            int smp_vcpus;

            int max_vcpus;
        } system;
    };
} qemu_info_t;
 int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv);







typedef void (*qemu_plugin_simple_cb_t)(qemu_plugin_id_t id);







typedef void (*qemu_plugin_udata_cb_t)(qemu_plugin_id_t id, void *userdata);






typedef void (*qemu_plugin_vcpu_simple_cb_t)(qemu_plugin_id_t id,
                                             unsigned int vcpu_index);







typedef void (*qemu_plugin_vcpu_udata_cb_t)(unsigned int vcpu_index,
                                            void *userdata);
void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb);
void qemu_plugin_reset(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb);
void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb);
void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb);
void qemu_plugin_register_vcpu_idle_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb);
void qemu_plugin_register_vcpu_resume_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_simple_cb_t cb);
void qemu_plugin_register_vcpu_loadvm_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_simple_cb_t cb);



struct qemu_plugin_tb;

struct qemu_plugin_insn;
enum qemu_plugin_cb_flags {
    QEMU_PLUGIN_CB_NO_REGS,
    QEMU_PLUGIN_CB_R_REGS,
    QEMU_PLUGIN_CB_RW_REGS,
};

enum qemu_plugin_mem_rw {
    QEMU_PLUGIN_MEM_R = 1,
    QEMU_PLUGIN_MEM_W,
    QEMU_PLUGIN_MEM_RW,
};
void qemu_plugin_register_vcpu_tlb_flush_cb(qemu_plugin_id_t id,
                                            qemu_plugin_vcpu_udata_cb_t cb,
                                            void *userdata);







typedef void (*qemu_plugin_vcpu_tb_trans_cb_t)(qemu_plugin_id_t id,
                                               struct qemu_plugin_tb *tb);
void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t id,
                                           qemu_plugin_vcpu_tb_trans_cb_t cb);
void qemu_plugin_register_vcpu_tb_exec_cb(struct qemu_plugin_tb *tb,
                                          qemu_plugin_vcpu_udata_cb_t cb,
                                          enum qemu_plugin_cb_flags flags,
                                          void *userdata);
enum qemu_plugin_op {
    QEMU_PLUGIN_INLINE_ADD_U64,
};
void qemu_plugin_register_vcpu_tb_exec_inline(struct qemu_plugin_tb *tb,
                                              enum qemu_plugin_op op,
                                              void *ptr, uint64_t imm);
void qemu_plugin_register_vcpu_insn_exec_cb(struct qemu_plugin_insn *insn,
                                            qemu_plugin_vcpu_udata_cb_t cb,
                                            enum qemu_plugin_cb_flags flags,
                                            void *userdata);
void qemu_plugin_register_vcpu_insn_exec_inline(struct qemu_plugin_insn *insn,
                                                enum qemu_plugin_op op,
                                                void *ptr, uint64_t imm);







size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb);







uint64_t qemu_plugin_tb_vaddr(const struct qemu_plugin_tb *tb);





uint64_t qemu_plugin_get_pc(void);







int32_t qemu_plugin_get_reg32(unsigned int reg_idx, bool* error);







int64_t qemu_plugin_get_reg64(unsigned int reg_idx, bool* error);
int qemu_plugin_load_plugin(char *path, int argc, char **argv);
void *qemu_plugin_import_function(const char *plugin, const char *function);
bool qemu_plugin_create_callback(qemu_plugin_id_t id, const char *name);
bool qemu_plugin_run_callback(qemu_plugin_id_t id, const char *name,
                              void *evdata, void *udata);
bool qemu_plugin_reg_callback(const char *target_plugin, const char *cb_name,
                              cb_func_t function_pointer);
bool qemu_plugin_unreg_callback(const char *target_plugin, const char *cb_name,
                                cb_func_t function_pointer);
int qemu_plugin_read_guest_virt_mem(uint64_t gva, void *buf, size_t length);







uint64_t qemu_plugin_virt_to_phys(uint64_t addr);







void *qemu_plugin_virt_to_host(uint64_t addr, int len);
struct qemu_plugin_insn *
qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t idx);
const void *qemu_plugin_insn_data(const struct qemu_plugin_insn *insn);







size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *insn);







uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn);







void *qemu_plugin_insn_haddr(const struct qemu_plugin_insn *insn);







typedef uint32_t qemu_plugin_meminfo_t;

struct qemu_plugin_hwaddr;







unsigned int qemu_plugin_mem_size_shift(qemu_plugin_meminfo_t info);






bool qemu_plugin_mem_is_sign_extended(qemu_plugin_meminfo_t info);






bool qemu_plugin_mem_is_big_endian(qemu_plugin_meminfo_t info);






bool qemu_plugin_mem_is_store(qemu_plugin_meminfo_t info);
struct qemu_plugin_hwaddr *qemu_plugin_get_hwaddr(qemu_plugin_meminfo_t info,
                                                  uint64_t vaddr);
bool qemu_plugin_hwaddr_is_io(const struct qemu_plugin_hwaddr *haddr);
uint64_t qemu_plugin_hwaddr_phys_addr(const struct qemu_plugin_hwaddr *haddr);





const char *qemu_plugin_hwaddr_device_name(const struct qemu_plugin_hwaddr *h);

typedef void
(*qemu_plugin_vcpu_mem_cb_t)(unsigned int vcpu_index,
                             qemu_plugin_meminfo_t info, uint64_t vaddr,
                             void *userdata);

void qemu_plugin_register_vcpu_mem_cb(struct qemu_plugin_insn *insn,
                                      qemu_plugin_vcpu_mem_cb_t cb,
                                      enum qemu_plugin_cb_flags flags,
                                      enum qemu_plugin_mem_rw rw,
                                      void *userdata);

void qemu_plugin_register_vcpu_mem_inline(struct qemu_plugin_insn *insn,
                                          enum qemu_plugin_mem_rw rw,
                                          enum qemu_plugin_op op, void *ptr,
                                          uint64_t imm);



typedef void
(*qemu_plugin_vcpu_syscall_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_index,
                                 int64_t num, uint64_t a1, uint64_t a2,
                                 uint64_t a3, uint64_t a4, uint64_t a5,
                                 uint64_t a6, uint64_t a7, uint64_t a8);

void qemu_plugin_register_vcpu_syscall_cb(qemu_plugin_id_t id,
                                          qemu_plugin_vcpu_syscall_cb_t cb);

typedef void
(*qemu_plugin_vcpu_syscall_ret_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_idx,
                                     int64_t num, int64_t ret);

void
qemu_plugin_register_vcpu_syscall_ret_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_syscall_ret_cb_t cb);
char *qemu_plugin_insn_disas(const struct qemu_plugin_insn *insn);
const char *qemu_plugin_insn_symbol(const struct qemu_plugin_insn *insn);
void qemu_plugin_vcpu_for_each(qemu_plugin_id_t id,
                               qemu_plugin_vcpu_simple_cb_t cb);

void qemu_plugin_register_flush_cb(qemu_plugin_id_t id,
                                   qemu_plugin_simple_cb_t cb);
void qemu_plugin_register_atexit_cb(qemu_plugin_id_t id,
                                    qemu_plugin_udata_cb_t cb, void *userdata);


int qemu_plugin_n_vcpus(void);


int qemu_plugin_n_max_vcpus(void);





void qemu_plugin_outs(const char *string);
bool qemu_plugin_bool_parse(const char *name, const char *val, bool *ret);
const char *qemu_plugin_path_to_binary(void);







uint64_t qemu_plugin_start_code(void);







uint64_t qemu_plugin_end_code(void);







uint64_t qemu_plugin_entry_code(void);




       
typedef void CPUState;
typedef uint64_t target_ulong;



typedef target_ulong target_ptr_t;
typedef int32_t target_pid_t;
typedef struct osi_proc_handle_struct {
    target_ptr_t taskd;
    target_ptr_t asid;
} OsiProcHandle;






typedef struct osi_thread_struct {
    target_pid_t pid;
    target_pid_t tid;
} OsiThread;






typedef struct osi_page_struct {
    target_ptr_t start;
    target_ulong len;
} OsiPage;





typedef struct osi_module_struct {
    target_ptr_t modd;
    target_ptr_t base;
    target_ptr_t size;
    char *file;
    char *name;
} OsiModule;




typedef struct osi_proc_struct {
    target_ptr_t taskd;
    target_ptr_t asid;
    target_pid_t pid;
    target_pid_t ppid;
    char *name;
    OsiPage *pages;
    uint64_t create_time;
} OsiProc;







OsiProc* get_current_process(void); typedef OsiProc*(*get_current_process_t)(void); get_current_process_t get_current_process_qpp; void _qpp_setup_get_current_process (void);;
OsiProc* get_process(const OsiProcHandle*); typedef OsiProc*(*get_process_t)(const OsiProcHandle*); get_process_t get_process_qpp; void _qpp_setup_get_process (void);;
OsiProcHandle* get_current_process_handle(void); typedef OsiProcHandle*(*get_current_process_handle_t)(void); get_current_process_handle_t get_current_process_handle_qpp; void _qpp_setup_get_current_process_handle (void);;
void notify_task_change(unsigned int, void*); typedef void(*notify_task_change_t)(unsigned int, void*); notify_task_change_t notify_task_change_qpp; void _qpp_setup_notify_task_change (void);;

struct get_process_data {
  OsiProc **p;
  const OsiProcHandle *h;
};
extern int (*external_plugin_install)(qemu_plugin_id_t id, const qemu_info_t *info,int argc, char **argv);
