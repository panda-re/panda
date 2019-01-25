
typedef long int ptrdiff_t;
typedef long unsigned int size_t;
typedef int wchar_t;
typedef struct {
  long long __max_align_ll __attribute__((__aligned__(__alignof__(long long))));
  long double __max_align_ld __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;












typedef signed char gint8;
typedef unsigned char guint8;
typedef signed short gint16;
typedef unsigned short guint16;



typedef signed int gint32;
typedef unsigned int guint32;





typedef signed long gint64;
typedef unsigned long guint64;
typedef signed long gssize;
typedef unsigned long gsize;
typedef gint64 goffset;
typedef signed long gintptr;
typedef unsigned long guintptr;
typedef int GPid;
















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







typedef long int __quad_t;
typedef unsigned long int __u_quad_t;


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
typedef __quad_t *__qaddr_t;
typedef char *__caddr_t;


typedef long int __intptr_t;


typedef unsigned int __socklen_t;



typedef __clock_t clock_t;





typedef __time_t time_t;



typedef __clockid_t clockid_t;
typedef __timer_t timer_t;
struct timespec
  {
    __time_t tv_sec;
    __syscall_slong_t tv_nsec;
  };








struct tm
{
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;


  long int tm_gmtoff;
  const char *tm_zone;




};








struct itimerspec
  {
    struct timespec it_interval;
    struct timespec it_value;
  };


struct sigevent;





typedef __pid_t pid_t;



extern clock_t clock (void) __attribute__ ((__nothrow__ , __leaf__));


extern time_t time (time_t *__timer) __attribute__ ((__nothrow__ , __leaf__));


extern double difftime (time_t __time1, time_t __time0)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));


extern time_t mktime (struct tm *__tp) __attribute__ ((__nothrow__ , __leaf__));





extern size_t strftime (char *__restrict __s, size_t __maxsize,
   const char *__restrict __format,
   const struct tm *__restrict __tp) __attribute__ ((__nothrow__ , __leaf__));

typedef struct __locale_struct
{

  struct __locale_data *__locales[13];


  const unsigned short int *__ctype_b;
  const int *__ctype_tolower;
  const int *__ctype_toupper;


  const char *__names[13];
} *__locale_t;


typedef __locale_t locale_t;

extern size_t strftime_l (char *__restrict __s, size_t __maxsize,
     const char *__restrict __format,
     const struct tm *__restrict __tp,
     __locale_t __loc) __attribute__ ((__nothrow__ , __leaf__));



extern struct tm *gmtime (const time_t *__timer) __attribute__ ((__nothrow__ , __leaf__));



extern struct tm *localtime (const time_t *__timer) __attribute__ ((__nothrow__ , __leaf__));





extern struct tm *gmtime_r (const time_t *__restrict __timer,
       struct tm *__restrict __tp) __attribute__ ((__nothrow__ , __leaf__));



extern struct tm *localtime_r (const time_t *__restrict __timer,
          struct tm *__restrict __tp) __attribute__ ((__nothrow__ , __leaf__));





extern char *asctime (const struct tm *__tp) __attribute__ ((__nothrow__ , __leaf__));


extern char *ctime (const time_t *__timer) __attribute__ ((__nothrow__ , __leaf__));







extern char *asctime_r (const struct tm *__restrict __tp,
   char *__restrict __buf) __attribute__ ((__nothrow__ , __leaf__));


extern char *ctime_r (const time_t *__restrict __timer,
        char *__restrict __buf) __attribute__ ((__nothrow__ , __leaf__));




extern char *__tzname[2];
extern int __daylight;
extern long int __timezone;




extern char *tzname[2];



extern void tzset (void) __attribute__ ((__nothrow__ , __leaf__));



extern int daylight;
extern long int timezone;





extern int stime (const time_t *__when) __attribute__ ((__nothrow__ , __leaf__));
extern time_t timegm (struct tm *__tp) __attribute__ ((__nothrow__ , __leaf__));


extern time_t timelocal (struct tm *__tp) __attribute__ ((__nothrow__ , __leaf__));


extern int dysize (int __year) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern int nanosleep (const struct timespec *__requested_time,
        struct timespec *__remaining);



extern int clock_getres (clockid_t __clock_id, struct timespec *__res) __attribute__ ((__nothrow__ , __leaf__));


extern int clock_gettime (clockid_t __clock_id, struct timespec *__tp) __attribute__ ((__nothrow__ , __leaf__));


extern int clock_settime (clockid_t __clock_id, const struct timespec *__tp)
     __attribute__ ((__nothrow__ , __leaf__));






extern int clock_nanosleep (clockid_t __clock_id, int __flags,
       const struct timespec *__req,
       struct timespec *__rem);


extern int clock_getcpuclockid (pid_t __pid, clockid_t *__clock_id) __attribute__ ((__nothrow__ , __leaf__));




extern int timer_create (clockid_t __clock_id,
    struct sigevent *__restrict __evp,
    timer_t *__restrict __timerid) __attribute__ ((__nothrow__ , __leaf__));


extern int timer_delete (timer_t __timerid) __attribute__ ((__nothrow__ , __leaf__));


extern int timer_settime (timer_t __timerid, int __flags,
     const struct itimerspec *__restrict __value,
     struct itimerspec *__restrict __ovalue) __attribute__ ((__nothrow__ , __leaf__));


extern int timer_gettime (timer_t __timerid, struct itimerspec *__value)
     __attribute__ ((__nothrow__ , __leaf__));


extern int timer_getoverrun (timer_t __timerid) __attribute__ ((__nothrow__ , __leaf__));





extern int timespec_get (struct timespec *__ts, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));




typedef char gchar;
typedef short gshort;
typedef long glong;
typedef int gint;
typedef gint gboolean;

typedef unsigned char guchar;
typedef unsigned short gushort;
typedef unsigned long gulong;
typedef unsigned int guint;

typedef float gfloat;
typedef double gdouble;
typedef void* gpointer;
typedef const void *gconstpointer;

typedef gint (*GCompareFunc) (gconstpointer a,
                                                 gconstpointer b);
typedef gint (*GCompareDataFunc) (gconstpointer a,
                                                 gconstpointer b,
       gpointer user_data);
typedef gboolean (*GEqualFunc) (gconstpointer a,
                                                 gconstpointer b);
typedef void (*GDestroyNotify) (gpointer data);
typedef void (*GFunc) (gpointer data,
                                                 gpointer user_data);
typedef guint (*GHashFunc) (gconstpointer key);
typedef void (*GHFunc) (gpointer key,
                                                 gpointer value,
                                                 gpointer user_data);
typedef void (*GFreeFunc) (gpointer data);
typedef const gchar * (*GTranslateFunc) (const gchar *str,
       gpointer data);
static inline gboolean _GLIB_CHECKED_ADD_U32 (guint32 *dest, guint32 a, guint32 b) {
  return !__builtin_uadd_overflow(a, b, dest); }
static inline gboolean _GLIB_CHECKED_MUL_U32 (guint32 *dest, guint32 a, guint32 b) {
  return !__builtin_umul_overflow(a, b, dest); }
static inline gboolean _GLIB_CHECKED_ADD_U64 (guint64 *dest, guint64 a, guint64 b) {
  typedef char _GStaticAssertCompileTimeAssertion_0[(sizeof (unsigned long long) == sizeof (guint64)) ? 1 : -1] __attribute__((__unused__));
  return !__builtin_uaddll_overflow(a, b, (unsigned long long *) dest); }
static inline gboolean _GLIB_CHECKED_MUL_U64 (guint64 *dest, guint64 a, guint64 b) {
  return !__builtin_umulll_overflow(a, b, (unsigned long long *) dest); }
typedef union _GDoubleIEEE754 GDoubleIEEE754;
typedef union _GFloatIEEE754 GFloatIEEE754;





union _GFloatIEEE754
{
  gfloat v_float;
  struct {
    guint mantissa : 23;
    guint biased_exponent : 8;
    guint sign : 1;
  } mpn;
};
union _GDoubleIEEE754
{
  gdouble v_double;
  struct {
    guint mantissa_low : 32;
    guint mantissa_high : 20;
    guint biased_exponent : 11;
    guint sign : 1;
  } mpn;
};
typedef struct _GTimeVal GTimeVal;

struct _GTimeVal
{
  glong tv_sec;
  glong tv_usec;
};



typedef __builtin_va_list __gnuc_va_list;
typedef __gnuc_va_list va_list;



extern
const gchar * g_get_user_name (void);
extern
const gchar * g_get_real_name (void);
extern
const gchar * g_get_home_dir (void);
extern
const gchar * g_get_tmp_dir (void);
extern
const gchar * g_get_host_name (void);
extern
const gchar * g_get_prgname (void);
extern
void g_set_prgname (const gchar *prgname);
extern
const gchar * g_get_application_name (void);
extern
void g_set_application_name (const gchar *application_name);

extern
void g_reload_user_special_dirs_cache (void);
extern
const gchar * g_get_user_data_dir (void);
extern
const gchar * g_get_user_config_dir (void);
extern
const gchar * g_get_user_cache_dir (void);
extern
const gchar * const * g_get_system_data_dirs (void);
extern
const gchar * const * g_get_system_config_dirs (void);

extern
const gchar * g_get_user_runtime_dir (void);
typedef enum {
  G_USER_DIRECTORY_DESKTOP,
  G_USER_DIRECTORY_DOCUMENTS,
  G_USER_DIRECTORY_DOWNLOAD,
  G_USER_DIRECTORY_MUSIC,
  G_USER_DIRECTORY_PICTURES,
  G_USER_DIRECTORY_PUBLIC_SHARE,
  G_USER_DIRECTORY_TEMPLATES,
  G_USER_DIRECTORY_VIDEOS,

  G_USER_N_DIRECTORIES
} GUserDirectory;

extern
const gchar * g_get_user_special_dir (GUserDirectory directory);
typedef struct _GDebugKey GDebugKey;
struct _GDebugKey
{
  const gchar *key;
  guint value;
};



extern
guint g_parse_debug_string (const gchar *string,
         const GDebugKey *keys,
         guint nkeys);

extern
gint g_snprintf (gchar *string,
         gulong n,
         gchar const *format,
         ...) __attribute__((__format__ (__printf__, 3, 4)));
extern
gint g_vsnprintf (gchar *string,
         gulong n,
         gchar const *format,
         va_list args)
         __attribute__((__format__ (__printf__, 3, 0)));

extern
void g_nullify_pointer (gpointer *nullify_location);

typedef enum
{
  G_FORMAT_SIZE_DEFAULT = 0,
  G_FORMAT_SIZE_LONG_FORMAT = 1 << 0,
  G_FORMAT_SIZE_IEC_UNITS = 1 << 1
} GFormatSizeFlags;

extern
gchar *g_format_size_full (guint64 size,
                             GFormatSizeFlags flags);
extern
gchar *g_format_size (guint64 size);

__attribute__((__deprecated__("Use '" "g_format_size" "' instead"))) extern
gchar *g_format_size_for_display (goffset size);
typedef void (*GVoidFunc) (void);

__attribute__((__deprecated__)) extern
void g_atexit (GVoidFunc func);
extern
gchar* g_find_program_in_path (const gchar *program);
extern
gint (g_bit_nth_lsf) (gulong mask,
                                 gint nth_bit);
extern
gint (g_bit_nth_msf) (gulong mask,
                                 gint nth_bit);
extern
guint (g_bit_storage) (gulong number);

static inline gint
g_bit_nth_lsf_impl (gulong mask,
                    gint nth_bit)
{
  if ((nth_bit < -1))
    nth_bit = -1;
  while (nth_bit < ((8 * 8) - 1))
    {
      nth_bit++;
      if (mask & (1UL << nth_bit))
        return nth_bit;
    }
  return -1;
}

static inline gint
g_bit_nth_msf_impl (gulong mask,
                    gint nth_bit)
{
  if (nth_bit < 0 || (nth_bit > 8 * 8))
    nth_bit = 8 * 8;
  while (nth_bit > 0)
    {
      nth_bit--;
      if (mask & (1UL << nth_bit))
        return nth_bit;
    }
  return -1;
}

static inline guint
g_bit_storage_impl (gulong number)
{




  guint n_bits = 0;

  do
    {
      n_bits++;
      number >>= 1;
    }
  while (number);
  return n_bits;

}



typedef struct _GMemVTable GMemVTable;
extern
void g_free (gpointer mem);

extern
void g_clear_pointer (gpointer *pp,
                           GDestroyNotify destroy);

extern
gpointer g_malloc (gsize n_bytes) __attribute__((__malloc__)) __attribute__((__alloc_size__(1)));
extern
gpointer g_malloc0 (gsize n_bytes) __attribute__((__malloc__)) __attribute__((__alloc_size__(1)));
extern
gpointer g_realloc (gpointer mem,
      gsize n_bytes) __attribute__((warn_unused_result));
extern
gpointer g_try_malloc (gsize n_bytes) __attribute__((__malloc__)) __attribute__((__alloc_size__(1)));
extern
gpointer g_try_malloc0 (gsize n_bytes) __attribute__((__malloc__)) __attribute__((__alloc_size__(1)));
extern
gpointer g_try_realloc (gpointer mem,
      gsize n_bytes) __attribute__((warn_unused_result));

extern
gpointer g_malloc_n (gsize n_blocks,
      gsize n_block_bytes) __attribute__((__malloc__)) __attribute__((__alloc_size__(1,2)));
extern
gpointer g_malloc0_n (gsize n_blocks,
      gsize n_block_bytes) __attribute__((__malloc__)) __attribute__((__alloc_size__(1,2)));
extern
gpointer g_realloc_n (gpointer mem,
      gsize n_blocks,
      gsize n_block_bytes) __attribute__((warn_unused_result));
extern
gpointer g_try_malloc_n (gsize n_blocks,
      gsize n_block_bytes) __attribute__((__malloc__)) __attribute__((__alloc_size__(1,2)));
extern
gpointer g_try_malloc0_n (gsize n_blocks,
      gsize n_block_bytes) __attribute__((__malloc__)) __attribute__((__alloc_size__(1,2)));
extern
gpointer g_try_realloc_n (gpointer mem,
      gsize n_blocks,
      gsize n_block_bytes) __attribute__((warn_unused_result));
static inline gpointer
g_steal_pointer (gpointer pp)
{
  gpointer *ptr = (gpointer *) pp;
  gpointer ref;

  ref = *ptr;
  *ptr = 
        ((void *)0)
            ;

  return ref;
}
struct _GMemVTable {
  gpointer (*malloc) (gsize n_bytes);
  gpointer (*realloc) (gpointer mem,
      gsize n_bytes);
  void (*free) (gpointer mem);

  gpointer (*calloc) (gsize n_blocks,
      gsize n_block_bytes);
  gpointer (*try_malloc) (gsize n_bytes);
  gpointer (*try_realloc) (gpointer mem,
      gsize n_bytes);
};
__attribute__((__deprecated__)) extern
void g_mem_set_vtable (GMemVTable *vtable);
__attribute__((__deprecated__)) extern
gboolean g_mem_is_system_malloc (void);

extern gboolean g_mem_gc_friendly;



extern GMemVTable *glib_mem_profiler_table;
__attribute__((__deprecated__)) extern
void g_mem_profile (void);




typedef struct _GNode GNode;


typedef enum
{
  G_TRAVERSE_LEAVES = 1 << 0,
  G_TRAVERSE_NON_LEAVES = 1 << 1,
  G_TRAVERSE_ALL = G_TRAVERSE_LEAVES | G_TRAVERSE_NON_LEAVES,
  G_TRAVERSE_MASK = 0x03,
  G_TRAVERSE_LEAFS = G_TRAVERSE_LEAVES,
  G_TRAVERSE_NON_LEAFS = G_TRAVERSE_NON_LEAVES
} GTraverseFlags;


typedef enum
{
  G_IN_ORDER,
  G_PRE_ORDER,
  G_POST_ORDER,
  G_LEVEL_ORDER
} GTraverseType;

typedef gboolean (*GNodeTraverseFunc) (GNode *node,
       gpointer data);
typedef void (*GNodeForeachFunc) (GNode *node,
       gpointer data);
typedef gpointer (*GCopyFunc) (gconstpointer src,
                                                 gpointer data);



struct _GNode
{
  gpointer data;
  GNode *next;
  GNode *prev;
  GNode *parent;
  GNode *children;
};
extern
GNode* g_node_new (gpointer data);
extern
void g_node_destroy (GNode *root);
extern
void g_node_unlink (GNode *node);
extern
GNode* g_node_copy_deep (GNode *node,
     GCopyFunc copy_func,
     gpointer data);
extern
GNode* g_node_copy (GNode *node);
extern
GNode* g_node_insert (GNode *parent,
     gint position,
     GNode *node);
extern
GNode* g_node_insert_before (GNode *parent,
     GNode *sibling,
     GNode *node);
extern
GNode* g_node_insert_after (GNode *parent,
     GNode *sibling,
     GNode *node);
extern
GNode* g_node_prepend (GNode *parent,
     GNode *node);
extern
guint g_node_n_nodes (GNode *root,
     GTraverseFlags flags);
extern
GNode* g_node_get_root (GNode *node);
extern
gboolean g_node_is_ancestor (GNode *node,
     GNode *descendant);
extern
guint g_node_depth (GNode *node);
extern
GNode* g_node_find (GNode *root,
     GTraverseType order,
     GTraverseFlags flags,
     gpointer data);
extern
void g_node_traverse (GNode *root,
     GTraverseType order,
     GTraverseFlags flags,
     gint max_depth,
     GNodeTraverseFunc func,
     gpointer data);






extern
guint g_node_max_height (GNode *root);

extern
void g_node_children_foreach (GNode *node,
      GTraverseFlags flags,
      GNodeForeachFunc func,
      gpointer data);
extern
void g_node_reverse_children (GNode *node);
extern
guint g_node_n_children (GNode *node);
extern
GNode* g_node_nth_child (GNode *node,
      guint n);
extern
GNode* g_node_last_child (GNode *node);
extern
GNode* g_node_find_child (GNode *node,
      GTraverseFlags flags,
      gpointer data);
extern
gint g_node_child_position (GNode *node,
      GNode *child);
extern
gint g_node_child_index (GNode *node,
      gpointer data);

extern
GNode* g_node_first_sibling (GNode *node);
extern
GNode* g_node_last_sibling (GNode *node);




typedef struct _GList GList;

struct _GList
{
  gpointer data;
  GList *next;
  GList *prev;
};



extern
GList* g_list_alloc (void) __attribute__((warn_unused_result));
extern
void g_list_free (GList *list);
extern
void g_list_free_1 (GList *list);

extern
void g_list_free_full (GList *list,
      GDestroyNotify free_func);
extern
GList* g_list_append (GList *list,
      gpointer data) __attribute__((warn_unused_result));
extern
GList* g_list_prepend (GList *list,
      gpointer data) __attribute__((warn_unused_result));
extern
GList* g_list_insert (GList *list,
      gpointer data,
      gint position) __attribute__((warn_unused_result));
extern
GList* g_list_insert_sorted (GList *list,
      gpointer data,
      GCompareFunc func) __attribute__((warn_unused_result));
extern
GList* g_list_insert_sorted_with_data (GList *list,
      gpointer data,
      GCompareDataFunc func,
      gpointer user_data) __attribute__((warn_unused_result));
extern
GList* g_list_insert_before (GList *list,
      GList *sibling,
      gpointer data) __attribute__((warn_unused_result));
extern
GList* g_list_concat (GList *list1,
      GList *list2) __attribute__((warn_unused_result));
extern
GList* g_list_remove (GList *list,
      gconstpointer data) __attribute__((warn_unused_result));
extern
GList* g_list_remove_all (GList *list,
      gconstpointer data) __attribute__((warn_unused_result));
extern
GList* g_list_remove_link (GList *list,
      GList *llink) __attribute__((warn_unused_result));
extern
GList* g_list_delete_link (GList *list,
      GList *link_) __attribute__((warn_unused_result));
extern
GList* g_list_reverse (GList *list) __attribute__((warn_unused_result));
extern
GList* g_list_copy (GList *list) __attribute__((warn_unused_result));

extern
GList* g_list_copy_deep (GList *list,
      GCopyFunc func,
      gpointer user_data) __attribute__((warn_unused_result));

extern
GList* g_list_nth (GList *list,
      guint n);
extern
GList* g_list_nth_prev (GList *list,
      guint n);
extern
GList* g_list_find (GList *list,
      gconstpointer data);
extern
GList* g_list_find_custom (GList *list,
      gconstpointer data,
      GCompareFunc func);
extern
gint g_list_position (GList *list,
      GList *llink);
extern
gint g_list_index (GList *list,
      gconstpointer data);
extern
GList* g_list_last (GList *list);
extern
GList* g_list_first (GList *list);
extern
guint g_list_length (GList *list);
extern
void g_list_foreach (GList *list,
      GFunc func,
      gpointer user_data);
extern
GList* g_list_sort (GList *list,
      GCompareFunc compare_func) __attribute__((warn_unused_result));
extern
GList* g_list_sort_with_data (GList *list,
      GCompareDataFunc compare_func,
      gpointer user_data) __attribute__((warn_unused_result));
extern
gpointer g_list_nth_data (GList *list,
      guint n);









typedef struct _GHashTable GHashTable;

typedef gboolean (*GHRFunc) (gpointer key,
                               gpointer value,
                               gpointer user_data);

typedef struct _GHashTableIter GHashTableIter;

struct _GHashTableIter
{

  gpointer dummy1;
  gpointer dummy2;
  gpointer dummy3;
  int dummy4;
  gboolean dummy5;
  gpointer dummy6;
};

extern
GHashTable* g_hash_table_new (GHashFunc hash_func,
                                            GEqualFunc key_equal_func);
extern
GHashTable* g_hash_table_new_full (GHashFunc hash_func,
                                            GEqualFunc key_equal_func,
                                            GDestroyNotify key_destroy_func,
                                            GDestroyNotify value_destroy_func);
extern
void g_hash_table_destroy (GHashTable *hash_table);
extern
gboolean g_hash_table_insert (GHashTable *hash_table,
                                            gpointer key,
                                            gpointer value);
extern
gboolean g_hash_table_replace (GHashTable *hash_table,
                                            gpointer key,
                                            gpointer value);
extern
gboolean g_hash_table_add (GHashTable *hash_table,
                                            gpointer key);
extern
gboolean g_hash_table_remove (GHashTable *hash_table,
                                            gconstpointer key);
extern
void g_hash_table_remove_all (GHashTable *hash_table);
extern
gboolean g_hash_table_steal (GHashTable *hash_table,
                                            gconstpointer key);
extern
void g_hash_table_steal_all (GHashTable *hash_table);
extern
gpointer g_hash_table_lookup (GHashTable *hash_table,
                                            gconstpointer key);
extern
gboolean g_hash_table_contains (GHashTable *hash_table,
                                            gconstpointer key);
extern
gboolean g_hash_table_lookup_extended (GHashTable *hash_table,
                                            gconstpointer lookup_key,
                                            gpointer *orig_key,
                                            gpointer *value);
extern
void g_hash_table_foreach (GHashTable *hash_table,
                                            GHFunc func,
                                            gpointer user_data);
extern
gpointer g_hash_table_find (GHashTable *hash_table,
                                            GHRFunc predicate,
                                            gpointer user_data);
extern
guint g_hash_table_foreach_remove (GHashTable *hash_table,
                                            GHRFunc func,
                                            gpointer user_data);
extern
guint g_hash_table_foreach_steal (GHashTable *hash_table,
                                            GHRFunc func,
                                            gpointer user_data);
extern
guint g_hash_table_size (GHashTable *hash_table);
extern
GList * g_hash_table_get_keys (GHashTable *hash_table);
extern
GList * g_hash_table_get_values (GHashTable *hash_table);
extern
gpointer * g_hash_table_get_keys_as_array (GHashTable *hash_table,
                                            guint *length);

extern
void g_hash_table_iter_init (GHashTableIter *iter,
                                            GHashTable *hash_table);
extern
gboolean g_hash_table_iter_next (GHashTableIter *iter,
                                            gpointer *key,
                                            gpointer *value);
extern
GHashTable* g_hash_table_iter_get_hash_table (GHashTableIter *iter);
extern
void g_hash_table_iter_remove (GHashTableIter *iter);
extern
void g_hash_table_iter_replace (GHashTableIter *iter,
                                            gpointer value);
extern
void g_hash_table_iter_steal (GHashTableIter *iter);

extern
GHashTable* g_hash_table_ref (GHashTable *hash_table);
extern
void g_hash_table_unref (GHashTable *hash_table);
extern
gboolean g_str_equal (gconstpointer v1,
                         gconstpointer v2);
extern
guint g_str_hash (gconstpointer v);

extern
gboolean g_int_equal (gconstpointer v1,
                         gconstpointer v2);
extern
guint g_int_hash (gconstpointer v);

extern
gboolean g_int64_equal (gconstpointer v1,
                         gconstpointer v2);
extern
guint g_int64_hash (gconstpointer v);

extern
gboolean g_double_equal (gconstpointer v1,
                         gconstpointer v2);
extern
guint g_double_hash (gconstpointer v);

extern
guint g_direct_hash (gconstpointer v) __attribute__((__const__));
extern
gboolean g_direct_equal (gconstpointer v1,
                         gconstpointer v2) __attribute__((__const__));


