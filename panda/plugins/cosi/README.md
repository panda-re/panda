# cosi

COSI (**C**omplete **O**perating **S**ystem **I**ntrospection, /ˈkōzē/ (like "cozy")) is a system for leveraging [Volatility] symbol tables in order to parse kernel data structures.

It has two main components. The first of which is the core, which provides an API for ASLR offset search, symbol lookup, and type layout information. Also provided is a set of APIs for getting information about OS resources such as processes, files, kernel modules, and more.

[Volatility]: https://github.com/volatilityfoundation/volatility

## Core API

(For more information about a function see [`cosi.h`](./cosi.h))

```c
target_ptr_t kaslr_offset(CPUState *cpu);
const VolatilityEnum *enum_from_name(const char *name);
const VolatilityBaseType *base_type_from_name(const char *name);
const VolatilitySymbol *symbol_from_name(const char *name);
const VolatilityStruct *type_from_name(const char *name);
target_ptr_t addr_of_symbol(const VolatilitySymbol *symbol);
target_ptr_t value_of_symbol(const VolatilitySymbol *symbol);
char *name_of_symbol(const VolatilitySymbol *symbol);
char *name_of_struct(const VolatilityStruct *ty);
char *get_field_by_index(const VolatilityStruct *ty, uintptr_t index);
char *name_of_enum(const VolatilityEnum *ty);
char *name_of_base_type(const VolatilityBaseType *ty);
target_ptr_t size_of_base_type(const VolatilityBaseType *ty);
bool is_base_type_signed(const VolatilityBaseType *ty);
target_ptr_t symbol_value_from_name(const char *name);
target_ptr_t symbol_addr_from_name(const char *name);
target_long offset_of_field(const VolatilityStruct *vol_struct, const char *name);
char *type_of_field(const VolatilityStruct *vol_struct, const char *name);
target_ulong size_of_struct(const VolatilityStruct *vol_struct);
target_ulong current_cpu_offset(CPUState *cpu);
void free_cosi_str(char *string);
```

## OS Resource APIs

(For more information about a function see [`cosi.h`](./cosi.h))

```c
struct CosiProc *get_current_process(CPUState *cpu);
void free_process(struct CosiProc *proc);
char *cosi_proc_name(const struct CosiProc *proc);
struct CosiThread *get_current_thread(CPUState *cpu);
void free_thread(struct CosiThread *thread);
```

## Cosi Usage/Structure

src/structs.rs contains two types of structure definitions. The first type are meant to mimic the kernel's definition of the structure (a stripped down version with only fields we care about, or that are typically present) so that fields we want for that structure can be read out of the guest and accessed as you would expect. The second type, which start with "Cosi," are the structures the user is meant to interact with. These Cosi structures have the underlying kernel structure as a field, but contain additional fields which hold metadata like a guest pointer to the underlying structure, as well as commonly useful fields which might require some computation or multiple dereferences to get at, such as the ppid of a process. Additionally, the Cosi structures have `new` defined (except for CosiThread for now) which returns a populated Cosi structure given a pointer to a certain kernel struct, and `get_current_*` which returns a Cosi struct for the named data type of the current process. For instance, calling `CosiFiles::get_current_files(cpu);` will return a CosiFiles structure which wraps the `files_struct` for the `current task_struct`.

src/lib.rs now contains definitions for `print_current_cosi*_info` defined for each cosi struct, which just print sort-of pretty formatted information about the current process, as well as a callback which triggers on asid change and dumps information to stdout using those functions.

