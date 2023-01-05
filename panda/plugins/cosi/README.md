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

### Symbol Tables
#### Providing Symbol Tables
COSI needs a symbol table in order to function. These symbol tables provide layouts and offsets for kernel data structures and symbols, and will vary from kernel to kernel. If you do not provide a path to a symbol table you've already generated and placed in your `~/.panda` directory, COSI will try to automatically grab the OS string from the kernel, and then check if a symbol table with the corresponding name exists on your system. If not, it then attemps to download that symbol table from our [corpus]. If we do not have a symbol table for the kernel you're attempting to use, you may have to [generate] it yourself. Once you do this, yielding say `new_symtab.json`, you will need to run 

`xz new_symtab.json` 

to compress the file, and then

`mv new_symtab.json.xz ~/.panda`

to move the resulting compressed file to where COSI will find it. Feel free to discard the original `.json` file. 

[corpus]: https://panda.re/volatility3_profiles/
[generate]: https://github.com/volatilityfoundation/volatility3#symbol-tables

#### Symbol Table Format
Symbol Tables, in this context, are `.json` files containing kernel symbol and structure information. For example, here is the (abridged) listing for `task_struct` from the `ubuntu_4.15.0-72-generic_64` symbol table (all but the first and last fields ommited for readability)

```json
"task_struct": {
    "size": 9088,
    "fields": {
      "acct_rss_mem1": {
        "type": {
          "kind": "base",
          "name": "long long unsigned int"
        },
        "offset": 3024
      },
      ...
      [snip]
      ...
      "wakee_flips": {
        "type": {
          "kind": "base",
          "name": "unsigned int"
        },
        "offset": 64
      }
    },
    "kind": "struct"
  },
```

As you can see, the fields for this structure are "size," "fields," and "kind." These fields may vary from structure to structure, but this should give you a rough idea of the format of the (very large) symbol tables. If you are very set on exploring these tables more, or need to view them for debugging purposes, the command line tool [jless] might prove useful, or if that somewhat too manual, the python script [`jdcoder.py`](./jdcoder.py) provided here may help as well.

[jless]: https://github.com/PaulJuliusMartinez/jless


### Source Files

#### structs.rs
[`src/structs.rs`](./src/structs.rs) contains two types of structure definitions. The first type are meant to mimic the kernel's definition of the structure (a stripped down version with only fields we care about, or that are typically present) so that fields we want for that structure can be read out of the guest and accessed as you would expect. The second type, which start with "Cosi," are the structures the user is meant to interact with. These Cosi structures have the underlying kernel structure as a field, but contain additional fields which hold metadata like a guest pointer to the underlying structure, as well as commonly useful fields which might require some computation or multiple dereferences to get at, such as the ppid of a process. Additionally, the Cosi structures have `new` defined (except for CosiThread, for now) which returns a populated Cosi structure given a pointer to a certain kernel struct, and `get_current_*` which returns a Cosi struct for the named data type of the current process. For instance, calling `CosiFiles::get_current_files(cpu);` will return a CosiFiles structure which wraps the `files_struct` for the `current task_struct`.

#### lib.rs
[src/lib.rs](./src/lib.rs) contains definitions for:

 `print_current_cosi*_info` defined for each cosi struct, which print sort-of pretty formatted information about the current process.
 
 `asid_changed`, a callback which triggers on asid change and dumps information to stdout using the `print_*` functions.

 `get_process_list` which walks the process list and returns a `Vec` of all processes running on the system.

 `get_process_children` which returns a `Vec` of children of a given process

as well as several functions which allow the plugin to work.

#### downloader.rs
[src/downloader.rs](./src/downloader.rs) contains the logic for automatic detection and download of the symbol table for the kernel being used.

