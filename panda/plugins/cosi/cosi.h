// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

typedef struct {} VolatilityEnum;
typedef struct {} VolatilityBaseType;
typedef struct {} VolatilitySymbol;
typedef struct {} VolatilityStruct;

target_ptr_t kaslr_offset(CPUState *cpu);

const VolatilityEnum *enum_from_name(const char *name);

const VolatilityBaseType *base_type_from_name(const char *name);

const VolatilitySymbol *symbol_from_name(const char *name);

const VolatilityStruct *type_from_name(const char *name);

target_ptr_t addr_of_symbol(const VolatilitySymbol *symbol);

target_ptr_t value_of_symbol(const VolatilitySymbol *symbol);

/**
 * Gets the name of the symbol as a C-compatible string, or null if the symbol cannot
 * be found. Must be freed via `free_cosi_str`.
 */
char *name_of_symbol(const VolatilitySymbol *symbol);

/**
 * Gets the name of the struct as a C-compatible string, or null if the symbol cannot
 * be found. Must be freed via `free_cosi_str`.
 */
char *name_of_struct(const VolatilityStruct *ty);

/**
 * Gets the name of the nth field in alphabetical order, returning null past the end
 */
char *get_field_by_index(const VolatilityStruct *ty, uintptr_t index);

/**
 * Gets the name of the enum as a C-compatible string, or null if the symbol cannot
 * be found. Must be freed via `free_cosi_str`.
 */
char *name_of_enum(const VolatilityEnum *ty);

/**
 * Gets the name of the base type as a C-compatible string, or null if the symbol cannot
 * be found. Must be freed via `free_cosi_str`.
 */
char *name_of_base_type(const VolatilityBaseType *ty);

/**
 * Gets the size of the base type in bytes
 */
target_ptr_t size_of_base_type(const VolatilityBaseType *ty);

bool is_base_type_signed(const VolatilityBaseType *ty);

target_ptr_t symbol_value_from_name(const char *name);

target_ptr_t symbol_addr_from_name(const char *name);

target_long offset_of_field(const VolatilityStruct *vol_struct, const char *name);

char *type_of_field(const VolatilityStruct *vol_struct, const char *name);

target_ulong size_of_struct(const VolatilityStruct *vol_struct);

target_ulong current_cpu_offset(CPUState *cpu);

void free_cosi_str(char *string);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
