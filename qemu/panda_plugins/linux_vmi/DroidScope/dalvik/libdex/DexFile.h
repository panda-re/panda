/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Access .dex (Dalvik Executable Format) files.  The code here assumes that
 * the DEX file has been rewritten (byte-swapped, word-aligned) and that
 * the contents can be directly accessed as a collection of C arrays.  Please
 * see docs/dalvik/dex-format.html for a detailed description.
 *
 * The structure and field names were chosen to match those in the DEX spec.
 *
 * It's generally assumed that the DEX file will be stored in shared memory,
 * obviating the need to copy code and constant pool entries into newly
 * allocated storage.  Maintaining local pointers to items in the shared area
 * is valid and encouraged.
 *
 * All memory-mapped structures are 32-bit aligned unless otherwise noted.
 */

#ifndef _LIBDEX_DEXFILE
#define _LIBDEX_DEXFILE

/***********************************************************************8
 * LIST OF CHANGES
 * 1. Changed location of vm/Common.h @ 44
 * 2. Changed location of SysUtil.h @ 46
 */

//LOK
//#include "vm/Common.h"      // basic type defs, e.g. u1/u2/u4/u8, and LOG
#include "dalvik/vm/Common.h"
//#include "libdex/SysUtil.h"
#include "dalvik/libdex/SysUtil.h"

/*
 * gcc-style inline management -- ensures we have a copy of all functions
 * in the library, so code that links against us will work whether or not
 * it was built with optimizations enabled.
 */
#ifndef _DEX_GEN_INLINES             /* only defined by DexInlines.c */
# define DEX_INLINE extern __inline__
#else
# define DEX_INLINE
#endif

/* DEX file magic number */
#define DEX_MAGIC       "dex\n"
/* version, encoded in 4 bytes of ASCII */
#define DEX_MAGIC_VERS  "035\0"

/* same, but for optimized DEX header */
#define DEX_OPT_MAGIC   "dey\n"
#define DEX_OPT_MAGIC_VERS  "036\0"

#define DEX_DEP_MAGIC   "deps"

/*
 * 160-bit SHA-1 digest.
 */
enum { kSHA1DigestLen = 20,                         //!< kSHA1DigestLen
       kSHA1DigestOutputLen = kSHA1DigestLen*2 +1 };//!< kSHA1DigestOutputLen

/* general constants */
enum {
    kDexEndianConstant = 0x12345678,    /* the endianness indicator */
    kDexNoIndex = 0xffffffff,           /* not a valid index value */
};

/*
 * access flags and masks; the "standard" ones are all <= 0x4000
 *
 * Note: There are related declarations in vm/oo/Object.h in the ClassFlags
 * enum.
 */
enum {
    ACC_PUBLIC       = 0x00000001,       // class, field, method, ic
    ACC_PRIVATE      = 0x00000002,       // field, method, ic
    ACC_PROTECTED    = 0x00000004,       // field, method, ic
    ACC_STATIC       = 0x00000008,       // field, method, ic
    ACC_FINAL        = 0x00000010,       // class, field, method, ic
    ACC_SYNCHRONIZED = 0x00000020,       // method (only allowed on natives)
    ACC_SUPER        = 0x00000020,       // class (not used in Dalvik)
    ACC_VOLATILE     = 0x00000040,       // field
    ACC_BRIDGE       = 0x00000040,       // method (1.5)
    ACC_TRANSIENT    = 0x00000080,       // field
    ACC_VARARGS      = 0x00000080,       // method (1.5)
    ACC_NATIVE       = 0x00000100,       // method
    ACC_INTERFACE    = 0x00000200,       // class, ic
    ACC_ABSTRACT     = 0x00000400,       // class, method, ic
    ACC_STRICT       = 0x00000800,       // method
    ACC_SYNTHETIC    = 0x00001000,       // field, method, ic
    ACC_ANNOTATION   = 0x00002000,       // class, ic (1.5)
    ACC_ENUM         = 0x00004000,       // class, field, ic (1.5)
    ACC_CONSTRUCTOR  = 0x00010000,       // method (Dalvik only)
    ACC_DECLARED_SYNCHRONIZED =
                       0x00020000,       // method (Dalvik only)
    ACC_CLASS_MASK =
        (ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT
                | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM),
    ACC_INNER_CLASS_MASK =
        (ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC),
    ACC_FIELD_MASK =
        (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
                | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM),
    ACC_METHOD_MASK =
        (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
                | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
                | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
                | ACC_DECLARED_SYNCHRONIZED),
};

/* annotation constants */
enum {
    kDexVisibilityBuild         = 0x00,     /* annotation visibility */
    kDexVisibilityRuntime       = 0x01,
    kDexVisibilitySystem        = 0x02,

    kDexAnnotationByte          = 0x00,
    kDexAnnotationShort         = 0x02,
    kDexAnnotationChar          = 0x03,
    kDexAnnotationInt           = 0x04,
    kDexAnnotationLong          = 0x06,
    kDexAnnotationFloat         = 0x10,
    kDexAnnotationDouble        = 0x11,
    kDexAnnotationString        = 0x17,
    kDexAnnotationType          = 0x18,
    kDexAnnotationField         = 0x19,
    kDexAnnotationMethod        = 0x1a,
    kDexAnnotationEnum          = 0x1b,
    kDexAnnotationArray         = 0x1c,
    kDexAnnotationAnnotation    = 0x1d,
    kDexAnnotationNull          = 0x1e,
    kDexAnnotationBoolean       = 0x1f,

    kDexAnnotationValueTypeMask = 0x1f,     /* low 5 bits */
    kDexAnnotationValueArgShift = 5,
};

/* map item type codes */
enum {
    kDexTypeHeaderItem               = 0x0000,
    kDexTypeStringIdItem             = 0x0001,
    kDexTypeTypeIdItem               = 0x0002,
    kDexTypeProtoIdItem              = 0x0003,
    kDexTypeFieldIdItem              = 0x0004,
    kDexTypeMethodIdItem             = 0x0005,
    kDexTypeClassDefItem             = 0x0006,
    kDexTypeMapList                  = 0x1000,
    kDexTypeTypeList                 = 0x1001,
    kDexTypeAnnotationSetRefList     = 0x1002,
    kDexTypeAnnotationSetItem        = 0x1003,
    kDexTypeClassDataItem            = 0x2000,
    kDexTypeCodeItem                 = 0x2001,
    kDexTypeStringDataItem           = 0x2002,
    kDexTypeDebugInfoItem            = 0x2003,
    kDexTypeAnnotationItem           = 0x2004,
    kDexTypeEncodedArrayItem         = 0x2005,
    kDexTypeAnnotationsDirectoryItem = 0x2006,
};

/* auxillary data section chunk codes */
enum {
    kDexChunkClassLookup            = 0x434c4b50,   /* CLKP */
    kDexChunkRegisterMaps           = 0x524d4150,   /* RMAP */

    kDexChunkEnd                    = 0x41454e44,   /* AEND */
};

/* debug info opcodes and constants */
enum {
    DBG_END_SEQUENCE         = 0x00,
    DBG_ADVANCE_PC           = 0x01,
    DBG_ADVANCE_LINE         = 0x02,
    DBG_START_LOCAL          = 0x03,
    DBG_START_LOCAL_EXTENDED = 0x04,
    DBG_END_LOCAL            = 0x05,
    DBG_RESTART_LOCAL        = 0x06,
    DBG_SET_PROLOGUE_END     = 0x07,
    DBG_SET_EPILOGUE_BEGIN   = 0x08,
    DBG_SET_FILE             = 0x09,
    DBG_FIRST_SPECIAL        = 0x0a,
    DBG_LINE_BASE            = -4,
    DBG_LINE_RANGE           = 15,
};

/*
 * Direct-mapped "header_item" struct.
 */
typedef struct DexHeader {
    u1  magic[8];           /* includes version number */
    u4  checksum;           /* adler32 checksum */
    u1  signature[kSHA1DigestLen]; /* SHA-1 hash */
    u4  fileSize;           /* length of entire file */
    u4  headerSize;         /* offset to start of next section */
    u4  endianTag;
    u4  linkSize;
    u4  linkOff;
    u4  mapOff;
    u4  stringIdsSize;
    u4  stringIdsOff;
    u4  typeIdsSize;
    u4  typeIdsOff;
    u4  protoIdsSize;
    u4  protoIdsOff;
    u4  fieldIdsSize;
    u4  fieldIdsOff;
    u4  methodIdsSize;
    u4  methodIdsOff;
    u4  classDefsSize;
    u4  classDefsOff;
    u4  dataSize;
    u4  dataOff;
} DexHeader;

/*
 * Direct-mapped "map_item".
 */
typedef struct DexMapItem {
    u2  type;              /* type code (see kDexType* above) */
    u2  unused;
    u4  size;              /* count of items of the indicated type */
    u4  offset;            /* file offset to the start of data */
} DexMapItem;

/*
 * Direct-mapped "map_list".
 */
typedef struct DexMapList {
    u4  size;               /* #of entries in list */
    DexMapItem list[1];     /* entries */
} DexMapList;

/*
 * Direct-mapped "string_id_item".
 */
typedef struct DexStringId {
    u4  stringDataOff;      /* file offset to string_data_item */
} DexStringId;

/*
 * Direct-mapped "type_id_item".
 */
typedef struct DexTypeId {
    u4  descriptorIdx;      /* index into stringIds list for type descriptor */
} DexTypeId;

/*
 * Direct-mapped "field_id_item".
 */
typedef struct DexFieldId {
    u2  classIdx;           /* index into typeIds list for defining class */
    u2  typeIdx;            /* index into typeIds for field type */
    u4  nameIdx;            /* index into stringIds for field name */
} DexFieldId;

/*
 * Direct-mapped "method_id_item".
 */
typedef struct DexMethodId {
    u2  classIdx;           /* index into typeIds list for defining class */
    u2  protoIdx;           /* index into protoIds for method prototype */
    u4  nameIdx;            /* index into stringIds for method name */
} DexMethodId;

/*
 * Direct-mapped "proto_id_item".
 */
typedef struct DexProtoId {
    u4  shortyIdx;          /* index into stringIds for shorty descriptor */
    u4  returnTypeIdx;      /* index into typeIds list for return type */
    u4  parametersOff;      /* file offset to type_list for parameter types */
} DexProtoId;

/*
 * Direct-mapped "class_def_item".
 */
typedef struct DexClassDef {
    u4  classIdx;           /* index into typeIds for this class */
    u4  accessFlags;
    u4  superclassIdx;      /* index into typeIds for superclass */
    u4  interfacesOff;      /* file offset to DexTypeList */
    u4  sourceFileIdx;      /* index into stringIds for source file name */
    u4  annotationsOff;     /* file offset to annotations_directory_item */
    u4  classDataOff;       /* file offset to class_data_item */
    u4  staticValuesOff;    /* file offset to DexEncodedArray */
} DexClassDef;

/*
 * Direct-mapped "type_item".
 */
typedef struct DexTypeItem {
    u2  typeIdx;            /* index into typeIds */
} DexTypeItem;

/*
 * Direct-mapped "type_list".
 */
typedef struct DexTypeList {
    u4  size;               /* #of entries in list */
    DexTypeItem list[1];    /* entries */
} DexTypeList;

/*
 * Direct-mapped "code_item".
 *
 * The "catches" table is used when throwing an exception,
 * "debugInfo" is used when displaying an exception stack trace or
 * debugging. An offset of zero indicates that there are no entries.
 */
typedef struct DexCode {
    u2  registersSize;
    u2  insSize;
    u2  outsSize;
    u2  triesSize;
    u4  debugInfoOff;       /* file offset to debug info stream */
    u4  insnsSize;          /* size of the insns array, in u2 units */
    u2  insns[1];
    /* followed by optional u2 padding */
    /* followed by try_item[triesSize] */
    /* followed by uleb128 handlersSize */
    /* followed by catch_handler_item[handlersSize] */
} DexCode;

/*
 * Direct-mapped "try_item".
 */
typedef struct DexTry {
    u4  startAddr;          /* start address, in 16-bit code units */
    u2  insnCount;          /* instruction count, in 16-bit code units */
    u2  handlerOff;         /* offset in encoded handler data to handlers */
} DexTry;

/*
 * Link table.  Currently undefined.
 */
typedef struct DexLink {
    u1  bleargh;
} DexLink;


/*
 * Direct-mapped "annotations_directory_item".
 */
typedef struct DexAnnotationsDirectoryItem {
    u4  classAnnotationsOff;  /* offset to DexAnnotationSetItem */
    u4  fieldsSize;           /* count of DexFieldAnnotationsItem */
    u4  methodsSize;          /* count of DexMethodAnnotationsItem */
    u4  parametersSize;       /* count of DexParameterAnnotationsItem */
    /* followed by DexFieldAnnotationsItem[fieldsSize] */
    /* followed by DexMethodAnnotationsItem[methodsSize] */
    /* followed by DexParameterAnnotationsItem[parametersSize] */
} DexAnnotationsDirectoryItem;

/*
 * Direct-mapped "field_annotations_item".
 */
typedef struct DexFieldAnnotationsItem {
    u4  fieldIdx;
    u4  annotationsOff;             /* offset to DexAnnotationSetItem */
} DexFieldAnnotationsItem;

/*
 * Direct-mapped "method_annotations_item".
 */
typedef struct DexMethodAnnotationsItem {
    u4  methodIdx;
    u4  annotationsOff;             /* offset to DexAnnotationSetItem */
} DexMethodAnnotationsItem;

/*
 * Direct-mapped "parameter_annotations_item".
 */
typedef struct DexParameterAnnotationsItem {
    u4  methodIdx;
    u4  annotationsOff;             /* offset to DexAnotationSetRefList */
} DexParameterAnnotationsItem;

/*
 * Direct-mapped "annotation_set_ref_item".
 */
typedef struct DexAnnotationSetRefItem {
    u4  annotationsOff;             /* offset to DexAnnotationSetItem */
} DexAnnotationSetRefItem;

/*
 * Direct-mapped "annotation_set_ref_list".
 */
typedef struct DexAnnotationSetRefList {
    u4  size;
    DexAnnotationSetRefItem list[1];
} DexAnnotationSetRefList;

/*
 * Direct-mapped "anotation_set_item".
 */
typedef struct DexAnnotationSetItem {
    u4  size;
    u4  entries[1];                 /* offset to DexAnnotationItem */
} DexAnnotationSetItem;

/*
 * Direct-mapped "annotation_item".
 *
 * NOTE: this structure is byte-aligned.
 */
typedef struct DexAnnotationItem {
    u1  visibility;
    u1  annotation[1];              /* data in encoded_annotation format */
} DexAnnotationItem;

/*
 * Direct-mapped "encoded_array".
 *
 * NOTE: this structure is byte-aligned.
 */
typedef struct DexEncodedArray {
    u1  array[1];                   /* data in encoded_array format */
} DexEncodedArray;

/*
 * Lookup table for classes.  It provides a mapping from class name to
 * class definition.  Used by dexFindClass().
 *
 * We calculate this at DEX optimization time and embed it in the file so we
 * don't need the same hash table in every VM.  This is slightly slower than
 * a hash table with direct pointers to the items, but because it's shared
 * there's less of a penalty for using a fairly sparse table.
 */
typedef struct DexClassLookup {
    int     size;                       // total size, including "size"
    int     numEntries;                 // size of table[]; always power of 2
    struct {
        u4      classDescriptorHash;    // class descriptor hash code
        int     classDescriptorOffset;  // in bytes, from start of DEX
        int     classDefOffset;         // in bytes, from start of DEX
    } table[1];
} DexClassLookup;

/*
 * Header added by DEX optimization pass.  Values are always written in
 * local byte and structure padding.  The first field (magic + version)
 * is guaranteed to be present and directly readable for all expected
 * compiler configurations; the rest is version-dependent.
 *
 * Try to keep this simple and fixed-size.
 */
typedef struct DexOptHeader {
    u1  magic[8];           /* includes version number */

    u4  dexOffset;          /* file offset of DEX header */
    u4  dexLength;
    u4  depsOffset;         /* offset of optimized DEX dependency table */
    u4  depsLength;
    u4  optOffset;          /* file offset of optimized data tables */
    u4  optLength;

    u4  flags;              /* some info flags */
    u4  checksum;           /* adler32 checksum covering deps/opt */

    /* pad for 64-bit alignment if necessary */
} DexOptHeader;

#define DEX_FLAG_VERIFIED           (1)     /* tried to verify all classes */
#define DEX_OPT_FLAG_BIG            (1<<1)  /* swapped to big-endian */
#define DEX_OPT_FLAG_FIELDS         (1<<2)  /* field access optimized */
#define DEX_OPT_FLAG_INVOCATIONS    (1<<3)  /* method calls optimized */

#define DEX_INTERFACE_CACHE_SIZE    128     /* must be power of 2 */

/*
 * Structure representing a DEX file.
 *
 * Code should regard DexFile as opaque, using the API calls provided here
 * to access specific structures.
 */
typedef struct DexFile {
    /* directly-mapped "opt" header */
    const DexOptHeader* pOptHeader;

    /* pointers to directly-mapped structs and arrays in base DEX */
    const DexHeader*    pHeader;
    const DexStringId*  pStringIds;
    const DexTypeId*    pTypeIds;
    const DexFieldId*   pFieldIds;
    const DexMethodId*  pMethodIds;
    const DexProtoId*   pProtoIds;
    const DexClassDef*  pClassDefs;
    const DexLink*      pLinkData;

    /*
     * These are mapped out of the "auxillary" section, and may not be
     * included in the file.
     */
    const DexClassLookup* pClassLookup;
    const void*         pRegisterMapPool;       // RegisterMapClassPool

    /* points to start of DEX file data */
    const u1*           baseAddr;

    /* track memory overhead for auxillary structures */
    int                 overhead;

    /* additional app-specific data structures associated with the DEX */
    //void*               auxData;
} DexFile;

/*
 * Utility function -- rounds up to the nearest power of 2.
 */
u4 dexRoundUpPower2(u4 val);

/*
 * Parse an optimized or unoptimized .dex file sitting in memory.
 *
 * On success, return a newly-allocated DexFile.
 */
DexFile* dexFileParse(const u1* data, size_t length, int flags);

/* bit values for "flags" argument to dexFileParse */
enum {
    kDexParseDefault            = 0,
    kDexParseVerifyChecksum     = 1,
    kDexParseContinueOnError    = (1 << 1),
};

/*
 * Fix the byte ordering of all fields in the DEX file, and do
 * structural verification. This is only required for code that opens
 * "raw" DEX files, such as the DEX optimizer.
 *
 * Return 0 on success.
 */
int dexSwapAndVerify(u1* addr, int len);

/*
 * Detect the file type of the given memory buffer via magic number.
 * Call dexSwapAndVerify() on an unoptimized DEX file, do nothing
 * but return successfully on an optimized DEX file, and report an
 * error for all other cases.
 *
 * Return 0 on success.
 */
int dexSwapAndVerifyIfNecessary(u1* addr, int len);

/*
 * Compute DEX checksum.
 */
u4 dexComputeChecksum(const DexHeader* pHeader);

/*
 * Free a DexFile structure, along with any associated structures.
 */
void dexFileFree(DexFile* pDexFile);

/*
 * Create class lookup table.
 */
DexClassLookup* dexCreateClassLookup(DexFile* pDexFile);

/*
 * Find a class definition by descriptor.
 */
const DexClassDef* dexFindClass(const DexFile* pFile, const char* descriptor);

/*
 * Set up the basic raw data pointers of a DexFile. This function isn't
 * meant for general use.
 */
void dexFileSetupBasicPointers(DexFile* pDexFile, const u1* data);

/* return the DexMapList of the file, if any */
DEX_INLINE const DexMapList* dexGetMap(const DexFile* pDexFile) {
    u4 mapOff = pDexFile->pHeader->mapOff;

    if (mapOff == 0) {
        return NULL;
    } else {
        return (const DexMapList*) (pDexFile->baseAddr + mapOff);
    }
}

/* return the const char* string data referred to by the given string_id */
DEX_INLINE const char* dexGetStringData(const DexFile* pDexFile,
        const DexStringId* pStringId) {
    const u1* ptr = pDexFile->baseAddr + pStringId->stringDataOff;

    // Skip the uleb128 length.
    while (*(ptr++) > 0x7f) /* empty */ ;

    return (const char*) ptr;
}
/* return the StringId with the specified index */
DEX_INLINE const DexStringId* dexGetStringId(const DexFile* pDexFile, u4 idx) {
    assert(idx < pDexFile->pHeader->stringIdsSize);
    return &pDexFile->pStringIds[idx];
}
/* return the UTF-8 encoded string with the specified string_id index */
DEX_INLINE const char* dexStringById(const DexFile* pDexFile, u4 idx) {
    const DexStringId* pStringId = dexGetStringId(pDexFile, idx);
    return dexGetStringData(pDexFile, pStringId);
}

/* Return the UTF-8 encoded string with the specified string_id index,
 * also filling in the UTF-16 size (number of 16-bit code points).*/
const char* dexStringAndSizeById(const DexFile* pDexFile, u4 idx,
        u4* utf16Size);

/* return the TypeId with the specified index */
DEX_INLINE const DexTypeId* dexGetTypeId(const DexFile* pDexFile, u4 idx) {
    assert(idx < pDexFile->pHeader->typeIdsSize);
    return &pDexFile->pTypeIds[idx];
}

/*
 * Get the descriptor string associated with a given type index.
 * The caller should not free() the returned string.
 */
DEX_INLINE const char* dexStringByTypeIdx(const DexFile* pDexFile, u4 idx) {
    const DexTypeId* typeId = dexGetTypeId(pDexFile, idx);
    return dexStringById(pDexFile, typeId->descriptorIdx);
}

/* return the MethodId with the specified index */
DEX_INLINE const DexMethodId* dexGetMethodId(const DexFile* pDexFile, u4 idx) {
    assert(idx < pDexFile->pHeader->methodIdsSize);
    return &pDexFile->pMethodIds[idx];
}

/* return the FieldId with the specified index */
DEX_INLINE const DexFieldId* dexGetFieldId(const DexFile* pDexFile, u4 idx) {
    assert(idx < pDexFile->pHeader->fieldIdsSize);
    return &pDexFile->pFieldIds[idx];
}

/* return the ProtoId with the specified index */
DEX_INLINE const DexProtoId* dexGetProtoId(const DexFile* pDexFile, u4 idx) {
    assert(idx < pDexFile->pHeader->protoIdsSize);
    return &pDexFile->pProtoIds[idx];
}

/*
 * Get the parameter list from a ProtoId. The returns NULL if the ProtoId
 * does not have a parameter list.
 */
DEX_INLINE const DexTypeList* dexGetProtoParameters(
    const DexFile *pDexFile, const DexProtoId* pProtoId) {
    if (pProtoId->parametersOff == 0) {
        return NULL;
    }
    return (const DexTypeList*)
        (pDexFile->baseAddr + pProtoId->parametersOff);
}

/* return the ClassDef with the specified index */
DEX_INLINE const DexClassDef* dexGetClassDef(const DexFile* pDexFile, u4 idx) {
    assert(idx < pDexFile->pHeader->classDefsSize);
    return &pDexFile->pClassDefs[idx];
}

/* given a ClassDef pointer, recover its index */
DEX_INLINE u4 dexGetIndexForClassDef(const DexFile* pDexFile,
    const DexClassDef* pClassDef)
{
    assert(pClassDef >= pDexFile->pClassDefs &&
           pClassDef < pDexFile->pClassDefs + pDexFile->pHeader->classDefsSize);
    return pClassDef - pDexFile->pClassDefs;
}

/* get the interface list for a DexClass */
DEX_INLINE const DexTypeList* dexGetInterfacesList(const DexFile* pDexFile,
    const DexClassDef* pClassDef)
{
    if (pClassDef->interfacesOff == 0)
        return NULL;
    return (const DexTypeList*)
        (pDexFile->baseAddr + pClassDef->interfacesOff);
}
/* return the Nth entry in a DexTypeList. */
DEX_INLINE const DexTypeItem* dexGetTypeItem(const DexTypeList* pList,
    u4 idx)
{
    assert(idx < pList->size);
    return &pList->list[idx];
}
/* return the type_idx for the Nth entry in a TypeList */
DEX_INLINE u4 dexTypeListGetIdx(const DexTypeList* pList, u4 idx) {
    const DexTypeItem* pItem = dexGetTypeItem(pList, idx);
    return pItem->typeIdx;
}

/* get the static values list for a DexClass */
DEX_INLINE const DexEncodedArray* dexGetStaticValuesList(
    const DexFile* pDexFile, const DexClassDef* pClassDef)
{
    if (pClassDef->staticValuesOff == 0)
        return NULL;
    return (const DexEncodedArray*)
        (pDexFile->baseAddr + pClassDef->staticValuesOff);
}

/* get the annotations directory item for a DexClass */
DEX_INLINE const DexAnnotationsDirectoryItem* dexGetAnnotationsDirectoryItem(
    const DexFile* pDexFile, const DexClassDef* pClassDef)
{
    if (pClassDef->annotationsOff == 0)
        return NULL;
    return (const DexAnnotationsDirectoryItem*)
        (pDexFile->baseAddr + pClassDef->annotationsOff);
}

/* get the source file string */
DEX_INLINE const char* dexGetSourceFile(
    const DexFile* pDexFile, const DexClassDef* pClassDef)
{
    if (pClassDef->sourceFileIdx == 0xffffffff)
        return NULL;
    return dexStringById(pDexFile, pClassDef->sourceFileIdx);
}

/* get the size, in bytes, of a DexCode */
size_t dexGetDexCodeSize(const DexCode* pCode);


/* get a pointer to the start of the debugging data */
DEX_INLINE const u1* dexGetDebugInfoStream(const DexFile* pDexFile,
    const DexCode* pCode)
{
    if (pCode->debugInfoOff == 0) {
        return NULL;
    } else {
        return pDexFile->baseAddr + pCode->debugInfoOff;
    }
}

/*
 * Callback for "new position table entry".
 * Returning non-0 causes the decoder to stop early.
 */
typedef int (*DexDebugNewPositionCb)(void *cnxt, u4 address, u4 lineNum);

/*
 * Callback for "new locals table entry". "signature" is an empty string
 * if no signature is available for an entry.
 */
typedef void (*DexDebugNewLocalCb)(void *cnxt, u2 reg, u4 startAddress,
        u4 endAddress, const char *name, const char *descriptor,
        const char *signature);

/*
 * Decode debug info for method.
 *
 * posCb is called in ascending address order.
 * localCb is called in order of ascending end address.
 */
void dexDecodeDebugInfo(
            const DexFile* pDexFile,
            const DexCode* pDexCode,
            const char* classDescriptor,
            u4 protoIdx,
            u4 accessFlags,
            DexDebugNewPositionCb posCb, DexDebugNewLocalCb localCb,
            void* cnxt);

/* DexClassDef convenience - get class descriptor */
DEX_INLINE const char* dexGetClassDescriptor(const DexFile* pDexFile,
    const DexClassDef* pClassDef)
{
    return dexStringByTypeIdx(pDexFile, pClassDef->classIdx);
}

/* DexClassDef convenience - get superclass descriptor */
DEX_INLINE const char* dexGetSuperClassDescriptor(const DexFile* pDexFile,
    const DexClassDef* pClassDef)
{
    if (pClassDef->superclassIdx == 0)
        return NULL;
    return dexStringByTypeIdx(pDexFile, pClassDef->superclassIdx);
}

/* DexClassDef convenience - get class_data_item pointer */
DEX_INLINE const u1* dexGetClassData(const DexFile* pDexFile,
    const DexClassDef* pClassDef)
{
    if (pClassDef->classDataOff == 0)
        return NULL;
    return (const u1*) (pDexFile->baseAddr + pClassDef->classDataOff);
}

/* Get an annotation set at a particular offset. */
DEX_INLINE const DexAnnotationSetItem* dexGetAnnotationSetItem(
    const DexFile* pDexFile, u4 offset)
{
    return (const DexAnnotationSetItem*) (pDexFile->baseAddr + offset);
}
/* get the class' annotation set */
DEX_INLINE const DexAnnotationSetItem* dexGetClassAnnotationSet(
    const DexFile* pDexFile, const DexAnnotationsDirectoryItem* pAnnoDir)
{
    if (pAnnoDir->classAnnotationsOff == 0)
        return NULL;
    return dexGetAnnotationSetItem(pDexFile, pAnnoDir->classAnnotationsOff);
}

/* get the class' field annotation list */
DEX_INLINE const DexFieldAnnotationsItem* dexGetFieldAnnotations(
    const DexFile* pDexFile, const DexAnnotationsDirectoryItem* pAnnoDir)
{
    if (pAnnoDir->fieldsSize == 0)
        return NULL;

    // Skip past the header to the start of the field annotations.
    return (const DexFieldAnnotationsItem*) &pAnnoDir[1];
}

/* get field annotation list size */
DEX_INLINE int dexGetFieldAnnotationsSize(const DexFile* pDexFile,
    const DexAnnotationsDirectoryItem* pAnnoDir)
{
    return pAnnoDir->fieldsSize;
}

/* return a pointer to the field's annotation set */
DEX_INLINE const DexAnnotationSetItem* dexGetFieldAnnotationSetItem(
    const DexFile* pDexFile, const DexFieldAnnotationsItem* pItem)
{
    return dexGetAnnotationSetItem(pDexFile, pItem->annotationsOff);
}

/* get the class' method annotation list */
DEX_INLINE const DexMethodAnnotationsItem* dexGetMethodAnnotations(
    const DexFile* pDexFile, const DexAnnotationsDirectoryItem* pAnnoDir)
{
    if (pAnnoDir->methodsSize == 0)
        return NULL;

    /*
     * Skip past the header and field annotations to the start of the
     * method annotations.
     */
    const u1* addr = (const u1*) &pAnnoDir[1];
    addr += pAnnoDir->fieldsSize * sizeof (DexFieldAnnotationsItem);
    return (const DexMethodAnnotationsItem*) addr;
}

/* get method annotation list size */
DEX_INLINE int dexGetMethodAnnotationsSize(const DexFile* pDexFile,
    const DexAnnotationsDirectoryItem* pAnnoDir)
{
    return pAnnoDir->methodsSize;
}

/* return a pointer to the method's annotation set */
DEX_INLINE const DexAnnotationSetItem* dexGetMethodAnnotationSetItem(
    const DexFile* pDexFile, const DexMethodAnnotationsItem* pItem)
{
    return dexGetAnnotationSetItem(pDexFile, pItem->annotationsOff);
}

/* get the class' parameter annotation list */
DEX_INLINE const DexParameterAnnotationsItem* dexGetParameterAnnotations(
    const DexFile* pDexFile, const DexAnnotationsDirectoryItem* pAnnoDir)
{
    if (pAnnoDir->parametersSize == 0)
        return NULL;

    /*
     * Skip past the header, field annotations, and method annotations
     * to the start of the parameter annotations.
     */
    const u1* addr = (const u1*) &pAnnoDir[1];
    addr += pAnnoDir->fieldsSize * sizeof (DexFieldAnnotationsItem);
    addr += pAnnoDir->methodsSize * sizeof (DexMethodAnnotationsItem);
    return (const DexParameterAnnotationsItem*) addr;
}

/* get method annotation list size */
DEX_INLINE int dexGetParameterAnnotationsSize(const DexFile* pDexFile,
    const DexAnnotationsDirectoryItem* pAnnoDir)
{
    return pAnnoDir->parametersSize;
}

/* return the parameter annotation ref list */
DEX_INLINE const DexAnnotationSetRefList* dexGetParameterAnnotationSetRefList(
    const DexFile* pDexFile, const DexParameterAnnotationsItem* pItem)
{
    return (const DexAnnotationSetRefList*)
        (pDexFile->baseAddr + pItem->annotationsOff);
}

/* get method annotation list size */
DEX_INLINE int dexGetParameterAnnotationSetRefSize(const DexFile* pDexFile,
    const DexParameterAnnotationsItem* pItem)
{
    if (pItem->annotationsOff == 0)
        return 0;
    return dexGetParameterAnnotationSetRefList(pDexFile, pItem)->size;
}

/* return the Nth entry from an annotation set ref list */
DEX_INLINE const DexAnnotationSetRefItem* dexGetParameterAnnotationSetRef(
    const DexAnnotationSetRefList* pList, u4 idx)
{
    assert(idx < pList->size);
    return &pList->list[idx];
}

/* given a DexAnnotationSetRefItem, return the DexAnnotationSetItem */
DEX_INLINE const DexAnnotationSetItem* dexGetSetRefItemItem(
    const DexFile* pDexFile, const DexAnnotationSetRefItem* pItem)
{
    return dexGetAnnotationSetItem(pDexFile, pItem->annotationsOff);
}

/* return the Nth annotation offset from a DexAnnotationSetItem */
DEX_INLINE u4 dexGetAnnotationOff(
    const DexAnnotationSetItem* pAnnoSet, u4 idx)
{
    assert(idx < pAnnoSet->size);
    return pAnnoSet->entries[idx];
}

/* return the Nth annotation item from a DexAnnotationSetItem */
DEX_INLINE const DexAnnotationItem* dexGetAnnotationItem(
    const DexFile* pDexFile, const DexAnnotationSetItem* pAnnoSet, u4 idx)
{
    return (const DexAnnotationItem*)
        (pDexFile->baseAddr + dexGetAnnotationOff(pAnnoSet, idx));
}


/*
 * ===========================================================================
 *      Utility Functions
 * ===========================================================================
 */

/*
 * Retrieve the next UTF-16 character from a UTF-8 string.
 *
 * Advances "*pUtf8Ptr" to the start of the next character.
 *
 * WARNING: If a string is corrupted by dropping a '\0' in the middle
 * of a 3-byte sequence, you can end up overrunning the buffer with
 * reads (and possibly with the writes if the length was computed and
 * cached before the damage). For performance reasons, this function
 * assumes that the string being parsed is known to be valid (e.g., by
 * already being verified). Most strings we process here are coming
 * out of dex files or other internal translations, so the only real
 * risk comes from the JNI NewStringUTF call.
 */
DEX_INLINE u2 dexGetUtf16FromUtf8(const char** pUtf8Ptr)
{
    unsigned int one, two, three;

    one = *(*pUtf8Ptr)++;
    if ((one & 0x80) != 0) {
        /* two- or three-byte encoding */
        two = *(*pUtf8Ptr)++;
        if ((one & 0x20) != 0) {
            /* three-byte encoding */
            three = *(*pUtf8Ptr)++;
            return ((one & 0x0f) << 12) |
                   ((two & 0x3f) << 6) |
                   (three & 0x3f);
        } else {
            /* two-byte encoding */
            return ((one & 0x1f) << 6) |
                   (two & 0x3f);
        }
    } else {
        /* one-byte encoding */
        return one;
    }
}

/* Compare two '\0'-terminated modified UTF-8 strings, using Unicode
 * code point values for comparison. This treats different encodings
 * for the same code point as equivalent, except that only a real '\0'
 * byte is considered the string terminator. The return value is as
 * for strcmp(). */
int dexUtf8Cmp(const char* s1, const char* s2);


/* for dexIsValidMemberNameUtf8(), a bit vector indicating valid low ascii */
extern u4 DEX_MEMBER_VALID_LOW_ASCII[4];

/* Helper for dexIsValidMemberUtf8(); do not call directly. */
bool dexIsValidMemberNameUtf8_0(const char** pUtf8Ptr);

/* Return whether the pointed-at modified-UTF-8 encoded character is
 * valid as part of a member name, updating the pointer to point past
 * the consumed character. This will consume two encoded UTF-16 code
 * points if the character is encoded as a surrogate pair. Also, if
 * this function returns false, then the given pointer may only have
 * been partially advanced. */
DEX_INLINE bool dexIsValidMemberNameUtf8(const char** pUtf8Ptr) {
    u1 c = (u1) **pUtf8Ptr;
    if (c <= 0x7f) {
        // It's low-ascii, so check the table.
        u4 wordIdx = c >> 5;
        u4 bitIdx = c & 0x1f;
        (*pUtf8Ptr)++;
        return (DEX_MEMBER_VALID_LOW_ASCII[wordIdx] & (1 << bitIdx)) != 0;
    }

    /*
     * It's a multibyte encoded character. Call a non-inline function
     * for the heavy lifting.
     */
    return dexIsValidMemberNameUtf8_0(pUtf8Ptr);
}

/* Return whether the given string is a valid field or method name. */
bool dexIsValidMemberName(const char* s);

/* Return whether the given string is a valid type descriptor. */
bool dexIsValidTypeDescriptor(const char* s);

/* Return whether the given string is a valid reference descriptor. This
 * is true if dexIsValidTypeDescriptor() returns true and the descriptor
 * is for a class or array and not a primitive type. */
bool dexIsReferenceDescriptor(const char* s);

/* Return whether the given string is a valid class descriptor. This
 * is true if dexIsValidTypeDescriptor() returns true and the descriptor
 * is for a class and not an array or primitive type. */
bool dexIsClassDescriptor(const char* s);

/* Return whether the given string is a valid field type descriptor. This
 * is true if dexIsValidTypeDescriptor() returns true and the descriptor
 * is for anything but "void". */
bool dexIsFieldDescriptor(const char* s);

#endif /*_LIBDEX_DEXFILE*/
