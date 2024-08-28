#ifndef FW_CFG_H
#define FW_CFG_H

#include "exec/hwaddr.h"
#include "hw/nvram/fw_cfg_keys.h"

typedef struct FWCfgFile {
    uint32_t  size;        /* file size */
    uint16_t  select;      /* write this to 0x510 to read it */
    uint16_t  reserved;
    char      name[FW_CFG_MAX_FILE_PATH];
} FWCfgFile;

#define FW_CFG_ORDER_OVERRIDE_VGA    70
#define FW_CFG_ORDER_OVERRIDE_NIC    80
#define FW_CFG_ORDER_OVERRIDE_USER   100
#define FW_CFG_ORDER_OVERRIDE_DEVICE 110

void fw_cfg_set_order_override(FWCfgState *fw_cfg, int order);
void fw_cfg_reset_order_override(FWCfgState *fw_cfg);

typedef struct FWCfgFiles {
    uint32_t  count;
    FWCfgFile f[];
} FWCfgFiles;

/* Control as first field allows for different structures selected by this
 * field, which might be useful in the future
 */
typedef struct FWCfgDmaAccess {
    uint32_t control;
    uint32_t length;
    uint64_t address;
} QEMU_PACKED FWCfgDmaAccess;

typedef void (*FWCfgReadCallback)(void *opaque);

typedef void (*FWCfgWriteCallback)(void *opaque, off_t start, size_t len);

/**
 * fw_cfg_add_bytes:
 * @s: fw_cfg device being modified
 * @key: selector key value for new fw_cfg item
 * @data: pointer to start of item data
 * @len: size of item data
 *
 * Add a new fw_cfg item, available by selecting the given key, as a raw
 * "blob" of the given size. The data referenced by the starting pointer
 * is only linked, NOT copied, into the data structure of the fw_cfg device.
 */
void fw_cfg_add_bytes(FWCfgState *s, uint16_t key, void *data, size_t len);

/**
 * fw_cfg_add_string:
 * @s: fw_cfg device being modified
 * @key: selector key value for new fw_cfg item
 * @value: NUL-terminated ascii string
 *
 * Add a new fw_cfg item, available by selecting the given key. The item
 * data will consist of a dynamically allocated copy of the provided string,
 * including its NUL terminator.
 */
void fw_cfg_add_string(FWCfgState *s, uint16_t key, const char *value);

/**
 * fw_cfg_add_i16:
 * @s: fw_cfg device being modified
 * @key: selector key value for new fw_cfg item
 * @value: 16-bit integer
 *
 * Add a new fw_cfg item, available by selecting the given key. The item
 * data will consist of a dynamically allocated copy of the given 16-bit
 * value, converted to little-endian representation.
 */
void fw_cfg_add_i16(FWCfgState *s, uint16_t key, uint16_t value);

/**
 * fw_cfg_modify_i16:
 * @s: fw_cfg device being modified
 * @key: selector key value for new fw_cfg item
 * @value: 16-bit integer
 *
 * Replace the fw_cfg item available by selecting the given key. The new
 * data will consist of a dynamically allocated copy of the given 16-bit
 * value, converted to little-endian representation. The data being replaced,
 * assumed to have been dynamically allocated during an earlier call to
 * either fw_cfg_add_i16() or fw_cfg_modify_i16(), is freed before returning.
 */
void fw_cfg_modify_i16(FWCfgState *s, uint16_t key, uint16_t value);

/**
 * fw_cfg_add_i32:
 * @s: fw_cfg device being modified
 * @key: selector key value for new fw_cfg item
 * @value: 32-bit integer
 *
 * Add a new fw_cfg item, available by selecting the given key. The item
 * data will consist of a dynamically allocated copy of the given 32-bit
 * value, converted to little-endian representation.
 */
void fw_cfg_add_i32(FWCfgState *s, uint16_t key, uint32_t value);

/**
 * fw_cfg_add_i64:
 * @s: fw_cfg device being modified
 * @key: selector key value for new fw_cfg item
 * @value: 64-bit integer
 *
 * Add a new fw_cfg item, available by selecting the given key. The item
 * data will consist of a dynamically allocated copy of the given 64-bit
 * value, converted to little-endian representation.
 */
void fw_cfg_add_i64(FWCfgState *s, uint16_t key, uint64_t value);

/**
 * fw_cfg_add_file:
 * @s: fw_cfg device being modified
 * @filename: name of new fw_cfg file item
 * @data: pointer to start of item data
 * @len: size of item data
 *
 * Add a new NAMED fw_cfg item as a raw "blob" of the given size. The data
 * referenced by the starting pointer is only linked, NOT copied, into the
 * data structure of the fw_cfg device.
 * The next available (unused) selector key starting at FW_CFG_FILE_FIRST
 * will be used; also, a new entry will be added to the file directory
 * structure residing at key value FW_CFG_FILE_DIR, containing the item name,
 * data size, and assigned selector key value.
 */
void fw_cfg_add_file(FWCfgState *s, const char *filename, void *data,
                     size_t len);

/**
 * fw_cfg_add_file_callback:
 * @s: fw_cfg device being modified
 * @filename: name of new fw_cfg file item
 * @callback: callback function
 * @callback_opaque: argument to be passed into callback function
 * @data: pointer to start of item data
 * @len: size of item data
 * @read_only: is file read only
 *
 * Add a new NAMED fw_cfg item as a raw "blob" of the given size. The data
 * referenced by the starting pointer is only linked, NOT copied, into the
 * data structure of the fw_cfg device.
 * The next available (unused) selector key starting at FW_CFG_FILE_FIRST
 * will be used; also, a new entry will be added to the file directory
 * structure residing at key value FW_CFG_FILE_DIR, containing the item name,
 * data size, and assigned selector key value.
 * Additionally, set a callback function (and argument) to be called each
 * time this item is selected (by having its selector key either written to
 * the fw_cfg control register, or passed to QEMU in FWCfgDmaAccess.control
 * with FW_CFG_DMA_CTL_SELECT).
 */
void fw_cfg_add_file_callback(FWCfgState *s, const char *filename,
                              FWCfgReadCallback callback, void *callback_opaque,
                              void *data, size_t len, bool read_only);

void fw_cfg_add_file_callback_write(FWCfgState *s, const char *filename,
                              FWCfgReadCallback callback, FWCfgWriteCallback write_callbac,
                              void *callback_opaque,
                              void *data, size_t len, bool read_only);

/**
 * fw_cfg_modify_file:
 * @s: fw_cfg device being modified
 * @filename: name of new fw_cfg file item
 * @data: pointer to start of item data
 * @len: size of item data
 *
 * Replace a NAMED fw_cfg item. If an existing item is found, its callback
 * information will be cleared, and a pointer to its data will be returned
 * to the caller, so that it may be freed if necessary. If an existing item
 * is not found, this call defaults to fw_cfg_add_file(), and NULL is
 * returned to the caller.
 * In either case, the new item data is only linked, NOT copied, into the
 * data structure of the fw_cfg device.
 *
 * Returns: pointer to old item's data, or NULL if old item does not exist.
 */
void *fw_cfg_modify_file(FWCfgState *s, const char *filename, void *data,
                         size_t len);

FWCfgState *fw_cfg_init_io_dma(uint32_t iobase, uint32_t dma_iobase,
                                AddressSpace *dma_as);
FWCfgState *fw_cfg_init_io(uint32_t iobase);
FWCfgState *fw_cfg_init_mem(hwaddr ctl_addr, hwaddr data_addr);
FWCfgState *fw_cfg_init_mem_wide(hwaddr ctl_addr,
                                 hwaddr data_addr, uint32_t data_width,
                                 hwaddr dma_addr, AddressSpace *dma_as);

FWCfgState *fw_cfg_find(void);
bool fw_cfg_dma_enabled(void *opaque);

#endif
