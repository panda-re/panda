/*
 * Block driver for the QCOW format
 *
 * Copyright (c) 2004-2006 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "block/block_int.h"
#include "sysemu/block-backend.h"
#include "qemu/module.h"
#include "qemu/bswap.h"
#include <zlib.h>
#include "qapi/qmp/qerror.h"
#include "crypto/cipher.h"
#include "migration/migration.h"

/**************************************************************/
/* QEMU COW block driver with compression and encryption support */

#define QCOW_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)
#define QCOW_VERSION 1

#define QCOW_CRYPT_NONE 0
#define QCOW_CRYPT_AES  1

#define QCOW_OFLAG_COMPRESSED (1LL << 63)

typedef struct QCowHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t backing_file_offset;
    uint32_t backing_file_size;
    uint32_t mtime;
    uint64_t size; /* in bytes */
    uint8_t cluster_bits;
    uint8_t l2_bits;
    uint16_t padding;
    uint32_t crypt_method;
    uint64_t l1_table_offset;
} QEMU_PACKED QCowHeader;

#define L2_CACHE_SIZE 16

typedef struct BDRVQcowState {
    int cluster_bits;
    int cluster_size;
    int cluster_sectors;
    int l2_bits;
    int l2_size;
    unsigned int l1_size;
    uint64_t cluster_offset_mask;
    uint64_t l1_table_offset;
    uint64_t *l1_table;
    uint64_t *l2_cache;
    uint64_t l2_cache_offsets[L2_CACHE_SIZE];
    uint32_t l2_cache_counts[L2_CACHE_SIZE];
    uint8_t *cluster_cache;
    uint8_t *cluster_data;
    uint64_t cluster_cache_offset;
    QCryptoCipher *cipher; /* NULL if no key yet */
    uint32_t crypt_method_header;
    CoMutex lock;
    Error *migration_blocker;
} BDRVQcowState;

static int decompress_cluster(BlockDriverState *bs, uint64_t cluster_offset);

static int qcow_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    const QCowHeader *cow_header = (const void *)buf;

    if (buf_size >= sizeof(QCowHeader) &&
        be32_to_cpu(cow_header->magic) == QCOW_MAGIC &&
        be32_to_cpu(cow_header->version) == QCOW_VERSION)
        return 100;
    else
        return 0;
}

static int qcow_open(BlockDriverState *bs, QDict *options, int flags,
                     Error **errp)
{
    BDRVQcowState *s = bs->opaque;
    unsigned int len, i, shift;
    int ret;
    QCowHeader header;
    Error *local_err = NULL;

    bs->file = bdrv_open_child(NULL, options, "file", bs, &child_file,
                               false, errp);
    if (!bs->file) {
        return -EINVAL;
    }

    ret = bdrv_pread(bs->file, 0, &header, sizeof(header));
    if (ret < 0) {
        goto fail;
    }
    be32_to_cpus(&header.magic);
    be32_to_cpus(&header.version);
    be64_to_cpus(&header.backing_file_offset);
    be32_to_cpus(&header.backing_file_size);
    be32_to_cpus(&header.mtime);
    be64_to_cpus(&header.size);
    be32_to_cpus(&header.crypt_method);
    be64_to_cpus(&header.l1_table_offset);

    if (header.magic != QCOW_MAGIC) {
        error_setg(errp, "Image not in qcow format");
        ret = -EINVAL;
        goto fail;
    }
    if (header.version != QCOW_VERSION) {
        error_setg(errp, "Unsupported qcow version %" PRIu32, header.version);
        ret = -ENOTSUP;
        goto fail;
    }

    if (header.size <= 1) {
        error_setg(errp, "Image size is too small (must be at least 2 bytes)");
        ret = -EINVAL;
        goto fail;
    }
    if (header.cluster_bits < 9 || header.cluster_bits > 16) {
        error_setg(errp, "Cluster size must be between 512 and 64k");
        ret = -EINVAL;
        goto fail;
    }

    /* l2_bits specifies number of entries; storing a uint64_t in each entry,
     * so bytes = num_entries << 3. */
    if (header.l2_bits < 9 - 3 || header.l2_bits > 16 - 3) {
        error_setg(errp, "L2 table size must be between 512 and 64k");
        ret = -EINVAL;
        goto fail;
    }

    if (header.crypt_method > QCOW_CRYPT_AES) {
        error_setg(errp, "invalid encryption method in qcow header");
        ret = -EINVAL;
        goto fail;
    }
    if (!qcrypto_cipher_supports(QCRYPTO_CIPHER_ALG_AES_128,
                                 QCRYPTO_CIPHER_MODE_CBC)) {
        error_setg(errp, "AES cipher not available");
        ret = -EINVAL;
        goto fail;
    }
    s->crypt_method_header = header.crypt_method;
    if (s->crypt_method_header) {
        if (bdrv_uses_whitelist() &&
            s->crypt_method_header == QCOW_CRYPT_AES) {
            error_setg(errp,
                       "Use of AES-CBC encrypted qcow images is no longer "
                       "supported in system emulators");
            error_append_hint(errp,
                              "You can use 'qemu-img convert' to convert your "
                              "image to an alternative supported format, such "
                              "as unencrypted qcow, or raw with the LUKS "
                              "format instead.\n");
            ret = -ENOSYS;
            goto fail;
        }

        bs->encrypted = true;
    }
    s->cluster_bits = header.cluster_bits;
    s->cluster_size = 1 << s->cluster_bits;
    s->cluster_sectors = 1 << (s->cluster_bits - 9);
    s->l2_bits = header.l2_bits;
    s->l2_size = 1 << s->l2_bits;
    bs->total_sectors = header.size / 512;
    s->cluster_offset_mask = (1LL << (63 - s->cluster_bits)) - 1;

    /* read the level 1 table */
    shift = s->cluster_bits + s->l2_bits;
    if (header.size > UINT64_MAX - (1LL << shift)) {
        error_setg(errp, "Image too large");
        ret = -EINVAL;
        goto fail;
    } else {
        uint64_t l1_size = (header.size + (1LL << shift) - 1) >> shift;
        if (l1_size > INT_MAX / sizeof(uint64_t)) {
            error_setg(errp, "Image too large");
            ret = -EINVAL;
            goto fail;
        }
        s->l1_size = l1_size;
    }

    s->l1_table_offset = header.l1_table_offset;
    s->l1_table = g_try_new(uint64_t, s->l1_size);
    if (s->l1_table == NULL) {
        error_setg(errp, "Could not allocate memory for L1 table");
        ret = -ENOMEM;
        goto fail;
    }

    ret = bdrv_pread(bs->file, s->l1_table_offset, s->l1_table,
               s->l1_size * sizeof(uint64_t));
    if (ret < 0) {
        goto fail;
    }

    for(i = 0;i < s->l1_size; i++) {
        be64_to_cpus(&s->l1_table[i]);
    }

    /* alloc L2 cache (max. 64k * 16 * 8 = 8 MB) */
    s->l2_cache =
        qemu_try_blockalign(bs->file->bs,
                            s->l2_size * L2_CACHE_SIZE * sizeof(uint64_t));
    if (s->l2_cache == NULL) {
        error_setg(errp, "Could not allocate L2 table cache");
        ret = -ENOMEM;
        goto fail;
    }
    s->cluster_cache = g_malloc(s->cluster_size);
    s->cluster_data = g_malloc(s->cluster_size);
    s->cluster_cache_offset = -1;

    /* read the backing file name */
    if (header.backing_file_offset != 0) {
        len = header.backing_file_size;
        if (len > 1023 || len >= sizeof(bs->backing_file)) {
            error_setg(errp, "Backing file name too long");
            ret = -EINVAL;
            goto fail;
        }
        ret = bdrv_pread(bs->file, header.backing_file_offset,
                   bs->backing_file, len);
        if (ret < 0) {
            goto fail;
        }
        bs->backing_file[len] = '\0';
    }

    /* Disable migration when qcow images are used */
    error_setg(&s->migration_blocker, "The qcow format used by node '%s' "
               "does not support live migration",
               bdrv_get_device_or_node_name(bs));
    ret = migrate_add_blocker(s->migration_blocker, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        error_free(s->migration_blocker);
        goto fail;
    }

    qemu_co_mutex_init(&s->lock);
    return 0;

 fail:
    g_free(s->l1_table);
    qemu_vfree(s->l2_cache);
    g_free(s->cluster_cache);
    g_free(s->cluster_data);
    return ret;
}


/* We have nothing to do for QCOW reopen, stubs just return
 * success */
static int qcow_reopen_prepare(BDRVReopenState *state,
                               BlockReopenQueue *queue, Error **errp)
{
    return 0;
}

static int qcow_set_key(BlockDriverState *bs, const char *key)
{
    BDRVQcowState *s = bs->opaque;
    uint8_t keybuf[16];
    int len, i;
    Error *err;

    memset(keybuf, 0, 16);
    len = strlen(key);
    if (len > 16)
        len = 16;
    /* XXX: we could compress the chars to 7 bits to increase
       entropy */
    for(i = 0;i < len;i++) {
        keybuf[i] = key[i];
    }
    assert(bs->encrypted);

    qcrypto_cipher_free(s->cipher);
    s->cipher = qcrypto_cipher_new(
        QCRYPTO_CIPHER_ALG_AES_128,
        QCRYPTO_CIPHER_MODE_CBC,
        keybuf, G_N_ELEMENTS(keybuf),
        &err);

    if (!s->cipher) {
        /* XXX would be nice if errors in this method could
         * be properly propagate to the caller. Would need
         * the bdrv_set_key() API signature to be fixed. */
        error_free(err);
        return -1;
    }
    return 0;
}

/* The crypt function is compatible with the linux cryptoloop
   algorithm for < 4 GB images. NOTE: out_buf == in_buf is
   supported */
static int encrypt_sectors(BDRVQcowState *s, int64_t sector_num,
                           uint8_t *out_buf, const uint8_t *in_buf,
                           int nb_sectors, bool enc, Error **errp)
{
    union {
        uint64_t ll[2];
        uint8_t b[16];
    } ivec;
    int i;
    int ret;

    for(i = 0; i < nb_sectors; i++) {
        ivec.ll[0] = cpu_to_le64(sector_num);
        ivec.ll[1] = 0;
        if (qcrypto_cipher_setiv(s->cipher,
                                 ivec.b, G_N_ELEMENTS(ivec.b),
                                 errp) < 0) {
            return -1;
        }
        if (enc) {
            ret = qcrypto_cipher_encrypt(s->cipher,
                                         in_buf,
                                         out_buf,
                                         512,
                                         errp);
        } else {
            ret = qcrypto_cipher_decrypt(s->cipher,
                                         in_buf,
                                         out_buf,
                                         512,
                                         errp);
        }
        if (ret < 0) {
            return -1;
        }
        sector_num++;
        in_buf += 512;
        out_buf += 512;
    }
    return 0;
}

/* 'allocate' is:
 *
 * 0 to not allocate.
 *
 * 1 to allocate a normal cluster (for sector indexes 'n_start' to
 * 'n_end')
 *
 * 2 to allocate a compressed cluster of size
 * 'compressed_size'. 'compressed_size' must be > 0 and <
 * cluster_size
 *
 * return 0 if not allocated.
 */
static uint64_t get_cluster_offset(BlockDriverState *bs,
                                   uint64_t offset, int allocate,
                                   int compressed_size,
                                   int n_start, int n_end)
{
    BDRVQcowState *s = bs->opaque;
    int min_index, i, j, l1_index, l2_index;
    uint64_t l2_offset, *l2_table, cluster_offset, tmp;
    uint32_t min_count;
    int new_l2_table;

    l1_index = offset >> (s->l2_bits + s->cluster_bits);
    l2_offset = s->l1_table[l1_index];
    new_l2_table = 0;
    if (!l2_offset) {
        if (!allocate)
            return 0;
        /* allocate a new l2 entry */
        l2_offset = bdrv_getlength(bs->file->bs);
        /* round to cluster size */
        l2_offset = (l2_offset + s->cluster_size - 1) & ~(s->cluster_size - 1);
        /* update the L1 entry */
        s->l1_table[l1_index] = l2_offset;
        tmp = cpu_to_be64(l2_offset);
        if (bdrv_pwrite_sync(bs->file,
                s->l1_table_offset + l1_index * sizeof(tmp),
                &tmp, sizeof(tmp)) < 0)
            return 0;
        new_l2_table = 1;
    }
    for(i = 0; i < L2_CACHE_SIZE; i++) {
        if (l2_offset == s->l2_cache_offsets[i]) {
            /* increment the hit count */
            if (++s->l2_cache_counts[i] == 0xffffffff) {
                for(j = 0; j < L2_CACHE_SIZE; j++) {
                    s->l2_cache_counts[j] >>= 1;
                }
            }
            l2_table = s->l2_cache + (i << s->l2_bits);
            goto found;
        }
    }
    /* not found: load a new entry in the least used one */
    min_index = 0;
    min_count = 0xffffffff;
    for(i = 0; i < L2_CACHE_SIZE; i++) {
        if (s->l2_cache_counts[i] < min_count) {
            min_count = s->l2_cache_counts[i];
            min_index = i;
        }
    }
    l2_table = s->l2_cache + (min_index << s->l2_bits);
    if (new_l2_table) {
        memset(l2_table, 0, s->l2_size * sizeof(uint64_t));
        if (bdrv_pwrite_sync(bs->file, l2_offset, l2_table,
                s->l2_size * sizeof(uint64_t)) < 0)
            return 0;
    } else {
        if (bdrv_pread(bs->file, l2_offset, l2_table,
                       s->l2_size * sizeof(uint64_t)) !=
            s->l2_size * sizeof(uint64_t))
            return 0;
    }
    s->l2_cache_offsets[min_index] = l2_offset;
    s->l2_cache_counts[min_index] = 1;
 found:
    l2_index = (offset >> s->cluster_bits) & (s->l2_size - 1);
    cluster_offset = be64_to_cpu(l2_table[l2_index]);
    if (!cluster_offset ||
        ((cluster_offset & QCOW_OFLAG_COMPRESSED) && allocate == 1)) {
        if (!allocate)
            return 0;
        /* allocate a new cluster */
        if ((cluster_offset & QCOW_OFLAG_COMPRESSED) &&
            (n_end - n_start) < s->cluster_sectors) {
            /* if the cluster is already compressed, we must
               decompress it in the case it is not completely
               overwritten */
            if (decompress_cluster(bs, cluster_offset) < 0)
                return 0;
            cluster_offset = bdrv_getlength(bs->file->bs);
            cluster_offset = (cluster_offset + s->cluster_size - 1) &
                ~(s->cluster_size - 1);
            /* write the cluster content */
            if (bdrv_pwrite(bs->file, cluster_offset, s->cluster_cache,
                            s->cluster_size) !=
                s->cluster_size)
                return -1;
        } else {
            cluster_offset = bdrv_getlength(bs->file->bs);
            if (allocate == 1) {
                /* round to cluster size */
                cluster_offset = (cluster_offset + s->cluster_size - 1) &
                    ~(s->cluster_size - 1);
                bdrv_truncate(bs->file, cluster_offset + s->cluster_size, NULL);
                /* if encrypted, we must initialize the cluster
                   content which won't be written */
                if (bs->encrypted &&
                    (n_end - n_start) < s->cluster_sectors) {
                    uint64_t start_sect;
                    assert(s->cipher);
                    start_sect = (offset & ~(s->cluster_size - 1)) >> 9;
                    memset(s->cluster_data + 512, 0x00, 512);
                    for(i = 0; i < s->cluster_sectors; i++) {
                        if (i < n_start || i >= n_end) {
                            Error *err = NULL;
                            if (encrypt_sectors(s, start_sect + i,
                                                s->cluster_data,
                                                s->cluster_data + 512, 1,
                                                true, &err) < 0) {
                                error_free(err);
                                errno = EIO;
                                return -1;
                            }
                            if (bdrv_pwrite(bs->file,
                                            cluster_offset + i * 512,
                                            s->cluster_data, 512) != 512)
                                return -1;
                        }
                    }
                }
            } else if (allocate == 2) {
                cluster_offset |= QCOW_OFLAG_COMPRESSED |
                    (uint64_t)compressed_size << (63 - s->cluster_bits);
            }
        }
        /* update L2 table */
        tmp = cpu_to_be64(cluster_offset);
        l2_table[l2_index] = tmp;
        if (bdrv_pwrite_sync(bs->file, l2_offset + l2_index * sizeof(tmp),
                &tmp, sizeof(tmp)) < 0)
            return 0;
    }
    return cluster_offset;
}

static int64_t coroutine_fn qcow_co_get_block_status(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors, int *pnum, BlockDriverState **file)
{
    BDRVQcowState *s = bs->opaque;
    int index_in_cluster, n;
    uint64_t cluster_offset;

    qemu_co_mutex_lock(&s->lock);
    cluster_offset = get_cluster_offset(bs, sector_num << 9, 0, 0, 0, 0);
    qemu_co_mutex_unlock(&s->lock);
    index_in_cluster = sector_num & (s->cluster_sectors - 1);
    n = s->cluster_sectors - index_in_cluster;
    if (n > nb_sectors)
        n = nb_sectors;
    *pnum = n;
    if (!cluster_offset) {
        return 0;
    }
    if ((cluster_offset & QCOW_OFLAG_COMPRESSED) || s->cipher) {
        return BDRV_BLOCK_DATA;
    }
    cluster_offset |= (index_in_cluster << BDRV_SECTOR_BITS);
    *file = bs->file->bs;
    return BDRV_BLOCK_DATA | BDRV_BLOCK_OFFSET_VALID | cluster_offset;
}

static int decompress_buffer(uint8_t *out_buf, int out_buf_size,
                             const uint8_t *buf, int buf_size)
{
    z_stream strm1, *strm = &strm1;
    int ret, out_len;

    memset(strm, 0, sizeof(*strm));

    strm->next_in = (uint8_t *)buf;
    strm->avail_in = buf_size;
    strm->next_out = out_buf;
    strm->avail_out = out_buf_size;

    ret = inflateInit2(strm, -12);
    if (ret != Z_OK)
        return -1;
    ret = inflate(strm, Z_FINISH);
    out_len = strm->next_out - out_buf;
    if ((ret != Z_STREAM_END && ret != Z_BUF_ERROR) ||
        out_len != out_buf_size) {
        inflateEnd(strm);
        return -1;
    }
    inflateEnd(strm);
    return 0;
}

static int decompress_cluster(BlockDriverState *bs, uint64_t cluster_offset)
{
    BDRVQcowState *s = bs->opaque;
    int ret, csize;
    uint64_t coffset;

    coffset = cluster_offset & s->cluster_offset_mask;
    if (s->cluster_cache_offset != coffset) {
        csize = cluster_offset >> (63 - s->cluster_bits);
        csize &= (s->cluster_size - 1);
        ret = bdrv_pread(bs->file, coffset, s->cluster_data, csize);
        if (ret != csize)
            return -1;
        if (decompress_buffer(s->cluster_cache, s->cluster_size,
                              s->cluster_data, csize) < 0) {
            return -1;
        }
        s->cluster_cache_offset = coffset;
    }
    return 0;
}

static coroutine_fn int qcow_co_readv(BlockDriverState *bs, int64_t sector_num,
                         int nb_sectors, QEMUIOVector *qiov)
{
    BDRVQcowState *s = bs->opaque;
    int index_in_cluster;
    int ret = 0, n;
    uint64_t cluster_offset;
    struct iovec hd_iov;
    QEMUIOVector hd_qiov;
    uint8_t *buf;
    void *orig_buf;
    Error *err = NULL;

    if (qiov->niov > 1) {
        buf = orig_buf = qemu_try_blockalign(bs, qiov->size);
        if (buf == NULL) {
            return -ENOMEM;
        }
    } else {
        orig_buf = NULL;
        buf = (uint8_t *)qiov->iov->iov_base;
    }

    qemu_co_mutex_lock(&s->lock);

    while (nb_sectors != 0) {
        /* prepare next request */
        cluster_offset = get_cluster_offset(bs, sector_num << 9,
                                                 0, 0, 0, 0);
        index_in_cluster = sector_num & (s->cluster_sectors - 1);
        n = s->cluster_sectors - index_in_cluster;
        if (n > nb_sectors) {
            n = nb_sectors;
        }

        if (!cluster_offset) {
            if (bs->backing) {
                /* read from the base image */
                hd_iov.iov_base = (void *)buf;
                hd_iov.iov_len = n * 512;
                qemu_iovec_init_external(&hd_qiov, &hd_iov, 1);
                qemu_co_mutex_unlock(&s->lock);
                ret = bdrv_co_readv(bs->backing, sector_num, n, &hd_qiov);
                qemu_co_mutex_lock(&s->lock);
                if (ret < 0) {
                    goto fail;
                }
            } else {
                /* Note: in this case, no need to wait */
                memset(buf, 0, 512 * n);
            }
        } else if (cluster_offset & QCOW_OFLAG_COMPRESSED) {
            /* add AIO support for compressed blocks ? */
            if (decompress_cluster(bs, cluster_offset) < 0) {
                goto fail;
            }
            memcpy(buf,
                   s->cluster_cache + index_in_cluster * 512, 512 * n);
        } else {
            if ((cluster_offset & 511) != 0) {
                goto fail;
            }
            hd_iov.iov_base = (void *)buf;
            hd_iov.iov_len = n * 512;
            qemu_iovec_init_external(&hd_qiov, &hd_iov, 1);
            qemu_co_mutex_unlock(&s->lock);
            ret = bdrv_co_readv(bs->file,
                                (cluster_offset >> 9) + index_in_cluster,
                                n, &hd_qiov);
            qemu_co_mutex_lock(&s->lock);
            if (ret < 0) {
                break;
            }
            if (bs->encrypted) {
                assert(s->cipher);
                if (encrypt_sectors(s, sector_num, buf, buf,
                                    n, false, &err) < 0) {
                    goto fail;
                }
            }
        }
        ret = 0;

        nb_sectors -= n;
        sector_num += n;
        buf += n * 512;
    }

done:
    qemu_co_mutex_unlock(&s->lock);

    if (qiov->niov > 1) {
        qemu_iovec_from_buf(qiov, 0, orig_buf, qiov->size);
        qemu_vfree(orig_buf);
    }

    return ret;

fail:
    error_free(err);
    ret = -EIO;
    goto done;
}

static coroutine_fn int qcow_co_writev(BlockDriverState *bs, int64_t sector_num,
                          int nb_sectors, QEMUIOVector *qiov)
{
    BDRVQcowState *s = bs->opaque;
    int index_in_cluster;
    uint64_t cluster_offset;
    const uint8_t *src_buf;
    int ret = 0, n;
    uint8_t *cluster_data = NULL;
    struct iovec hd_iov;
    QEMUIOVector hd_qiov;
    uint8_t *buf;
    void *orig_buf;

    s->cluster_cache_offset = -1; /* disable compressed cache */

    if (qiov->niov > 1) {
        buf = orig_buf = qemu_try_blockalign(bs, qiov->size);
        if (buf == NULL) {
            return -ENOMEM;
        }
        qemu_iovec_to_buf(qiov, 0, buf, qiov->size);
    } else {
        orig_buf = NULL;
        buf = (uint8_t *)qiov->iov->iov_base;
    }

    qemu_co_mutex_lock(&s->lock);

    while (nb_sectors != 0) {

        index_in_cluster = sector_num & (s->cluster_sectors - 1);
        n = s->cluster_sectors - index_in_cluster;
        if (n > nb_sectors) {
            n = nb_sectors;
        }
        cluster_offset = get_cluster_offset(bs, sector_num << 9, 1, 0,
                                            index_in_cluster,
                                            index_in_cluster + n);
        if (!cluster_offset || (cluster_offset & 511) != 0) {
            ret = -EIO;
            break;
        }
        if (bs->encrypted) {
            Error *err = NULL;
            assert(s->cipher);
            if (!cluster_data) {
                cluster_data = g_malloc0(s->cluster_size);
            }
            if (encrypt_sectors(s, sector_num, cluster_data, buf,
                                n, true, &err) < 0) {
                error_free(err);
                ret = -EIO;
                break;
            }
            src_buf = cluster_data;
        } else {
            src_buf = buf;
        }

        hd_iov.iov_base = (void *)src_buf;
        hd_iov.iov_len = n * 512;
        qemu_iovec_init_external(&hd_qiov, &hd_iov, 1);
        qemu_co_mutex_unlock(&s->lock);
        ret = bdrv_co_writev(bs->file,
                             (cluster_offset >> 9) + index_in_cluster,
                             n, &hd_qiov);
        qemu_co_mutex_lock(&s->lock);
        if (ret < 0) {
            break;
        }
        ret = 0;

        nb_sectors -= n;
        sector_num += n;
        buf += n * 512;
    }
    qemu_co_mutex_unlock(&s->lock);

    if (qiov->niov > 1) {
        qemu_vfree(orig_buf);
    }
    g_free(cluster_data);

    return ret;
}

static void qcow_close(BlockDriverState *bs)
{
    BDRVQcowState *s = bs->opaque;

    qcrypto_cipher_free(s->cipher);
    s->cipher = NULL;
    g_free(s->l1_table);
    qemu_vfree(s->l2_cache);
    g_free(s->cluster_cache);
    g_free(s->cluster_data);

    migrate_del_blocker(s->migration_blocker);
    error_free(s->migration_blocker);
}

static int qcow_create(const char *filename, QemuOpts *opts, Error **errp)
{
    int header_size, backing_filename_len, l1_size, shift, i;
    QCowHeader header;
    uint8_t *tmp;
    int64_t total_size = 0;
    char *backing_file = NULL;
    int flags = 0;
    Error *local_err = NULL;
    int ret;
    BlockBackend *qcow_blk;

    /* Read out options */
    total_size = ROUND_UP(qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0),
                          BDRV_SECTOR_SIZE);
    backing_file = qemu_opt_get_del(opts, BLOCK_OPT_BACKING_FILE);
    if (qemu_opt_get_bool_del(opts, BLOCK_OPT_ENCRYPT, false)) {
        flags |= BLOCK_FLAG_ENCRYPT;
    }

    ret = bdrv_create_file(filename, opts, &local_err);
    if (ret < 0) {
        error_propagate(errp, local_err);
        goto cleanup;
    }

    qcow_blk = blk_new_open(filename, NULL, NULL,
                            BDRV_O_RDWR | BDRV_O_RESIZE | BDRV_O_PROTOCOL,
                            &local_err);
    if (qcow_blk == NULL) {
        error_propagate(errp, local_err);
        ret = -EIO;
        goto cleanup;
    }

    blk_set_allow_write_beyond_eof(qcow_blk, true);

    ret = blk_truncate(qcow_blk, 0, errp);
    if (ret < 0) {
        goto exit;
    }

    memset(&header, 0, sizeof(header));
    header.magic = cpu_to_be32(QCOW_MAGIC);
    header.version = cpu_to_be32(QCOW_VERSION);
    header.size = cpu_to_be64(total_size);
    header_size = sizeof(header);
    backing_filename_len = 0;
    if (backing_file) {
        if (strcmp(backing_file, "fat:")) {
            header.backing_file_offset = cpu_to_be64(header_size);
            backing_filename_len = strlen(backing_file);
            header.backing_file_size = cpu_to_be32(backing_filename_len);
            header_size += backing_filename_len;
        } else {
            /* special backing file for vvfat */
            backing_file = NULL;
        }
        header.cluster_bits = 9; /* 512 byte cluster to avoid copying
                                    unmodified sectors */
        header.l2_bits = 12; /* 32 KB L2 tables */
    } else {
        header.cluster_bits = 12; /* 4 KB clusters */
        header.l2_bits = 9; /* 4 KB L2 tables */
    }
    header_size = (header_size + 7) & ~7;
    shift = header.cluster_bits + header.l2_bits;
    l1_size = (total_size + (1LL << shift) - 1) >> shift;

    header.l1_table_offset = cpu_to_be64(header_size);
    if (flags & BLOCK_FLAG_ENCRYPT) {
        header.crypt_method = cpu_to_be32(QCOW_CRYPT_AES);
    } else {
        header.crypt_method = cpu_to_be32(QCOW_CRYPT_NONE);
    }

    /* write all the data */
    ret = blk_pwrite(qcow_blk, 0, &header, sizeof(header), 0);
    if (ret != sizeof(header)) {
        goto exit;
    }

    if (backing_file) {
        ret = blk_pwrite(qcow_blk, sizeof(header),
                         backing_file, backing_filename_len, 0);
        if (ret != backing_filename_len) {
            goto exit;
        }
    }

    tmp = g_malloc0(BDRV_SECTOR_SIZE);
    for (i = 0; i < DIV_ROUND_UP(sizeof(uint64_t) * l1_size, BDRV_SECTOR_SIZE);
         i++) {
        ret = blk_pwrite(qcow_blk, header_size + BDRV_SECTOR_SIZE * i,
                         tmp, BDRV_SECTOR_SIZE, 0);
        if (ret != BDRV_SECTOR_SIZE) {
            g_free(tmp);
            goto exit;
        }
    }

    g_free(tmp);
    ret = 0;
exit:
    blk_unref(qcow_blk);
cleanup:
    g_free(backing_file);
    return ret;
}

static int qcow_make_empty(BlockDriverState *bs)
{
    BDRVQcowState *s = bs->opaque;
    uint32_t l1_length = s->l1_size * sizeof(uint64_t);
    int ret;

    memset(s->l1_table, 0, l1_length);
    if (bdrv_pwrite_sync(bs->file, s->l1_table_offset, s->l1_table,
            l1_length) < 0)
        return -1;
    ret = bdrv_truncate(bs->file, s->l1_table_offset + l1_length, NULL);
    if (ret < 0)
        return ret;

    memset(s->l2_cache, 0, s->l2_size * L2_CACHE_SIZE * sizeof(uint64_t));
    memset(s->l2_cache_offsets, 0, L2_CACHE_SIZE * sizeof(uint64_t));
    memset(s->l2_cache_counts, 0, L2_CACHE_SIZE * sizeof(uint32_t));

    return 0;
}

/* XXX: put compressed sectors first, then all the cluster aligned
   tables to avoid losing bytes in alignment */
static coroutine_fn int
qcow_co_pwritev_compressed(BlockDriverState *bs, uint64_t offset,
                           uint64_t bytes, QEMUIOVector *qiov)
{
    BDRVQcowState *s = bs->opaque;
    QEMUIOVector hd_qiov;
    struct iovec iov;
    z_stream strm;
    int ret, out_len;
    uint8_t *buf, *out_buf;
    uint64_t cluster_offset;

    buf = qemu_blockalign(bs, s->cluster_size);
    if (bytes != s->cluster_size) {
        if (bytes > s->cluster_size ||
            offset + bytes != bs->total_sectors << BDRV_SECTOR_BITS)
        {
            qemu_vfree(buf);
            return -EINVAL;
        }
        /* Zero-pad last write if image size is not cluster aligned */
        memset(buf + bytes, 0, s->cluster_size - bytes);
    }
    qemu_iovec_to_buf(qiov, 0, buf, qiov->size);

    out_buf = g_malloc(s->cluster_size);

    /* best compression, small window, no zlib header */
    memset(&strm, 0, sizeof(strm));
    ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION,
                       Z_DEFLATED, -12,
                       9, Z_DEFAULT_STRATEGY);
    if (ret != 0) {
        ret = -EINVAL;
        goto fail;
    }

    strm.avail_in = s->cluster_size;
    strm.next_in = (uint8_t *)buf;
    strm.avail_out = s->cluster_size;
    strm.next_out = out_buf;

    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        deflateEnd(&strm);
        ret = -EINVAL;
        goto fail;
    }
    out_len = strm.next_out - out_buf;

    deflateEnd(&strm);

    if (ret != Z_STREAM_END || out_len >= s->cluster_size) {
        /* could not compress: write normal cluster */
        ret = qcow_co_writev(bs, offset >> BDRV_SECTOR_BITS,
                             bytes >> BDRV_SECTOR_BITS, qiov);
        if (ret < 0) {
            goto fail;
        }
        goto success;
    }
    qemu_co_mutex_lock(&s->lock);
    cluster_offset = get_cluster_offset(bs, offset, 2, out_len, 0, 0);
    qemu_co_mutex_unlock(&s->lock);
    if (cluster_offset == 0) {
        ret = -EIO;
        goto fail;
    }
    cluster_offset &= s->cluster_offset_mask;

    iov = (struct iovec) {
        .iov_base   = out_buf,
        .iov_len    = out_len,
    };
    qemu_iovec_init_external(&hd_qiov, &iov, 1);
    ret = bdrv_co_pwritev(bs->file, cluster_offset, out_len, &hd_qiov, 0);
    if (ret < 0) {
        goto fail;
    }
success:
    ret = 0;
fail:
    qemu_vfree(buf);
    g_free(out_buf);
    return ret;
}

static int qcow_get_info(BlockDriverState *bs, BlockDriverInfo *bdi)
{
    BDRVQcowState *s = bs->opaque;
    bdi->cluster_size = s->cluster_size;
    return 0;
}

static QemuOptsList qcow_create_opts = {
    .name = "qcow-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(qcow_create_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "Virtual disk size"
        },
        {
            .name = BLOCK_OPT_BACKING_FILE,
            .type = QEMU_OPT_STRING,
            .help = "File name of a base image"
        },
        {
            .name = BLOCK_OPT_ENCRYPT,
            .type = QEMU_OPT_BOOL,
            .help = "Encrypt the image",
            .def_value_str = "off"
        },
        { /* end of list */ }
    }
};

static BlockDriver bdrv_qcow = {
    .format_name	= "qcow",
    .instance_size	= sizeof(BDRVQcowState),
    .bdrv_probe		= qcow_probe,
    .bdrv_open		= qcow_open,
    .bdrv_close		= qcow_close,
    .bdrv_child_perm        = bdrv_format_default_perms,
    .bdrv_reopen_prepare    = qcow_reopen_prepare,
    .bdrv_create            = qcow_create,
    .bdrv_has_zero_init     = bdrv_has_zero_init_1,
    .supports_backing       = true,

    .bdrv_co_readv          = qcow_co_readv,
    .bdrv_co_writev         = qcow_co_writev,
    .bdrv_co_get_block_status   = qcow_co_get_block_status,

    .bdrv_set_key           = qcow_set_key,
    .bdrv_make_empty        = qcow_make_empty,
    .bdrv_co_pwritev_compressed = qcow_co_pwritev_compressed,
    .bdrv_get_info          = qcow_get_info,

    .create_opts            = &qcow_create_opts,
};

static void bdrv_qcow_init(void)
{
    bdrv_register(&bdrv_qcow);
}

block_init(bdrv_qcow_init);
