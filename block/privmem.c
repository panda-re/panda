/*
 * non-persistent / private memory block driver, COW on fork
 *
 * Authors:
 *  Ryan Hileman <lunixbochs@gmail.com>
 *
 * Copyright (C) 2016 Ryan Hileman
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include <sys/mman.h>

#include "block/block.h"
#include "block/block_int.h"
#include "qapi/error.h"
#include "qapi/qmp/qerror.h"
#include "qemu/error-report.h"

typedef struct {
    int fd;
    char *buf;
    size_t size;
} BDRVCOWState;

static QemuOptsList runtime_opts = {
    .name = "privmem",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = "filename",
            .type = QEMU_OPT_STRING,
            .help = "",
        },
        { /* end of list */ }
    },
};

static int privmem_file_open(BlockDriverState *bs, QDict *options, int flags,
                          Error **errp)
{
    QemuOpts *opts;
    BDRVCOWState *s = bs->opaque;
    const char *filename, *p;
    struct stat sb;
    int ret = 0;

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &error_abort);
    filename = qemu_opt_get(opts, "filename");
    if (error_abort) {
        error_propagate(errp, error_abort);
        ret = -EINVAL;
        goto fail;
    }

    /* strip "privmem:". XXX whats the proper way to handle this? */
    p = strchr(filename, ':');
    if(p)
        filename = p + 1;

    s->fd = qemu_open(filename, O_RDONLY);
    if (fstat(s->fd, &sb) == -1 || !S_ISREG(sb.st_mode)) {
        perror(filename);
        ret = -EINVAL;
        goto fail;
    }
    s->size = sb.st_size;
    s->buf = mmap(0, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, s->fd, 0);
    if (s->buf == MAP_FAILED) {
        perror("mmap");
        ret = -EINVAL;
        goto fail;
    }

fail:
    qemu_opts_del(opts);
    return ret;
}

static void privmem_close(BlockDriverState *bs)
{
    BDRVCOWState *s = bs->opaque;
    munmap(s->buf, s->size);
    close(s->fd);
}

static int64_t privmem_getlength(BlockDriverState *bs)
{
    BDRVCOWState *s = bs->opaque;
    return s->size;
}

static coroutine_fn int privmem_read(BlockDriverState *bs,
                                    int64_t sector_num, uint8_t *buf, int nb_sectors)
{
    BDRVCOWState *s = bs->opaque;
    int64_t i, bufoff, imgoff, dist;
    for (i = 0; i < nb_sectors; i++) {
        imgoff = (sector_num + i) * 0x200;
        bufoff = i * 0x200;
        if (imgoff >= s->size - 0x200) {
            dist = s->size - imgoff;
            memcpy(buf + bufoff, s->buf + imgoff, dist);
            memset(buf + bufoff + dist, 0, 0x200 - dist);
        } else if (imgoff >= s->size) {
            memset(buf + bufoff, 0, 0x200);
        } else {
            memcpy(buf + bufoff, s->buf + imgoff, 0x200);
        }
    }
    return 0;
}

static coroutine_fn int privmem_write(BlockDriverState *bs,
                                      int64_t sector_num, const uint8_t *buf, int nb_sectors)
{
    BDRVCOWState *s = bs->opaque;
    int64_t i, bufoff, imgoff, dist;
    for (i = 0; i < nb_sectors; i++) {
        imgoff = (sector_num + i) * 0x200;
        bufoff = i * 0x200;
        if (imgoff >= s->size - 0x200) {
            dist = s->size - imgoff;
            memcpy(s->buf + imgoff, buf + bufoff, dist);
        } else if (imgoff < s->size) {
            memcpy(s->buf + imgoff, buf + bufoff, 0x200);
        }
    }
    return 0;
}

static BlockDriver bdrv_privmem = {
    .format_name            = "privmem",
    .protocol_name          = "privmem",
    .instance_size          = sizeof(BDRVCOWState),

    .bdrv_file_open         = privmem_file_open,
    .bdrv_close             = privmem_close,
    .bdrv_getlength         = privmem_getlength,

    // TODO: integrate privmem_read/write
    //.bdrv_read              = privmem_read,
    //.bdrv_write             = privmem_write,
};

static void bdrv_privmem_init(void)
{
    bdrv_register(&bdrv_privmem);
}

block_init(bdrv_privmem_init);
