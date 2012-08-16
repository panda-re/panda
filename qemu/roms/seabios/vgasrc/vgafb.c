// Code for manipulating VGA framebuffers.
//
// Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2001-2008 the LGPL VGABios developers Team
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "util.h" // memset_far
#include "vgatables.h" // find_vga_entry


/****************************************************************
 * Screen scrolling
 ****************************************************************/

static inline void *
memcpy_stride(u16 seg, void *dst, void *src, int copylen, int stride, int lines)
{
    for (; lines; lines--, dst+=stride, src+=stride)
        memcpy_far(seg, dst, seg, src, copylen);
    return dst;
}

static inline void
memset_stride(u16 seg, void *dst, u8 val, int setlen, int stride, int lines)
{
    for (; lines; lines--, dst+=stride)
        memset_far(seg, dst, val, setlen);
}

static inline void
memset16_stride(u16 seg, void *dst, u16 val, int setlen, int stride, int lines)
{
    for (; lines; lines--, dst+=stride)
        memset16_far(seg, dst, val, setlen);
}

static void
scroll_pl4(struct vgamode_s *vmode_g, int nblines, int attr
           , struct cursorpos ul, struct cursorpos lr)
{
    struct VideoParam_s *vparam_g = GET_GLOBAL(vmode_g->vparam);
    u8 cheight = GET_GLOBAL(vparam_g->cheight);
    int stride = GET_BDA(video_cols);
    void *src_far, *dest_far;
    if (nblines >= 0) {
        dest_far = (void*)(ul.y * cheight * stride + ul.x);
        src_far = dest_far + nblines * cheight * stride;
    } else {
        // Scroll down
        nblines = -nblines;
        dest_far = (void*)(lr.y * cheight * stride + ul.x);
        src_far = dest_far - nblines * cheight * stride;
        stride = -stride;
    }
    int cols = lr.x - ul.x + 1;
    int rows = lr.y - ul.y + 1;
    if (nblines < rows) {
        vgahw_grdc_write(0x05, 0x01);
        dest_far = memcpy_stride(SEG_GRAPH, dest_far, src_far, cols, stride
                                 , (rows - nblines) * cheight);
    }
    if (attr < 0)
        attr = 0;
    vgahw_grdc_write(0x05, 0x02);
    memset_stride(SEG_GRAPH, dest_far, attr, cols, stride, nblines * cheight);
    vgahw_grdc_write(0x05, 0x00);
}

static void
scroll_cga(struct vgamode_s *vmode_g, int nblines, int attr
            , struct cursorpos ul, struct cursorpos lr)
{
    struct VideoParam_s *vparam_g = GET_GLOBAL(vmode_g->vparam);
    u8 cheight = GET_GLOBAL(vparam_g->cheight);
    u8 bpp = GET_GLOBAL(vmode_g->pixbits);
    int stride = GET_BDA(video_cols) * bpp;
    void *src_far, *dest_far;
    if (nblines >= 0) {
        dest_far = (void*)(ul.y * cheight * stride + ul.x * bpp);
        src_far = dest_far + nblines * cheight * stride;
    } else {
        // Scroll down
        nblines = -nblines;
        dest_far = (void*)(lr.y * cheight * stride + ul.x * bpp);
        src_far = dest_far - nblines * cheight * stride;
        stride = -stride;
    }
    int cols = (lr.x - ul.x + 1) * bpp;
    int rows = lr.y - ul.y + 1;
    if (nblines < rows) {
        memcpy_stride(SEG_CTEXT, dest_far + 0x2000, src_far + 0x2000, cols
                      , stride, (rows - nblines) * cheight / 2);
        dest_far = memcpy_stride(SEG_CTEXT, dest_far, src_far, cols
                                 , stride, (rows - nblines) * cheight / 2);
    }
    if (attr < 0)
        attr = 0;
    memset_stride(SEG_CTEXT, dest_far + 0x2000, attr, cols
                  , stride, nblines * cheight / 2);
    memset_stride(SEG_CTEXT, dest_far, attr, cols
                  , stride, nblines * cheight / 2);
}

static void
scroll_text(struct vgamode_s *vmode_g, int nblines, int attr
            , struct cursorpos ul, struct cursorpos lr)
{
    u16 nbrows = GET_BDA(video_rows) + 1;
    u16 nbcols = GET_BDA(video_cols);
    void *src_far, *dest_far = (void*)SCREEN_MEM_START(nbcols, nbrows, ul.page);
    int stride = nbcols * 2;
    if (nblines >= 0) {
        dest_far += ul.y * stride + ul.x * 2;
        src_far = dest_far + nblines * stride;
    } else {
        // Scroll down
        nblines = -nblines;
        dest_far += lr.y * stride + ul.x * 2;
        src_far = dest_far - nblines * stride;
        stride = -stride;
    }
    int cols = (lr.x - ul.x + 1) * 2;
    int rows = lr.y - ul.y + 1;
    u16 seg = GET_GLOBAL(vmode_g->sstart);
    if (nblines < rows)
        dest_far = memcpy_stride(seg, dest_far, src_far, cols, stride
                                 , (rows - nblines));
    if (attr < 0)
        attr = 0x07;
    attr = (attr << 8) | ' ';
    memset16_stride(seg, dest_far, attr, cols, stride, nblines);
}

void
vgafb_scroll(int nblines, int attr, struct cursorpos ul, struct cursorpos lr)
{
    // Get the mode
    struct vgamode_s *vmode_g = find_vga_entry(GET_BDA(video_mode));
    if (!vmode_g)
        return;

    // FIXME gfx mode not complete
    switch (GET_GLOBAL(vmode_g->memmodel)) {
    case CTEXT:
    case MTEXT:
        scroll_text(vmode_g, nblines, attr, ul, lr);
        break;
    case PLANAR4:
    case PLANAR1:
        scroll_pl4(vmode_g, nblines, attr, ul, lr);
        break;
    case CGA:
        scroll_cga(vmode_g, nblines, attr, ul, lr);
        break;
    default:
        dprintf(1, "Scroll in graphics mode\n");
    }
}

void
clear_screen(struct vgamode_s *vmode_g)
{
    switch (GET_GLOBAL(vmode_g->memmodel)) {
    case CTEXT:
    case MTEXT:
        memset16_far(GET_GLOBAL(vmode_g->sstart), 0, 0x0720, 32*1024);
        break;
    case CGA:
        memset16_far(GET_GLOBAL(vmode_g->sstart), 0, 0x0000, 32*1024);
        break;
    default:
        // XXX - old code gets/sets/restores sequ register 2 to 0xf -
        // but it should always be 0xf anyway.
        memset16_far(GET_GLOBAL(vmode_g->sstart), 0, 0x0000, 64*1024);
    }
}


/****************************************************************
 * Read/write characters to screen
 ****************************************************************/

static void
write_gfx_char_pl4(struct vgamode_s *vmode_g
                   , struct cursorpos cp, struct carattr ca)
{
    u16 nbcols = GET_BDA(video_cols);
    if (cp.x >= nbcols)
        return;

    struct VideoParam_s *vparam_g = GET_GLOBAL(vmode_g->vparam);
    u8 cheight = GET_GLOBAL(vparam_g->cheight);
    u8 *fdata_g;
    switch (cheight) {
    case 14:
        fdata_g = vgafont14;
        break;
    case 16:
        fdata_g = vgafont16;
        break;
    default:
        fdata_g = vgafont8;
    }
    u16 addr = cp.x + cp.y * cheight * nbcols;
    u16 src = ca.car * cheight;
    vgahw_sequ_write(0x02, 0x0f);
    vgahw_grdc_write(0x05, 0x02);
    if (ca.attr & 0x80)
        vgahw_grdc_write(0x03, 0x18);
    else
        vgahw_grdc_write(0x03, 0x00);
    u8 i;
    for (i = 0; i < cheight; i++) {
        u8 *dest_far = (void*)(addr + i * nbcols);
        u8 j;
        for (j = 0; j < 8; j++) {
            u8 mask = 0x80 >> j;
            vgahw_grdc_write(0x08, mask);
            GET_FARVAR(SEG_GRAPH, *dest_far);
            if (GET_GLOBAL(fdata_g[src + i]) & mask)
                SET_FARVAR(SEG_GRAPH, *dest_far, ca.attr & 0x0f);
            else
                SET_FARVAR(SEG_GRAPH, *dest_far, 0x00);
        }
    }
    vgahw_grdc_write(0x08, 0xff);
    vgahw_grdc_write(0x05, 0x00);
    vgahw_grdc_write(0x03, 0x00);
}

static void
write_gfx_char_cga(struct vgamode_s *vmode_g
                   , struct cursorpos cp, struct carattr ca)
{
    u16 nbcols = GET_BDA(video_cols);
    if (cp.x >= nbcols)
        return;

    u8 *fdata_g = vgafont8;
    u8 bpp = GET_GLOBAL(vmode_g->pixbits);
    u16 addr = (cp.x * bpp) + cp.y * 320;
    u16 src = ca.car * 8;
    u8 i;
    for (i = 0; i < 8; i++) {
        u8 *dest_far = (void*)(addr + (i >> 1) * 80);
        if (i & 1)
            dest_far += 0x2000;
        u8 mask = 0x80;
        if (bpp == 1) {
            u8 data = 0;
            if (ca.attr & 0x80)
                data = GET_FARVAR(SEG_CTEXT, *dest_far);
            u8 j;
            for (j = 0; j < 8; j++) {
                if (GET_GLOBAL(fdata_g[src + i]) & mask) {
                    if (ca.attr & 0x80)
                        data ^= (ca.attr & 0x01) << (7 - j);
                    else
                        data |= (ca.attr & 0x01) << (7 - j);
                }
                mask >>= 1;
            }
            SET_FARVAR(SEG_CTEXT, *dest_far, data);
        } else {
            while (mask > 0) {
                u8 data = 0;
                if (ca.attr & 0x80)
                    data = GET_FARVAR(SEG_CTEXT, *dest_far);
                u8 j;
                for (j = 0; j < 4; j++) {
                    if (GET_GLOBAL(fdata_g[src + i]) & mask) {
                        if (ca.attr & 0x80)
                            data ^= (ca.attr & 0x03) << ((3 - j) * 2);
                        else
                            data |= (ca.attr & 0x03) << ((3 - j) * 2);
                    }
                    mask >>= 1;
                }
                SET_FARVAR(SEG_CTEXT, *dest_far, data);
                dest_far += 1;
            }
        }
    }
}

static void
write_gfx_char_lin(struct vgamode_s *vmode_g
                   , struct cursorpos cp, struct carattr ca)
{
    // Get the dimensions
    u16 nbcols = GET_BDA(video_cols);
    if (cp.x >= nbcols)
        return;

    u8 *fdata_g = vgafont8;
    u16 addr = cp.x * 8 + cp.y * nbcols * 64;
    u16 src = ca.car * 8;
    u8 i;
    for (i = 0; i < 8; i++) {
        u8 *dest_far = (void*)(addr + i * nbcols * 8);
        u8 mask = 0x80;
        u8 j;
        for (j = 0; j < 8; j++) {
            u8 data = 0x00;
            if (GET_GLOBAL(fdata_g[src + i]) & mask)
                data = ca.attr;
            SET_FARVAR(SEG_GRAPH, dest_far[j], data);
            mask >>= 1;
        }
    }
}

static void
write_text_char(struct vgamode_s *vmode_g
                , struct cursorpos cp, struct carattr ca)
{
    // Get the dimensions
    u16 nbrows = GET_BDA(video_rows) + 1;
    u16 nbcols = GET_BDA(video_cols);

    // Compute the address
    void *address_far = (void*)(SCREEN_MEM_START(nbcols, nbrows, cp.page)
                                + (cp.x + cp.y * nbcols) * 2);

    if (ca.use_attr) {
        u16 dummy = (ca.attr << 8) | ca.car;
        SET_FARVAR(GET_GLOBAL(vmode_g->sstart), *(u16*)address_far, dummy);
    } else {
        SET_FARVAR(GET_GLOBAL(vmode_g->sstart), *(u8*)address_far, ca.car);
    }
}

void
vgafb_write_char(struct cursorpos cp, struct carattr ca)
{
    // Get the mode
    struct vgamode_s *vmode_g = find_vga_entry(GET_BDA(video_mode));
    if (!vmode_g)
        return;

    // FIXME gfx mode not complete
    switch (GET_GLOBAL(vmode_g->memmodel)) {
    case CTEXT:
    case MTEXT:
        write_text_char(vmode_g, cp, ca);
        break;
    case PLANAR4:
    case PLANAR1:
        write_gfx_char_pl4(vmode_g, cp, ca);
        break;
    case CGA:
        write_gfx_char_cga(vmode_g, cp, ca);
        break;
    case LINEAR8:
        write_gfx_char_lin(vmode_g, cp, ca);
        break;
    }
}

struct carattr
vgafb_read_char(struct cursorpos cp)
{
    // Get the mode
    struct vgamode_s *vmode_g = find_vga_entry(GET_BDA(video_mode));
    if (!vmode_g)
        goto fail;

    if (!(GET_GLOBAL(vmode_g->memmodel) & TEXT)) {
        // FIXME gfx mode
        dprintf(1, "Read char in graphics mode\n");
        goto fail;
    }

    // Get the dimensions
    u16 nbrows = GET_BDA(video_rows) + 1;
    u16 nbcols = GET_BDA(video_cols);

    // Compute the address
    u16 *address_far = (void*)(SCREEN_MEM_START(nbcols, nbrows, cp.page)
                               + (cp.x + cp.y * nbcols) * 2);
    u16 v = GET_FARVAR(GET_GLOBAL(vmode_g->sstart), *address_far);
    struct carattr ca = {v, v>>8, 0};
    return ca;

fail: ;
    struct carattr ca2 = {0, 0, 0};
    return ca2;
}


/****************************************************************
 * Read/write pixels
 ****************************************************************/

void
vgafb_write_pixel(u8 color, u16 x, u16 y)
{
    // Get the mode
    struct vgamode_s *vmode_g = find_vga_entry(GET_BDA(video_mode));
    if (!vmode_g)
        return;
    if (GET_GLOBAL(vmode_g->memmodel) & TEXT)
        return;

    u8 *addr_far, mask, attr, data;
    switch (GET_GLOBAL(vmode_g->memmodel)) {
    case PLANAR4:
    case PLANAR1:
        addr_far = (void*)(x / 8 + y * GET_BDA(video_cols));
        mask = 0x80 >> (x & 0x07);
        vgahw_grdc_write(0x08, mask);
        vgahw_grdc_write(0x05, 0x02);
        data = GET_FARVAR(SEG_GRAPH, *addr_far);
        if (color & 0x80)
            vgahw_grdc_write(0x03, 0x18);
        SET_FARVAR(SEG_GRAPH, *addr_far, color);
        vgahw_grdc_write(0x08, 0xff);
        vgahw_grdc_write(0x05, 0x00);
        vgahw_grdc_write(0x03, 0x00);
        break;
    case CGA:
        if (GET_GLOBAL(vmode_g->pixbits) == 2)
            addr_far = (void*)((x >> 2) + (y >> 1) * 80);
        else
            addr_far = (void*)((x >> 3) + (y >> 1) * 80);
        if (y & 1)
            addr_far += 0x2000;
        data = GET_FARVAR(SEG_CTEXT, *addr_far);
        if (GET_GLOBAL(vmode_g->pixbits) == 2) {
            attr = (color & 0x03) << ((3 - (x & 0x03)) * 2);
            mask = 0x03 << ((3 - (x & 0x03)) * 2);
        } else {
            attr = (color & 0x01) << (7 - (x & 0x07));
            mask = 0x01 << (7 - (x & 0x07));
        }
        if (color & 0x80) {
            data ^= attr;
        } else {
            data &= ~mask;
            data |= attr;
        }
        SET_FARVAR(SEG_CTEXT, *addr_far, data);
        break;
    case LINEAR8:
        addr_far = (void*)(x + y * (GET_BDA(video_cols) * 8));
        SET_FARVAR(SEG_GRAPH, *addr_far, color);
        break;
    }
}

u8
vgafb_read_pixel(u16 x, u16 y)
{
    // Get the mode
    struct vgamode_s *vmode_g = find_vga_entry(GET_BDA(video_mode));
    if (!vmode_g)
        return 0;
    if (GET_GLOBAL(vmode_g->memmodel) & TEXT)
        return 0;

    u8 *addr_far, mask, attr=0, data, i;
    switch (GET_GLOBAL(vmode_g->memmodel)) {
    case PLANAR4:
    case PLANAR1:
        addr_far = (void*)(x / 8 + y * GET_BDA(video_cols));
        mask = 0x80 >> (x & 0x07);
        attr = 0x00;
        for (i = 0; i < 4; i++) {
            vgahw_grdc_write(0x04, i);
            data = GET_FARVAR(SEG_GRAPH, *addr_far) & mask;
            if (data > 0)
                attr |= (0x01 << i);
        }
        break;
    case CGA:
        addr_far = (void*)((x >> 2) + (y >> 1) * 80);
        if (y & 1)
            addr_far += 0x2000;
        data = GET_FARVAR(SEG_CTEXT, *addr_far);
        if (GET_GLOBAL(vmode_g->pixbits) == 2)
            attr = (data >> ((3 - (x & 0x03)) * 2)) & 0x03;
        else
            attr = (data >> (7 - (x & 0x07))) & 0x01;
        break;
    case LINEAR8:
        addr_far = (void*)(x + y * (GET_BDA(video_cols) * 8));
        attr = GET_FARVAR(SEG_GRAPH, *addr_far);
        break;
    }
    return attr;
}


/****************************************************************
 * Font loading
 ****************************************************************/

void
vgafb_load_font(u16 seg, void *src_far, u16 count
                , u16 start, u8 destflags, u8 fontsize)
{
    get_font_access();
    u16 blockaddr = ((destflags & 0x03) << 14) + ((destflags & 0x04) << 11);
    void *dest_far = (void*)(blockaddr + start*32);
    u16 i;
    for (i = 0; i < count; i++)
        memcpy_far(SEG_GRAPH, dest_far + i*32
                   , seg, src_far + i*fontsize, fontsize);
    release_font_access();
}
