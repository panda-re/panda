/*
 *   Creation Date: <2002/10/23 20:26:40 samuel>
 *   Time-stamp: <2004/01/07 19:39:15 samuel>
 *
 *	<video.c>
 *
 *	Mac-on-Linux display node
 *
 *   Copyright (C) 2002, 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libc/diskio.h"
#include "libopenbios/ofmem.h"
#include "drivers/drivers.h"
#include "packages/video.h"
#include "libopenbios/console.h"
#include "drivers/vga.h"

typedef struct osi_fb_info {
    unsigned long mphys;
    int rb, w, h, depth;
} osi_fb_info_t;

static struct {
	int		has_video;
	osi_fb_info_t	fb;
	unsigned long		*pal;		/* 256 elements */
} video;


int
video_get_res( int *w, int *h )
{
	if( !video.has_video ) {
		*w = *h = 0;
		return -1;
	}
	*w = video.fb.w;
	*h = video.fb.h;
	return 0;
}

static void
startup_splash( void )
{
#ifdef CONFIG_MOL
	int fd, s, i, y, x, dx, dy;
	int width, height;
	char *pp, *p;
	char buf[64];
#endif

	/* only draw logo in 24-bit mode (for now) */
	if( video.fb.depth < 15 )
		return;
#ifdef CONFIG_MOL
	for( i=0; i<2; i++ ) {
		if( !BootHGetStrResInd("bootlogo", buf, sizeof(buf), 0, i) )
			return;
		*(!i ? &width : &height) = atol(buf);
	}

	if( (s=width * height * 3) > 0x20000 )
		return;

	if( (fd=open_io("pseudo:,bootlogo")) >= 0 ) {
		p = malloc( s );
		if( read_io(fd, p, s) != s )
			printk("bootlogo size error\n");
		close_io( fd );

		dx = (video.fb.w - width)/2;
		dy = (video.fb.h - height)/3;

		pp = (char*)video.fb.mphys + dy * video.fb.rb + dx * (video.fb.depth >= 24 ? 4 : 2);

		for( y=0 ; y<height; y++, pp += video.fb.rb ) {
			if( video.fb.depth >= 24 ) {
				unsigned long *d = (unsigned long*)pp;
				for( x=0; x<width; x++, p+=3, d++ )
					*d = ((int)p[0] << 16) | ((int)p[1] << 8) | p[2];
			} else if( video.fb.depth == 15 ) {
				unsigned short *d = (unsigned short*)pp;
				for( x=0; x<width; x++, p+=3, d++ ) {
					int col = ((int)p[0] << 16) | ((int)p[1] << 8) | p[2];
					*d = ((col>>9) & 0x7c00) | ((col>>6) & 0x03e0) | ((col>>3) & 0x1f);
				}
			}
		}
		free( p );
	}
#else
	/* No bootlogo support yet on other platforms */
	return;
#endif
}

static unsigned long
get_color( int col_ind )
{
	unsigned long col;
	if( !video.has_video || col_ind < 0 || col_ind > 255 )
		return 0;
	if( video.fb.depth == 8 )
		return col_ind;
	col = video.pal[col_ind];
	if( video.fb.depth == 24 || video.fb.depth == 32 )
		return col;
	if( video.fb.depth == 15 )
		return ((col>>9) & 0x7c00) | ((col>>6) & 0x03e0) | ((col>>3) & 0x1f);
	return 0;
}

void
draw_pixel( int x, int y, int colind )
{
	char *p = (char*)video.fb.mphys + video.fb.rb * y;
	int color, d = video.fb.depth;

	if( x < 0 || y < 0 || x >= video.fb.w || y >=video.fb.h )
		return;
	color = get_color( colind );

	if( d >= 24 )
		*((unsigned long*)p + x) = color;
	else if( d >= 15 )
		*((short*)p + x) = color;
	else
		*(p + x) = color;
}

static void
fill_rect( int col_ind, int x, int y, int w, int h )
{
	char *pp;
	unsigned long col = get_color(col_ind);

        if (!video.has_video || x < 0 || y < 0 || w <= 0 || h <= 0 ||
            x + w > video.fb.w || y + h > video.fb.h)
		return;

	pp = (char*)video.fb.mphys + video.fb.rb * y;
	for( ; h--; pp += video.fb.rb ) {
		int ww = w;
		if( video.fb.depth == 24 || video.fb.depth == 32 ) {
			unsigned long *p = (unsigned long*)pp + x;
			while( ww-- )
				*p++ = col;
		} else if( video.fb.depth == 16 || video.fb.depth == 15 ) {
			unsigned short *p = (unsigned short*)pp + x;
			while( ww-- )
				*p++ = col;
		} else {
                        char *p = (char *)((unsigned short*)pp + x);

			while( ww-- )
				*p++ = col;
		}
	}
}

static void
refresh_palette( void )
{
#ifdef CONFIG_MOL
	if( video.fb.depth == 8 )
		OSI_RefreshPalette();
#endif
}

void
set_color( int ind, unsigned long color )
{
	if( !video.has_video || ind < 0 || ind > 255 )
		return;
	video.pal[ind] = color;

#ifdef CONFIG_MOL
	if( video.fb.depth == 8 )
		OSI_SetColor( ind, color );
#elif defined(CONFIG_SPARC32)
	if( video.fb.depth == 8 ) {
            dac[0] = ind << 24;
            dac[1] = ((color >> 16) & 0xff) << 24; // Red
            dac[1] = ((color >> 8) & 0xff) << 24; // Green
            dac[1] = (color & 0xff) << 24; // Blue
        }
#else
	vga_set_color(ind, ((color >> 16) & 0xff),
			   ((color >> 8) & 0xff),
			   (color & 0xff));
#endif
}

void
video_scroll( int height )
{
	int i, offs, size, *dest, *src;

        if (height <= 0 || height >= video.fb.h) {
                return;
        }
	offs = video.fb.rb * height;
	size = (video.fb.h * video.fb.rb - offs)/16;
	dest = (int*)video.fb.mphys;
	src = (int*)(video.fb.mphys + offs);

	for( i=0; i<size; i++ ) {
		dest[0] = src[0];
		dest[1] = src[1];
		dest[2] = src[2];
		dest[3] = src[3];
		dest += 4;
		src += 4;
	}
}

/************************************************************************/
/*	OF methods							*/
/************************************************************************/

DECLARE_NODE( video, INSTALL_OPEN, 0, "Tdisplay" );

/* ( -- width height ) (?) */
static void
video_dimensions( void )
{
	int w, h;
	(void) video_get_res( &w, &h );
	PUSH( w );
	PUSH( h );
}

/* ( table start count -- ) (?) */
static void
video_set_colors( void )
{
	int count = POP();
	int start = POP();
	unsigned char *p = (unsigned char*)cell2pointer(POP());
	int i;

	for( i=0; i<count; i++, p+=3 ) {
		unsigned long col = (p[0] << 16) | (p[1] << 8) | p[2];
		set_color( i + start, col );
	}
	refresh_palette();
}

/* ( r g b index -- ) */
static void
video_color_bang( void )
{
	int index = POP();
	int b = POP();
	int g = POP();
	int r = POP();
	unsigned long col = ((r << 16) & 0xff0000) | ((g << 8) & 0x00ff00) | (b & 0xff);
	/* printk("color!: %08lx %08lx %08lx %08lx\n", r, g, b, index ); */
	set_color( index, col );
	refresh_palette();
}

/* ( color_ind x y width height -- ) (?) */
static void
video_fill_rect( void )
{
	int h = POP();
	int w = POP();
	int y = POP();
	int x = POP();
	int color_ind = POP();

	fill_rect( color_ind, x, y, w, h );
}

/* ( addr len -- actual ) */
static void
video_write(void)
{
    char *addr;
    int len;

    len = POP();
    addr = (char *)cell2pointer(POP());

    console_draw_fstr(addr, len);
    PUSH(len);
}

NODE_METHODS( video ) = {
	{"dimensions",		video_dimensions	},
	{"set-colors",		video_set_colors	},
	{"fill-rectangle",	video_fill_rect		},
	{"color!",		video_color_bang	},
	{"write",		video_write		},
};


/************************************************************************/
/*	init 								*/
/************************************************************************/

void
init_video( unsigned long fb,  int width, int height, int depth, int rb )
{
        int i;
#ifdef CONFIG_PPC
        int s, size;
#endif
	phandle_t ph=0;

	video.fb.mphys = fb;
	video.fb.w = width;
	video.fb.h = height;
	video.fb.depth = depth;
	video.fb.rb = rb;
	while( (ph=dt_iterate_type(ph, "display")) ) {
		set_int_property( ph, "width", video.fb.w );
		set_int_property( ph, "height", video.fb.h );
		set_int_property( ph, "depth", video.fb.depth );
		set_int_property( ph, "linebytes", video.fb.rb );
		set_int_property( ph, "address", video.fb.mphys );
	}
	video.has_video = 1;
	video.pal = malloc( 256 * sizeof(unsigned long) );

#ifdef CONFIG_PPC
        s = (video.fb.mphys & 0xfff);
        size = ((video.fb.h * video.fb.rb + s) + 0xfff) & ~0xfff;

	ofmem_claim_phys( video.fb.mphys, size, 0 );
	ofmem_claim_virt( video.fb.mphys, size, 0 );
	ofmem_map( video.fb.mphys, video.fb.mphys, size, -1 );
#endif

	for( i=0; i<256; i++ )
		set_color( i, i * 0x010101 );

	set_color( 254, 0xffffcc );
	fill_rect( 254, 0, 0, video.fb.w, video.fb.h );

	refresh_palette();
	startup_splash();

	REGISTER_NODE( video );
}
