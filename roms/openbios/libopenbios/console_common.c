/*
 *	<console.c>
 *
 *	Simple text console
 *
 *   Copyright (C) 2002, 2003 Samuel Rydh (samuel@ibrium.se)
 *   Copyright (C) 2005 Stefan Reinauer <stepan@openbios.org>
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/fontdata.h"
#include "libopenbios/console.h"
#include "packages/video.h"

#define FONT_ADJ_HEIGHT	 (FONT_HEIGHT + 2)

// Warning: will hang on purpose when encountering unknown codes
//#define DEBUG_CONSOLE
#ifdef DEBUG_CONSOLE
#define DPRINTF(fmt, args...)                   \
    do {                                        \
        printk(fmt , ##args);                   \
        for (;;);                               \
    } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

typedef enum {
    ESnormal, ESesc, ESsquare, ESgetpars, ESgotpars, ESfunckey,
    EShash, ESsetG0, ESsetG1, ESpercent, ESignore, ESnonstd,
    ESpalette
} vc_state_t;

#define NPAR 16
static struct {
	int	inited;
	int	physw, physh;
	int	w,h;

	int	x,y;
	char	*buf;

	int	cursor_on;
	vc_state_t vc_state;
	unsigned int vc_npar,vc_par[NPAR]; /* Parameters of current
                                              escape sequence */
} cons;

static int
get_conschar( int x, int y )
{
	if( (unsigned int)x < cons.w && (unsigned int)y < cons.h )
		return cons.buf[y*cons.w + x];
	return ' ';
}

static void
draw_char( unsigned int h, unsigned int v )
{
        const unsigned char *c = fontdata;
	int x, y, xx, rskip, m;
	int invert = (h==cons.x && v==cons.y && cons.cursor_on);
	int ch = get_conschar( h, v );

	while( h >= cons.w || v >= cons.h )
		return;

	h *= FONT_WIDTH;
	v *= FONT_ADJ_HEIGHT;

	rskip = (FONT_WIDTH > 8)? 2 : 1;
	c += rskip * (unsigned int)(ch & 0xff) * FONT_HEIGHT;

	for( x=0; x<FONT_WIDTH; x++ ) {
		xx = x % 8;
		if( x && !xx )
			c++;
		m = (1<<(7-xx));
		for( y=0; y<FONT_HEIGHT; y++ ){
			int col = ((!(c[rskip*y] & m)) != invert) ? 254 : 0;
			draw_pixel( h+x, v+y+1, col );
		}
		draw_pixel( h+x, v, 254 );
		draw_pixel( h+x, v+FONT_HEIGHT+1, 254 );
	}
}

static void
show_cursor( int show )
{
	if( cons.cursor_on == show )
		return;
	cons.cursor_on = show;
	draw_char( cons.x, cons.y );
}


static void
draw_line( int n )
{
	int i;

	if( n >= cons.h || n < 0 )
		return;
	for( i=0; i<cons.w; i++ )
		draw_char( i, n );
}

#if 0
static void
refresh( void )
{
	int i;
	for( i=0; i<cons.h; i++ )
		draw_line(i);
}
#endif

int
console_init( void )
{
	if( video_get_res(&cons.physw,&cons.physh) < 0 )
		return -1;

	set_color( 0, 0 );

	cons.w = cons.physw/FONT_WIDTH;
	cons.h = cons.physh/FONT_ADJ_HEIGHT;
	cons.buf = malloc( cons.w * cons.h );
	cons.inited = 1;
	cons.x = cons.y = 0;
        cons.vc_state = ESnormal;
	return 0;
}

void
console_close( void )
{
 	if( !cons.inited )
		return;
	free( cons.buf );
	cons.inited = 0;
}

static void
rec_char( int ch, int x, int y )
{
	if( (unsigned int)x < cons.w && (unsigned int)y < cons.h ) {
		cons.buf[y*cons.w + x] = ch;
		draw_char( x, y );
	}
}

static void
scroll1( void )
{
    int x, y;

    video_scroll(FONT_ADJ_HEIGHT);

    for (y = 1; y < cons.h - 1; y++) {
        for (x = 0; x < cons.w; x++)
            cons.buf[(y - 1) * cons.w + x] = cons.buf[y * cons.w + x];
    }
    for (x = 0; x < cons.w; x++)
        cons.buf[(cons.h - 1) * cons.w + x] = ' ';
    draw_line(cons.h - 1);
}

// Insert char
static void csi_at(unsigned int nr)
{
    unsigned int x;

    if (nr > cons.w - cons.x)
        nr = cons.w - cons.x;
    else if (!nr)
        return;

    for (x = cons.x + nr; x < cons.w - 1; x++)
        cons.buf[cons.y * cons.w + x - nr] = cons.buf[cons.y * cons.w + x];
    for (x = cons.x; x < cons.x + nr; x++)
        cons.buf[cons.y * cons.w + x] = ' ';
    draw_line(cons.y);
}

static void
do_con_trol(unsigned char ch)
{
    unsigned int i, j;

    switch (ch) {
    case 7:
        // BEL
        return;
    case 8:
        // BS
        if (cons.x)
            cons.x--;
        return;
    case 9:
        // HT
        cons.x = (cons.x + 8) & ~7;
        return;
    case 10:
        // LF
        cons.x = 0;
        cons.y++;
        return;
    case 12:
        // FF
        for (i = 0; i < cons.h; i++) {
            for (j = 0; j < cons.w; j++)
                cons.buf[i * cons.w + j] = ' ';
            draw_line(i);
        }
        cons.x = cons.y = 0;
        return;
    case 13:
        // CR
        cons.x = 0;
        return;
    case 25:
        // EM
        return;
    case 24: // CAN
    case 26: // SUB
        cons.vc_state = ESnormal;
        return;
    case 27:
        // ESC
        cons.vc_state = ESesc;
        return;
    }
    if (ch < 32)
        DPRINTF("Unhandled control char %d\n", ch);

    switch (cons.vc_state) {
    case ESesc:
        cons.vc_state = ESnormal;
        switch (ch) {
        case '[':
            cons.vc_state = ESsquare;
            return;
        case 'M':
            scroll1();
            return;
        default:
            DPRINTF("Unhandled basic escape code '%c'\n", ch);
            return;
        }
        return;
    case ESsquare:
        for(cons.vc_npar = 0; cons.vc_npar < NPAR ; cons.vc_npar++)
            cons.vc_par[cons.vc_npar] = 0;
        cons.vc_npar = 0;
        cons.vc_state = ESgetpars;
        // Fall through
    case ESgetpars:
        if (ch == ';' && cons.vc_npar < NPAR - 1) {
            cons.vc_npar++;
            return;
        } else if (ch >= '0' && ch <= '9') {
            cons.vc_par[cons.vc_npar] *= 10;
            cons.vc_par[cons.vc_npar] += ch - '0';
            return;
        } else
            cons.vc_state=ESgotpars;
        // Fall through
    case ESgotpars:
        cons.vc_state = ESnormal;
        switch(ch) {
        case 'A':
            // Cursor up
            if (cons.vc_par[0] == 0)
                cons.vc_par[0] = 1;
            if (cons.y - cons.vc_par[0] > 0)
                cons.y -= cons.vc_par[0];
            return;
        case 'B':
            // Cursor down
            if (cons.vc_par[0] == 0)
                cons.vc_par[0] = 1;
            if (cons.y + cons.vc_par[0] < cons.h - 1)
                cons.y += cons.vc_par[0];
            return;
        case 'C':
            // Cursor right
            if (cons.vc_par[0] == 0)
                cons.vc_par[0] = 1;
            if (cons.x + cons.vc_par[0] < cons.w - 1)
                cons.x += cons.vc_par[0];
            return;
        case 'D':
            // Cursor left
            if (cons.vc_par[0] == 0)
                cons.vc_par[0] = 1;
            if (cons.x - cons.vc_par[0] > 0)
                cons.x -= cons.vc_par[0];
            return;
        case 'H':
        case 'f':
            // Set cursor position
            if (cons.vc_par[0])
                cons.vc_par[0]--;

            if (cons.vc_par[1])
                cons.vc_par[1]--;

            cons.x = cons.vc_par[1];
            cons.y = cons.vc_par[0];
            return;
        case 'J':
            if (cons.vc_par[0] == 0 && (unsigned int)cons.y < (unsigned int)cons.h &&
                (unsigned int)cons.x < (unsigned int)cons.w) {
                // erase from cursor to end of display
                for (i = cons.x; i < cons.w; i++)
                    cons.buf[cons.y * cons.w + i] = ' ';
                draw_line(cons.y);
                for (j = cons.y + 1; j < cons.h; j++) {
                    for (i = 0; i < cons.w; i++)
                        cons.buf[j * cons.w + i] = ' ';
                    draw_line(j);
                }
            } else {
                DPRINTF("Unhandled CSI J code '%c'\n", cons.vc_par[0]);
            }
            return;
        case 'K':
            switch (cons.vc_par[0]) {
            case 0: /* erase from cursor to end of line */
                for (i = cons.x; i < cons.w; i++)
                    cons.buf[cons.y * cons.w + i] = ' ';
                draw_line(cons.y);
                return;
            case 1: /* erase from start of line to cursor */
                for (i = 0; i <= cons.x; i++)
                    cons.buf[cons.y * cons.w + i] = ' ';
                draw_line(cons.y);
                return;
            case 2: /* erase whole line */
                for (i = 0; i < cons.w; i++)
                    cons.buf[cons.y * cons.w + i] = ' ';
                draw_line(cons.y);
                return;
            default:
                DPRINTF("Unhandled CSI K code '%c'\n", cons.vc_par[0]);
                return;
            }
            return;
        case 'M':
            if (cons.vc_par[0] == 1)
                scroll1();
            else
                DPRINTF("Unhandled CSI M %d\n", cons.vc_par[0]);
            return;
        case 'm':
            // Attributes are ignored
            return;
        case '@':
            csi_at(cons.vc_par[0]);
            return;
        default:
            DPRINTF("Unhandled escape code '%c', par[%d, %d, %d, %d, %d]\n",
                    ch, cons.vc_par[0], cons.vc_par[1], cons.vc_par[2],
                    cons.vc_par[3], cons.vc_par[4]);
            return;
        }
        return;
    default:
        cons.vc_state = ESnormal;
        rec_char(ch, cons.x++, cons.y);
        return;
    }
}

int
console_draw_fstr(const char *str, int len)
{
        unsigned int y, x;
        unsigned char ch;

        if (!str || len <= 0) {
		return 0;
	}

	if( !cons.inited && console_init() )
		return -1;

	show_cursor(0);
        while((ch = *str++) && len--) {
		do_con_trol(ch);

		if( cons.x >= cons.w ) {
			cons.x=0, cons.y++;
		}
		if( cons.y >= cons.h ) {
			for( y=0; y<cons.h-1; y++ )
				for( x=0; x<cons.w; x++ )
					cons.buf[y*cons.w + x] = cons.buf[(y+1)*cons.w + x];
			cons.y = cons.h-1;
			cons.x = 0;
			scroll1();
		}
	}
	show_cursor(1);
	return 0;
}
