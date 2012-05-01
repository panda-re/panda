#include <stdio.h>
#include <curses.h>
#include <ipxe/console.h>

FILE_LICENCE ( GPL2_OR_LATER );

static void ansiscr_reset(struct _curses_screen *scr) __nonnull;
static void ansiscr_movetoyx(struct _curses_screen *scr,
                               unsigned int y, unsigned int x) __nonnull;
static void ansiscr_putc(struct _curses_screen *scr, chtype c) __nonnull;

unsigned short _COLS = 80;
unsigned short _LINES = 24;

static void ansiscr_reset ( struct _curses_screen *scr ) {
	/* Reset terminal attributes and clear screen */
	scr->attrs = 0;
	scr->curs_x = 0;
	scr->curs_y = 0;
	printf ( "\033[0m" );
}

static void ansiscr_movetoyx ( struct _curses_screen *scr,
			       unsigned int y, unsigned int x ) {
	if ( ( x != scr->curs_x ) || ( y != scr->curs_y ) ) {
		/* ANSI escape sequence to update cursor position */
		printf ( "\033[%d;%dH", ( y + 1 ), ( x + 1 ) );
		scr->curs_x = x;
		scr->curs_y = y;
	}
}

static void ansiscr_putc ( struct _curses_screen *scr, chtype c ) {
	unsigned int character = ( c & A_CHARTEXT );
	attr_t attrs = ( c & ( A_ATTRIBUTES | A_COLOR ) );
	int bold = ( attrs & A_BOLD );
	attr_t cpair = PAIR_NUMBER ( attrs );
	short fcol;
	short bcol;

	/* Update attributes if changed */
	if ( attrs != scr->attrs ) {
		scr->attrs = attrs;
		pair_content ( cpair, &fcol, &bcol );
		/* ANSI escape sequence to update character attributes */
		printf ( "\033[0;%d;3%d;4%dm", ( bold ? 1 : 22 ), fcol, bcol );
	}

	/* Print the actual character */
	putchar ( character );

	/* Update expected cursor position */
	if ( ++(scr->curs_x) == _COLS ) {
		scr->curs_x = 0;
		++scr->curs_y;
	}
}

static int ansiscr_getc ( struct _curses_screen *scr __unused ) {
	return getchar();
}

static bool ansiscr_peek ( struct _curses_screen *scr __unused ) {
	return iskey();
}

SCREEN _ansi_screen = {
	.init		= ansiscr_reset,
	.exit		= ansiscr_reset,
	.movetoyx	= ansiscr_movetoyx,
	.putc		= ansiscr_putc,
	.getc		= ansiscr_getc,
	.peek		= ansiscr_peek,
};
