/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <curses.h>
#include <ipxe/console.h>
#include <ipxe/settings.h>
#include <ipxe/editbox.h>
#include <ipxe/keys.h>
#include <ipxe/settings_ui.h>

/** @file
 *
 * Option configuration console
 *
 */

/* Colour pairs */
#define CPAIR_NORMAL	1
#define CPAIR_SELECT	2
#define CPAIR_EDIT	3
#define CPAIR_ALERT	4
#define CPAIR_URL	5

/* Screen layout */
#define TITLE_ROW		1
#define SETTINGS_LIST_ROW	3
#define SETTINGS_LIST_COL	1
#define SETTINGS_LIST_ROWS	15
#define INFO_ROW		19
#define ALERT_ROW		22
#define INSTRUCTION_ROW		22
#define INSTRUCTION_PAD "     "

/** Layout of text within a setting widget */
struct setting_row_text {
	char start[0];
	char pad1[1];
	char name[15];
	char pad2[1];
	char value[60];
	char pad3[1];
	char nul;
} __attribute__ (( packed ));

/** A setting row widget */
struct setting_row_widget {
	/** Target configuration settings block
	 *
	 * Valid only for rows that lead to new settings blocks.
	 */
	struct settings *settings;
	/** Configuration setting
	 *
	 * Valid only for rows that represent individual settings.
	 */
	struct setting *setting;
	/** Screen row */
	unsigned int row;
	/** Screen column */
	unsigned int col;
	/** Edit box widget used for editing setting */
	struct edit_box editbox;
	/** Editing in progress flag */
	int editing;
	/** Setting originates from this block flag */
	int originates_here;
	/** Buffer for setting's value */
	char value[256]; /* enough size for a DHCP string */
};

/** A settings widget */
struct setting_widget {
	/** Settings block */
	struct settings *settings;
	/** Number of rows */
	unsigned int num_rows;
	/** Current row index */
	unsigned int current;
        /** Index of the first visible row, for scrolling. */
	unsigned int first_visible;
	/** Active row */
	struct setting_row_widget row;
};

/**
 * Select a setting row
 *
 * @v widget		Setting widget
 * @v index		Index of setting row
 * @ret count		Number of settings rows
 */
static unsigned int select_setting_row ( struct setting_widget *widget,
					 unsigned int index ) {
	struct settings *settings;
	struct settings *origin;
	struct setting *setting;
	unsigned int count = 0;

	/* Initialise structure */
	memset ( &widget->row, 0, sizeof ( widget->row ) );
	widget->current = index;
	widget->row.row = ( SETTINGS_LIST_ROW + index - widget->first_visible );
	widget->row.col = SETTINGS_LIST_COL;

	/* Include parent settings block, if applicable */
	if ( widget->settings->parent && ( count++ == index ) ) {
		widget->row.settings = widget->settings->parent;
		snprintf ( widget->row.value, sizeof ( widget->row.value ),
			   "../" );
	}

	/* Include any child settings blocks, if applicable */
	list_for_each_entry ( settings, &widget->settings->children, siblings ){
		if ( count++ == index ) {
			widget->row.settings = settings;
			snprintf ( widget->row.value,
				   sizeof ( widget->row.value ), "%s/",
				   settings->name );
		}
	}

	/* Include any applicable settings */
	for_each_table_entry ( setting, SETTINGS ) {
		if ( ! setting_applies ( widget->settings, setting ) )
			continue;
		if ( count++ == index ) {
			widget->row.setting = setting;

			/* Read current setting value */
			fetchf_setting ( widget->settings, widget->row.setting,
					 widget->row.value,
					 sizeof ( widget->row.value ) );

			/* Check setting's origin */
			origin = fetch_setting_origin ( widget->settings,
							widget->row.setting );
			widget->row.originates_here =
				( origin == widget->settings );
		}
	}

	/* Initialise edit box */
	init_editbox ( &widget->row.editbox, widget->row.value,
		       sizeof ( widget->row.value ), NULL, widget->row.row,
		       ( widget->row.col +
			 offsetof ( struct setting_row_text, value ) ),
		       sizeof ( ( ( struct setting_row_text * ) NULL )->value ),
		       0 );

	return count;
}

static size_t string_copy ( char *dest, const char *src, size_t len ) {
	size_t src_len;

	src_len = strlen ( src );
	if ( len > src_len )
		len = src_len;
	memcpy ( dest, src, len );
	return len;
}

/**
 * Draw setting row
 *
 * @v widget		Setting widget
 */
static void draw_setting_row ( struct setting_widget *widget ) {
	struct setting_row_text text;
	unsigned int curs_offset;
	char *value;

	/* Fill row with spaces */
	memset ( &text, ' ', sizeof ( text ) );
	text.nul = '\0';

	/* Construct row content */
	if ( widget->row.settings ) {

		/* Construct space-padded name */
		curs_offset = ( offsetof ( typeof ( text ), name ) +
				string_copy ( text.name, widget->row.value,
					      sizeof ( text.name ) ) );

	} else {

		/* Construct dot-padded name */
		memset ( text.name, '.', sizeof ( text.name ) );
		string_copy ( text.name, widget->row.setting->name,
			      sizeof ( text.name ) );

		/* Construct space-padded value */
		value = widget->row.value;
		if ( ! *value )
			value = "<not specified>";
		curs_offset = ( offsetof ( typeof ( text ), value ) +
				string_copy ( text.value, value,
					      sizeof ( text.value ) ) );
	}

	/* Print row */
	if ( widget->row.originates_here || widget->row.settings )
		attron ( A_BOLD );
	mvprintw ( widget->row.row, widget->row.col, "%s", text.start );
	attroff ( A_BOLD );
	move ( widget->row.row, widget->row.col + curs_offset );
}

/**
 * Edit setting widget
 *
 * @v widget		Setting widget
 * @v key		Key pressed by user
 * @ret key		Key returned to application, or zero
 */
static int edit_setting ( struct setting_widget *widget, int key ) {
	assert ( widget->row.setting != NULL );
	widget->row.editing = 1;
	return edit_editbox ( &widget->row.editbox, key );
}

/**
 * Save setting widget value back to configuration settings
 *
 * @v widget		Setting widget
 */
static int save_setting ( struct setting_widget *widget ) {
	assert ( widget->row.setting != NULL );
	return storef_setting ( widget->settings, widget->row.setting,
				widget->row.value );
}

/**
 * Print message centred on specified row
 *
 * @v row		Row
 * @v fmt		printf() format string
 * @v args		printf() argument list
 */
static void vmsg ( unsigned int row, const char *fmt, va_list args ) {
	char buf[COLS];
	size_t len;

	len = vsnprintf ( buf, sizeof ( buf ), fmt, args );
	mvprintw ( row, ( ( COLS - len ) / 2 ), "%s", buf );
}

/**
 * Print message centred on specified row
 *
 * @v row		Row
 * @v fmt		printf() format string
 * @v ..		printf() arguments
 */
static void msg ( unsigned int row, const char *fmt, ... ) {
	va_list args;

	va_start ( args, fmt );
	vmsg ( row, fmt, args );
	va_end ( args );
}

/**
 * Clear message on specified row
 *
 * @v row		Row
 */
static void clearmsg ( unsigned int row ) {
	move ( row, 0 );
	clrtoeol();
}

/**
 * Print alert message
 *
 * @v fmt		printf() format string
 * @v args		printf() argument list
 */
static void valert ( const char *fmt, va_list args ) {
	clearmsg ( ALERT_ROW );
	color_set ( CPAIR_ALERT, NULL );
	vmsg ( ALERT_ROW, fmt, args );
	sleep ( 2 );
	color_set ( CPAIR_NORMAL, NULL );
	clearmsg ( ALERT_ROW );
}

/**
 * Print alert message
 *
 * @v fmt		printf() format string
 * @v ...		printf() arguments
 */
static void alert ( const char *fmt, ... ) {
	va_list args;

	va_start ( args, fmt );
	valert ( fmt, args );
	va_end ( args );
}

/**
 * Draw title row
 *
 * @v widget		Setting widget
 */
static void draw_title_row ( struct setting_widget *widget ) {
	const char *name;

	clearmsg ( TITLE_ROW );
	name = settings_name ( widget->settings );
	attron ( A_BOLD );
	msg ( TITLE_ROW, "iPXE configuration settings%s%s",
	      ( name[0] ? " - " : "" ), name );
	attroff ( A_BOLD );
}

/**
 * Draw information row
 *
 * @v widget		Setting widget
 */
static void draw_info_row ( struct setting_widget *widget ) {
	struct settings *origin;
	char buf[32];

	/* Draw nothing unless this row represents a setting */
	clearmsg ( INFO_ROW );
	clearmsg ( INFO_ROW + 1 );
	if ( ! widget->row.setting )
		return;

	/* Determine a suitable setting name */
	origin = fetch_setting_origin ( widget->settings, widget->row.setting );
	if ( ! origin )
		origin = widget->settings;
	setting_name ( origin, widget->row.setting, buf, sizeof ( buf ) );

	/* Draw row */
	attron ( A_BOLD );
	msg ( INFO_ROW, "%s - %s", buf, widget->row.setting->description );
	attroff ( A_BOLD );
	color_set ( CPAIR_URL, NULL );
	msg ( ( INFO_ROW + 1 ), "http://ipxe.org/cfg/%s",
	      widget->row.setting->name );
	color_set ( CPAIR_NORMAL, NULL );
}

/**
 * Draw instruction row
 *
 * @v widget		Setting widget
 */
static void draw_instruction_row ( struct setting_widget *widget ) {

	clearmsg ( INSTRUCTION_ROW );
	if ( widget->row.editing ) {
		msg ( INSTRUCTION_ROW,
		      "Enter - accept changes" INSTRUCTION_PAD
		      "Ctrl-C - discard changes" );
	} else {
		msg ( INSTRUCTION_ROW,
		      "%sCtrl-X - exit configuration utility",
		      ( widget->row.originates_here ?
			"Ctrl-D - delete setting" INSTRUCTION_PAD : "" ) );
	}
}

/**
 * Reveal setting row
 *
 * @v widget		Setting widget
 * @v index		Index of setting row
 */
static void reveal_setting_row ( struct setting_widget *widget,
				 unsigned int index ) {
	unsigned int i;

	/* Simply return if setting N is already on-screen. */
	if ( index - widget->first_visible < SETTINGS_LIST_ROWS )
		return;

	/* Jump scroll to make the specified setting row visible. */
	while ( widget->first_visible < index )
		widget->first_visible += SETTINGS_LIST_ROWS;
	while ( widget->first_visible > index )
		widget->first_visible -= SETTINGS_LIST_ROWS;

	/* Draw ellipses before and/or after the settings list to
	 * represent any invisible settings.
	 */
	mvaddstr ( SETTINGS_LIST_ROW - 1,
		   SETTINGS_LIST_COL + 1,
		   widget->first_visible > 0 ? "..." : "   " );
	mvaddstr ( SETTINGS_LIST_ROW + SETTINGS_LIST_ROWS,
		   SETTINGS_LIST_COL + 1,
		   ( ( widget->first_visible + SETTINGS_LIST_ROWS )
		     < widget->num_rows ? "..." : "   " ) );

	/* Draw visible settings. */
	for ( i = 0; i < SETTINGS_LIST_ROWS; i++ ) {
		if ( ( widget->first_visible + i ) < widget->num_rows ) {
			select_setting_row ( widget,
					     widget->first_visible + i );
			draw_setting_row ( widget );
		} else {
			clearmsg ( SETTINGS_LIST_ROW + i );
		}
	}
}

/**
 * Reveal setting row
 *
 * @v widget		Setting widget
 * @v settings		Settings block
 */
static void init_widget ( struct setting_widget *widget,
			  struct settings *settings ) {

	widget->settings = settings;
	widget->num_rows = select_setting_row ( widget, 0 );
	widget->first_visible = SETTINGS_LIST_ROWS;
	draw_title_row ( widget );
	reveal_setting_row ( widget, 0 );
	select_setting_row ( widget, 0 );
}

static int main_loop ( struct settings *settings ) {
	struct setting_widget widget;
	int redraw = 1;
	int move;
	unsigned int next;
	int key;
	int rc;

	/* Print initial screen content */
	color_set ( CPAIR_NORMAL, NULL );
	memset ( &widget, 0, sizeof ( widget ) );
	init_widget ( &widget, settings );

	while ( 1 ) {

		/* Redraw rows if necessary */
		if ( redraw ) {
			draw_info_row ( &widget );
			draw_instruction_row ( &widget );
			color_set ( ( widget.row.editing ?
				      CPAIR_EDIT : CPAIR_SELECT ), NULL );
			draw_setting_row ( &widget );
			color_set ( CPAIR_NORMAL, NULL );
			redraw = 0;
		}

		if ( widget.row.editing ) {

			/* Sanity check */
			assert ( widget.row.setting != NULL );

			/* Redraw edit box */
			color_set ( CPAIR_EDIT, NULL );
			draw_editbox ( &widget.row.editbox );
			color_set ( CPAIR_NORMAL, NULL );

			/* Process keypress */
			key = edit_setting ( &widget, getkey ( 0 ) );
			switch ( key ) {
			case CR:
			case LF:
				if ( ( rc = save_setting ( &widget ) ) != 0 )
					alert ( " %s ", strerror ( rc ) );
				/* Fall through */
			case CTRL_C:
				select_setting_row ( &widget, widget.current );
				redraw = 1;
				break;
			default:
				/* Do nothing */
				break;
			}

		} else {

			/* Process keypress */
			key = getkey ( 0 );
			move = 0;
			switch ( key ) {
			case KEY_DOWN:
				if ( widget.current < ( widget.num_rows - 1 ) )
					move = +1;
				break;
			case KEY_UP:
				if ( widget.current > 0 )
					move = -1;
				break;
			case CTRL_D:
				if ( ! widget.row.setting )
					break;
				if ( ( rc = delete_setting ( widget.settings,
						widget.row.setting ) ) != 0 ) {
					alert ( " %s ", strerror ( rc ) );
				}
				select_setting_row ( &widget, widget.current );
				redraw = 1;
				break;
			case CTRL_X:
				return 0;
			case CR:
			case LF:
				if ( widget.row.settings ) {
					init_widget ( &widget,
						      widget.row.settings );
					redraw = 1;
				}
				/* Fall through */
			default:
				if ( widget.row.setting ) {
					edit_setting ( &widget, key );
					redraw = 1;
				}
				break;
			}
			if ( move ) {
				next = ( widget.current + move );
				draw_setting_row ( &widget );
				redraw = 1;
				reveal_setting_row ( &widget, next );
				select_setting_row ( &widget, next );
			}
		}
	}
}

int settings_ui ( struct settings *settings ) {
	int rc;

	initscr();
	start_color();
	init_pair ( CPAIR_NORMAL, COLOR_WHITE, COLOR_BLUE );
	init_pair ( CPAIR_SELECT, COLOR_WHITE, COLOR_RED );
	init_pair ( CPAIR_EDIT, COLOR_BLACK, COLOR_CYAN );
	init_pair ( CPAIR_ALERT, COLOR_WHITE, COLOR_RED );
	init_pair ( CPAIR_URL, COLOR_CYAN, COLOR_BLUE );
	color_set ( CPAIR_NORMAL, NULL );
	erase();
	
	rc = main_loop ( settings );

	endwin();

	return rc;
}
