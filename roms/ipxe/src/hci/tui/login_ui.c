/*
 * Copyright (C) 2009 Michael Brown <mbrown@fensystems.co.uk>.
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

/** @file
 *
 * Login UI
 *
 */

#include <string.h>
#include <errno.h>
#include <curses.h>
#include <ipxe/console.h>
#include <ipxe/settings.h>
#include <ipxe/editbox.h>
#include <ipxe/keys.h>
#include <ipxe/login_ui.h>

/* Colour pairs */
#define CPAIR_NORMAL		1
#define CPAIR_LABEL		2
#define CPAIR_EDITBOX		3

/* Screen layout */
#define USERNAME_LABEL_ROW	8
#define USERNAME_ROW		10
#define PASSWORD_LABEL_ROW	14
#define PASSWORD_ROW		16
#define LABEL_COL		36
#define EDITBOX_COL		30
#define EDITBOX_WIDTH		20

int login_ui ( void ) {
	char username[64];
	char password[64];
	struct edit_box username_box;
	struct edit_box password_box;
	struct edit_box *current_box = &username_box;
	int key;
	int rc = -EINPROGRESS;

	/* Fetch current setting values */
	fetch_string_setting ( NULL, &username_setting, username,
			       sizeof ( username ) );
	fetch_string_setting ( NULL, &password_setting, password,
			       sizeof ( password ) );

	/* Initialise UI */
	initscr();
	start_color();
	init_pair ( CPAIR_NORMAL, COLOR_WHITE, COLOR_BLACK );
	init_pair ( CPAIR_LABEL, COLOR_WHITE, COLOR_BLACK );
	init_pair ( CPAIR_EDITBOX, COLOR_WHITE, COLOR_BLUE );
	init_editbox ( &username_box, username, sizeof ( username ), NULL,
		       USERNAME_ROW, EDITBOX_COL, EDITBOX_WIDTH, 0 );
	init_editbox ( &password_box, password, sizeof ( password ), NULL,
		       PASSWORD_ROW, EDITBOX_COL, EDITBOX_WIDTH,
		       EDITBOX_STARS );

	/* Draw initial UI */
	erase();
	color_set ( CPAIR_LABEL, NULL );
	mvprintw ( USERNAME_LABEL_ROW, LABEL_COL, "Username:" );
	mvprintw ( PASSWORD_LABEL_ROW, LABEL_COL, "Password:" );
	color_set ( CPAIR_EDITBOX, NULL );
	draw_editbox ( &username_box );
	draw_editbox ( &password_box );

	/* Main loop */
	while ( rc == -EINPROGRESS ) {

		draw_editbox ( current_box );

		key = getkey ( 0 );
		switch ( key ) {
		case KEY_DOWN:
			current_box = &password_box;
			break;
		case KEY_UP:
			current_box = &username_box;
			break;
		case TAB:
			current_box = ( ( current_box == &username_box ) ?
					&password_box : &username_box );
			break;
		case KEY_ENTER:
			if ( current_box == &username_box ) {
				current_box = &password_box;
			} else {
				rc = 0;
			}
			break;
		case CTRL_C:
		case ESC:
			rc = -ECANCELED;
			break;
		default:
			edit_editbox ( current_box, key );
			break;
		}
	}

	/* Terminate UI */
	color_set ( CPAIR_NORMAL, NULL );
	erase();
	endwin();

	if ( rc != 0 )
		return rc;

	/* Store settings */
	if ( ( rc = store_setting ( NULL, &username_setting, username,
				    strlen ( username ) ) ) != 0 )
		return rc;
	if ( ( rc = store_setting ( NULL, &password_setting, password,
				    strlen ( password ) ) ) != 0 )
		return rc;

	return 0;
}
