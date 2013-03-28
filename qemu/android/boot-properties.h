/* Copyright (C) 2009 The Android Open Source Project
**
** This software is licensed under the terms of the GNU General Public
** License version 2, as published by the Free Software Foundation, and
** may be copied, distributed, and modified under those terms.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

#ifndef _ANDROID_BOOT_PROPERTIES_H
#define _ANDROID_BOOT_PROPERTIES_H

/* Manage the set of boot system properties.
 * See the documentation for the 'boot-properties' service
 * in docs/ANDROID-QEMUD-SERVICES.TXT
 */

/* these values give the maximum length of system property
 * names and values. They must match the corresponding definitions
 * in the Android source tree (in system/core/include/cutils/properties.h)
 */
#define  PROPERTY_MAX_NAME    32
#define  PROPERTY_MAX_VALUE   92

/* record a new boot system property, this must be performed before the
 * VM is started. Returns 0 on success, or < 0 on error.
 * Possible errors are:
 * -1 property name too long
 * -2 property value too long
 * -3 invalid characters in property name
 */
int  boot_property_add( const char*  name, const char*  value );

/* same as boot_property_add, but allows to use non-zero terminated strings.
 */
int  boot_property_add2( const char*  name, int  namelen,
                         const char*  value, int  valuelen );

/* init the boot property QEMUD service. This must be performed before
 * the VM is started. This is also performed automatically if you call
 * boot_property_add().
 */
void  boot_property_init_service( void );

/* parse the parameter of -prop options passed on the command line
 */
void  boot_property_parse_option( const char*  param );

#endif /* _ANDROID_BOOT_PROPERTIES_H */
