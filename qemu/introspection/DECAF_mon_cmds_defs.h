/**
 * Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public 
 * License along with this program; if not, write to the Free 
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 * MA 02111-1307 USA
**/

/**
 * This file was created because of the many different QEMU versions between
 * Android and the regular QEMU. Since the definitions have all changed, this 
 * was the best way to limit the amount of changes when porting to a new version
 * It is certainly possible that all of this work is for naught.
 * @author Lok Yan
 * @date 14 DEC 2012
 * 
**/

#ifndef DECAF_MON_CMDS_DEFS_H
#define DECAF_MON_CMDS_DEFS_H

  #if defined(_QEMU_MON_HANDLER_CMD) || defined(_QEMU_MON_HANDLER_CMD_NEW) || defined(_QEMU_MON_HANDLER_INFO)
    #error QEMU Handler Aliases already defined
  #endif

  #if defined(QEMU_ANDROID_GINGERBREAD)
    #define _QEMU_MON_HANDLER_CMD handler
    #define _QEMU_MON_HANDLER_CMD_NEW handler
    #define _QEMU_MON_HANDLER_INFO handler
  #else 
    #warn DECAF Warning: FIX_ME_UNDEFINED_QEMU_VERSION
    #define _QEMU_MON_HANDLER_CMD mhandler.cmd
    #define _QEMU_MON_HANDLER_CMD_NEW mhandler.cmd_new
    #define _QEMU_MON_HANDLER_INFO mhandler.info
  #endif

  #if defined(_QEMU_MON_KEY_VALUE)
    #error QEMU Key Value Macro already defined
  #endif

  #if defined(QEMU_ANDROID_GINGERBREAD)
    #define _QEMU_MON_KEY_VALUE(_key, _value) _value
  #else
    #define _QEMU_MON_KEY_VALUE(_key, _value) _key ":" _value
  #endif

#endif//DECAF_MON_CMDS_DEFS_H
