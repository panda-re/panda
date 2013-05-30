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
 * @author Lok Yan
 * @date 14 October 2012
 *
 * DECAF_cmds.c and .h are used for implementing monitor commands default to DECAF.
 */

#ifndef DECAF_CMDS_H
#define DECAF_CMDS_H

#include "monitor.h"
#include "qdict.h"

#ifdef __cplusplus
extern "C"
{
#endif
void do_guest_ps(Monitor *mon);
void do_guest_pt(Monitor* mon);
void do_guest_modules(Monitor *mon, int pid);

void do_sym_to_addr(Monitor* mon, int pid, const char* modName, const char* symName);
#ifdef __cplusplus
}
#endif

#endif//DECAF_CMDS_H
