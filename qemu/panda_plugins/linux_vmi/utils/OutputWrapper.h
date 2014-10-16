/**
 * Copyright (C) <2011> <Syracuse System Security (Sycure) Lab>
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
**//*
 * OutputWrapper.h (used to be Output.h)
 *
 *  Created on: Sep 29, 2011
 *      Author: lok
 */

#ifndef OUTPUT_WRAPPER_H_
#define OUTPUT_WRAPPER_H_

#include <stdio.h>
#include "monitor.h"

#ifdef __cplusplus
extern "C"
{
#endif

/** vprintf wrapper - prints out to a file if fp is set
 *  otherwise, it will try the monitor (if set), otherwise
 *  default_mon and then finally stdout. 
 * In other words, fp, monitor, default_mon, stdout are the
 * outputs in order of preference.
 * By default, fp and monitor are NULL and so default_mon
 *  is the preferred output if -monitor is used.
**/
void DECAF_vprintf(FILE* fp, const char* fmt, va_list ap);
/**  DECAF_vprintf wrapper **/
void DECAF_printf(const char* fmt, ...);
/** Prints to a particular monitor uses DECAF_vprintf)**/
void DECAF_mprintf(Monitor* mon, const char* fmt, ...);
/** Prints to a file (uses DECAF_vprintf)**/
void DECAF_fprintf(FILE* fp, const char* fmt, ...);

/** Flush - whatever is the current preferred output **/
void DECAF_flush(void);
/** Flush the monitor **/
void DECAF_mflush(Monitor* mon);
/** Flush a file **/
void DECAF_fflush(FILE* fp);

/** Get the current fp (if it exists) **/
FILE* DECAF_get_output_fp(void);

/** get the current monitor - it is default_mon if the monitor was never set **/
Monitor* DECAF_get_output_mon(void);

/** I Put this here as a reference. The idea is that we use a magic FD value
 to represent the default monitor. All of the code is there, just not
 exported for use 
const FILE* DECAF_get_monitor_fp(void);
**/

/** Function called by the set_output_file command - currently not used **/
void DECAF_do_set_output_file(Monitor* mon, const char* fileName);
/** Sets the output file **/
void DECAF_set_output_file(const char* fileName);
/** Sets the output monitor **/
void DECAF_set_output_mon(Monitor* mon);
/** Basically calls the final flush and closes the fp**/
void DECAF_output_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* OUTPUT_WRAPPER_H_ */
