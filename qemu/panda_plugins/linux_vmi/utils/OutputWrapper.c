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
 * OutputWrapper.c (Used to be Output.c)
 *
 *  Created on: Sep 29, 2011
 *      Author: lok
 */

#include "OutputWrapper.h"

//file pointers should never be in the kernel memory range so this should work
static const void* DECAF_OUTPUT_MONITOR_FD = (void*)0xFEEDBEEF;

FILE* ofp = NULL;
Monitor* pMon = NULL;

void DECAF_printf(const char* fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  DECAF_vprintf(ofp, fmt, ap);
  va_end(ap);
}

void DECAF_fprintf(FILE* fp, const char* fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  DECAF_vprintf(fp, fmt, ap);
  va_end(ap);
}

void DECAF_mprintf(Monitor* mon, const char* fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  if (mon != NULL)
  {
    monitor_vprintf(mon, fmt, ap);
  }
  else
  {
    DECAF_vprintf(NULL, fmt, ap);
  }
  va_end(ap);
}

void DECAF_vprintf(FILE* fp, const char *fmt, va_list ap)
{
  if (fp == NULL)
  {
    //that means either use stdout or monitor
    /*if (pMon != NULL)
    {
      monitor_vprintf(pMon, fmt, ap);
    }
    else if (default_mon != NULL)
    {
      monitor_vprintf(default_mon, fmt, ap);
    }
    else
    {
      */vprintf(fmt, ap);
    //}
  }
  else
  {
    if ( (fp == DECAF_OUTPUT_MONITOR_FD) && (default_mon != NULL) ) 
    {
      monitor_vprintf(default_mon, fmt, ap);
    }
    else
    {
      vfprintf(fp, fmt, ap);
    }
  }
}

void DECAF_flush(void)
{
  if (ofp != NULL)
  {
    DECAF_fflush(ofp);
  }
  else if (pMon != NULL)
  {
    DECAF_mflush(pMon);
  }
  else if (default_mon != NULL)
  {
    DECAF_mflush(default_mon);
  }
  else
  {
    fflush(stdout);
  }
}

void DECAF_mflush(Monitor* mon)
{
  monitor_flush(mon);
}

void DECAF_fflush(FILE* fp)
{
  if (fp != NULL)
  {
    fflush(fp);
  }
}

void DECAF_do_set_output_file(Monitor* mon, const char* fileName)
{
  DECAF_set_output_file(fileName);
}

void DECAF_set_output_file(const char* fileName)
{
  if (ofp != NULL)
  {
    return;
  }

  if (strcmp(fileName, "stdout") == 0)
  {
    DECAF_output_cleanup();
    return;
  }

  //open the file
  ofp = fopen(fileName, "w");
  if (ofp == NULL)
  {
    DECAF_printf("Could not open the file [%s]\n", fileName);
  }
}

void DECAF_set_output_mon(Monitor* mon)
{
  if (mon != NULL)
  {
    pMon = mon;
  }
}

void DECAF_output_cleanup(void)
{
  if (ofp != NULL)
  {
    fflush(ofp);
    fclose(ofp);
    ofp = NULL;
  }
  if (pMon != NULL)
  {
    monitor_flush(pMon); 
    pMon = NULL;
  }
  if (default_mon != NULL)
  {
    monitor_flush(default_mon);
  }
  else //should I just do an fflush anyways? - nah
  {
    fflush(stdout);
  }
}


FILE* DECAF_get_output_fp(void)
{
  return (ofp);
}

Monitor* DECAF_get_output_mon(void)
{
  if (pMon != NULL)
  {
    return (pMon);
  }
  else
  {
    return (default_mon);
  }
}

const FILE* DECAF_get_monitor_fp(void)
{
  return (DECAF_OUTPUT_MONITOR_FD);
}
