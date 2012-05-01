/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/


#ifndef SYSTEMCALL_H
#define SYSTEMCALL_H

extern inline int
syscall (int nr)
{
    register unsigned long r0 asm("r0") = nr;
    register unsigned long r3 asm("r3");
    asm volatile ("sc" : "=r" (r3) 
                       : "r" (r0));
    return r3;
} 

extern inline long
syscall_1 (int nr, long arg0)
{
    register unsigned long r0 asm("r0") = nr;
    register unsigned long r3 asm("r3") = arg0;
    asm volatile ("sc" : "=r" (r3) 
                       : "0" (r3), "r" (r0));
    return r3;
} 

extern inline long
syscall_2 (int nr, long arg0, long arg1)
{
    register unsigned long r0 asm("r0") = nr;
    register unsigned long r3 asm("r3") = arg0;
    register unsigned long r4 asm("r4") = arg1;
    asm volatile ("sc" : "=r" (r3) 
		       : "0" (r3), "r" (r4), "r" (r0)); 
    return r3;
} 

extern inline long
syscall_3 (int nr, long arg0, long arg1, long arg2)
{
    register unsigned long r0 asm("r0") = nr;
    register unsigned long r3 asm("r3") = arg0;
    register unsigned long r4 asm("r4") = arg1;
    register unsigned long r5 asm("r5") = arg2;
    asm volatile ("sc" : "=r" (r3) 
		       : "0" (r3), "r" (r4), "r" (r5), "r" (r0)); 
    return r3;
} 

extern inline long
syscall_4 (int nr, long arg0, long arg1, long arg2, long arg3)
{
    register unsigned long r0 asm("r0") = nr;
    register unsigned long r3 asm("r3") = arg0;
    register unsigned long r4 asm("r4") = arg1;
    register unsigned long r5 asm("r5") = arg2;
    register unsigned long r6 asm("r6") = arg3;
    asm volatile ("sc" : "=r" (r3) 
		       : "0" (r3), "r" (r4), "r" (r5), "r" (r6), "r" (r0)); 
    return r3;
} 

extern inline long
syscall_5 (int nr, long arg0, long arg1, long arg2, long arg3, 
	   long arg4)
{
    register unsigned long r0 asm("r0") = nr;
    register unsigned long r3 asm("r3") = arg0;
    register unsigned long r4 asm("r4") = arg1;
    register unsigned long r5 asm("r5") = arg2;
    register unsigned long r6 asm("r6") = arg3;
    register unsigned long r7 asm("r7") = arg4;
    asm volatile ("sc" : "=r" (r3) 
		       : "0" (r3), "r" (r4), "r" (r5), 
		         "r" (r6), "r" (r7), "r" (r0)); 
    return r3;
} 

extern inline long
syscall_6 (int nr, long arg0, long arg1, long arg2, long arg3, 
	   long arg4, long arg5)
{
    register unsigned long r0 asm("r0") = nr;
    register unsigned long r3 asm("r3") = arg0;
    register unsigned long r4 asm("r4") = arg1;
    register unsigned long r5 asm("r5") = arg2;
    register unsigned long r6 asm("r6") = arg3;
    register unsigned long r7 asm("r7") = arg4;
    register unsigned long r8 asm("r8") = arg5;
    asm volatile ("sc" : "=r" (r3) 
		       : "0" (r3), "r" (r4), "r" (r5), 
		         "r" (r6), "r" (r7), "r" (r8), "r" (r0)); 
    return r3;
} 

extern inline long
syscall_7 (int nr, long arg0, long arg1, long arg2, long arg3, 
	   long arg4, long arg5, long arg6)
{
    register unsigned long r0 asm("r0") = nr;
    register unsigned long r3 asm("r3") = arg0;
    register unsigned long r4 asm("r4") = arg1;
    register unsigned long r5 asm("r5") = arg2;
    register unsigned long r6 asm("r6") = arg3;
    register unsigned long r7 asm("r7") = arg4;
    register unsigned long r8 asm("r8") = arg5;
    register unsigned long r9 asm("r9") = arg6;
    asm volatile ("sc" : "=r" (r3) 
		       : "0" (r3), "r" (r4), "r" (r5), 
		         "r" (r6), "r" (r7), "r" (r8), 
		         "r" (r9), "r" (r0)); 
    return r3;
} 


#define _exit_sc_nr 1
#define _read_sc_nr 2
#define _write_sc_nr 3
#define _open_sc_nr 4
#define _close_sc_nr 5
#define _getpid_sc_nr 6
#define _brk_sc_nr 7
#define _ioctl_sc_nr 8
#define _socket_sc_nr 9
#define _wait4_sc_nr 10
#define _sigreturn_sc_nr 11
#define _rt_sigaction_sc_nr 12
#define _lseek_sc_nr 13

#define _sock_sc_nr 1
#define _sendto_sc_nr 2
#define _send_sc_nr 3
#define _recv_sc_nr 4


//typedef unsigned long size_t; 

#endif
