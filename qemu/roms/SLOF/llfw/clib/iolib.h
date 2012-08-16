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

#ifndef IOLIB_H
#define IOLIB_H

#include <stdint.h>

#define addr_t  	volatile unsigned int
#define addr8_t 	volatile unsigned char

extern void     halt_sys (unsigned int);

extern uint32_t get_sb_version (void);

extern void     uart_send_byte(unsigned char b);
extern void     io_putchar(unsigned char);

extern uint64_t tb_frequency(void);
extern uint64_t be_frequency(void);

extern uint32_t get_dec(void);
extern void     set_dec(uint32_t);
extern void     delay_ms( unsigned int ms );

#endif
