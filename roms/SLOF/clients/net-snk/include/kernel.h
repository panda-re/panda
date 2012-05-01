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

#ifndef KERNEL_H
#define KERNEL_H
#include <stddef.h>

int printk(const char *, ...);
void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
void udelay(unsigned int);
void mdelay(unsigned int);
int getchar(void);

int strcmp(const char *, const char *);
char *strcpy(char *, const char *);
int printf(const char *, ...);
void *malloc_aligned(size_t size, int align);

void exception_forward(void);
void undo_exception(void);

#endif
