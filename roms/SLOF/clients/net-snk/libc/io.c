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


#include "stddef.h"
#include "systemcall.h"
#include "unistd.h"


ssize_t write(int fd, const void *buf, size_t count)
{
    return syscall_3 (_write_sc_nr, fd, (long) buf, count);
}

ssize_t read(int fd, void *buf, size_t count)
{
    return syscall_3 (_read_sc_nr, fd, (long) buf, count);
}

ssize_t lseek(int fd, long off, int whence)
{
    return syscall_3 (_lseek_sc_nr, fd, off, whence);
}

int open(const char *name, int flags)
{
    return syscall_2 (_open_sc_nr, (long int) name, flags);
}

int close(int fd)
{
    return syscall_1(_close_sc_nr,fd);
}
