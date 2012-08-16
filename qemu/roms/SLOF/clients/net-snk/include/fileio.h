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

#ifndef FILEIO_H
#define FILEIO_H
#include <sys/socket.h>

struct snk_fileio_type;
typedef struct snk_fileio_type snk_fileio_t;

#define FILEIO_TYPE_EMPTY 0
#define FILEIO_TYPE_USED  1

typedef long (*fileio_read_t)
	(snk_fileio_t *fileio, char *buf, long len);
typedef long (*fileio_write_t)
	(snk_fileio_t *fileio, char *buf, long len);
typedef int  (*fileio_ioctl_t)
	(snk_fileio_t *fileio, int request, void *data);
typedef int  (*fileio_bind_t)
	(snk_fileio_t *fileio, const struct sockaddr *, long len);
typedef int  (*fileio_connect_t)
	(snk_fileio_t *fileio, const struct sockaddr *, long len);
typedef int  (*fileio_close_t)
	(snk_fileio_t *fileio);

struct snk_fileio_type {
	int type;
	int idx;

	fileio_read_t    read;
	fileio_write_t   write;
	fileio_ioctl_t   ioctl;
	fileio_bind_t    bind;
	fileio_connect_t connect;
	fileio_close_t   close;

	void *data;
};

#define FILEIO_MAX 32
extern snk_fileio_t fd_array[FILEIO_MAX];

#endif
