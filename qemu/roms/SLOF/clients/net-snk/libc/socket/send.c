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


#include "sys/socket.h"

int socket(int dom, int type, int proto, char *mac_addr)
{
    return syscall_5 (_socket_sc_nr, _sock_sc_nr, dom, type, proto, (long)mac_addr);
}

int sendto(int fd, const void* buffer, int len, int flags, const void* sock_addr, int sock_addr_len)
{
    return syscall_7 (_socket_sc_nr, _sendto_sc_nr, fd, (long) buffer, len, flags, (long) sock_addr, sock_addr_len);
}

int send(int fd, void* buffer, int len, int flags)
{
    return syscall_5 (_socket_sc_nr, _send_sc_nr, fd, (long) buffer, len, flags);
}

int recv(int fd, void* buffer, int len, int flags)
{
    return syscall_5 (_socket_sc_nr, _recv_sc_nr, fd, (long) buffer, len, flags);
}


