#pragma once

// Here we define functions osi_linux provides in addition to
// the standard osi API.

#define INVALID_FILE_POS (-1)

// returns fd for a filename or a NULL if failed
char *osi_linux_fd_to_filename(CPUState *env, OsiProc *p, int fd);

// returns pos in a file 
unsigned long long osi_linux_fd_to_pos(CPUState *env, OsiProc *p, int fd);

/* vim:set tabstop=4 softtabstop=4 expandtab: */
