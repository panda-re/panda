#ifndef __OSI_LINUX_INT_FNS_H__
#define __OSI_LINUX_INT_FNS_H__

// Here we define functions osi_linux provides in addition to
// the standard osi API.

// resolves an fd to a filename or a made-up name if not a file
char *osi_linux_resolve_fd(CPUState *env, OsiProc *p, int fd);

#endif

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
