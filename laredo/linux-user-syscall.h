#include <stdio.h>
#include <stdint.h>

void inst_open(int ret, void *p, int flags);
void inst_read(int fd, int ret, void *p);
void inst_write(int fd, int ret, void *p);
void inst_exit_group(void);

