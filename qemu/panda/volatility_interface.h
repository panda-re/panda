#ifndef __VOL_INT_H__
#define __VOL_INT_H__

#include "panda_vol_int.pb-c.h"

/******** Common definitions ********/
#define VOL_CMD_LEN 1024

struct _vol_ll_node {
    size_t data_size;
    void *data_ptr;
    struct _vol_ll_node *next_ptr;
};
typedef struct _vol_ll_node vol_ll_node;
/******** Common interface functions ********/
vol_ll_node *vol_run_cmd(const char *cmd_name, const char *pmemaccess_path,
                         const char *profile);
char *vol_create_cmd(const char *file_path, const char *profile,
                     const char *command, const char *output_file);
ssize_t vol_read_len(int fd, void *data, int data_size, int data_len);
vol_ll_node *vol_create_ll(int vol_output_fd);

#endif
