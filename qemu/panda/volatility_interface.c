#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include "memory-access.h"
#include "panda_vol_int.pb-c.h"
#include "volatility_interface.h"

/*
 * Calls volatility with the specified options
 */
vol_ll_node *
vol_run_cmd(const char *cmd_name, const char *pmemaccess_path, const char *profile)
{
    FILE *vol_stream = NULL;
    char *vol_cmd = NULL;
    char *vol_output_file = NULL;
    int vol_output_fd = -1;
    vol_ll_node *ret = NULL;

    // Start pmemaccess interface
    memory_access_start(pmemaccess_path);

    // Create volatility command
    vol_output_file = calloc(L_tmpnam, sizeof(char));
    if (tmpnam(vol_output_file) == NULL) {
        fprintf(stderr, "Failed to create temporary output file\n");
        return NULL;
    }
    vol_cmd = vol_create_cmd(pmemaccess_path, profile, cmd_name,
                             vol_output_file);
    if (vol_cmd == NULL) {
	fprintf(stderr, "Failed to get volatility command string\n");
        return NULL;
    }

    // Run volatility
    vol_stream = popen(vol_cmd, "r");
    pclose(vol_stream);
    vol_output_fd = open(vol_output_file, O_RDONLY);
    ret = vol_create_ll(vol_output_fd);

    free(vol_output_file);
    free(vol_cmd);
    close(vol_output_fd);
    return ret;
}

/*
 * Creates a volatility command string that can be run
 */
char *
vol_create_cmd(const char *file_path, const char *profile,
               const char *command, const char *output_file)
{
    char *vol_cmd = calloc(VOL_CMD_LEN, sizeof(char));
    if (vol_cmd == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        return NULL;
    }

    // Build the command string
    snprintf(vol_cmd, VOL_CMD_LEN, "python ~/git/volatility/vol.py"
             " %s"
             " -f %s"
             " --profile=%s"
             " --output-file=%s"
             " --output=protobuf",
             command, file_path, profile, output_file);
    return vol_cmd;
}

/*
 * read wrapper that waits for a certion number of bytes
 */
ssize_t
vol_read_len(int fd, void *data, int data_size, int data_len)
{
    ssize_t read_len = 0;
    while (read_len != (data_size*data_len)) {
	read_len = read(fd, data, data_size * data_len);
	if (read_len == -1 || read_len == 0) break;
	if (read_len != (data_size*data_len))
	    lseek(fd, -read_len, SEEK_CUR);
	usleep(100);
    }
    return read_len;
}

/*
 * Reads protobuf data and creates a linked list
 */
vol_ll_node *
vol_create_ll(int vol_output_fd)
{
    char *vol_output = NULL;
    ssize_t read_len = 0;
    unsigned int item_len = 0;
    vol_ll_node *task_head = NULL;
    vol_ll_node *task_cur = NULL;
    char done = 0;

    while (!done) {
	// Read item size
	read_len = vol_read_len(vol_output_fd, &item_len, sizeof(unsigned int), 1);
	if (read_len == -1 || read_len == 0) break;
	// Read item data
        vol_output = calloc(item_len, sizeof(char));
	read_len = vol_read_len(vol_output_fd, vol_output, 1, item_len);
	if (read_len == -1 || read_len == 0) break;
	// Make a new task list entry
	if (task_head == NULL) {
	    task_head = calloc(1, sizeof(vol_ll_node));
	    task_cur = task_head;
	} else {
	    task_cur->next_ptr = calloc(1, sizeof(vol_ll_node));
	    task_cur = task_cur->next_ptr;
	}
	task_cur->data_size = item_len;
	task_cur->data_ptr = vol_output;
	task_cur->next_ptr = NULL;
    }

    return task_head;
}

