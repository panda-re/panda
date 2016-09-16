/*
 * Simple test that reads a file, labels a buffer, writes, then syncs it to
 * disk.  Then reads the file again, and queries taint.  Tests operation of hard
 * drive taint.  Opens file using O_DIRECT flag to minimize caching on Linux to
 * allow us to better observe taint transfers.  Assumes presence of a file
 * called 'taintfile' of at least 9728 bytes.
 */

#define _GNU_SOURCE

#include "assert.h"
#include "errno.h"
#include "fcntl.h"
#include "inttypes.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/stat.h"

#include "panda_mark.h"

int main(){
    int f = open("taintfile", O_DIRECT|O_RDWR);
    assert (f != -1);
    struct stat st;
    stat("taintfile", &st);
    assert(st.st_size != 0);
    char *buf;
    // Required for use of O_DIRECT.  Alignment has to be on the order of 512
    // bytes (size of a sector), and size has to be a multiple of the block
    // size.
    posix_memalign((void**)&buf, 512, 9728);
    int r = read(f, buf, 9728);
    if (r == -1){
        printf("Read Error %d\n", errno);
        exit(1);
    }
    
    label_buffer((uint64_t)buf, st.st_size);
    lseek(f, 0, SEEK_SET);
    r = write(f, buf, 9728);
    if (r == -1){
        printf("Write Error %d\n", errno);
        exit(1);
    }
    close(f);
    //memset(buf, 0, 9728); <-- Don't do this

    f = open("taintfile", O_DIRECT|O_RDWR);
    stat("taintfile", &st);
    assert(st.st_size != 0);
    r = read(f, buf, 9728);
    if (r == -1){
        printf("Read 2 Error %d\n", errno);
        exit(1);
    }
    query_buffer((uint64_t)buf, st.st_size);
    close(f);
    free(buf);
    
    return 0;
}

