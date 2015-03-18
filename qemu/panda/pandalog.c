
#ifndef PANDALOG_READER
#include "panda_common.h"
#include "rr_log.h"
#endif


#include "pandalog.pb-c.h"
#include "pandalog.h"
#include <zlib.h>
#include <stdlib.h>

gzFile pandalog_file = 0;

uint32_t pandalog_buf_size = 16;
unsigned char *pandalog_buf = 0;

void resize_pandalog(size_t n);


void resize_pandalog(size_t n) {
    if (pandalog_buf == 0) {
        pandalog_buf = (unsigned char *) malloc(pandalog_buf_size);
    }
    int size_changed = 0;
    while (n > pandalog_buf_size) {
        size_changed = 1;
        pandalog_buf_size *= 2;
        //        printf ("increasing pandalog buf to %d bytes\n", pandalog_buf_size);
    }
    if (size_changed) {
        pandalog_buf = (unsigned char *) realloc(pandalog_buf, pandalog_buf_size);
    }
}



// open for read or write
void pandalog_open(const char *path, const char *mode) {
    pandalog_file = gzopen(path, mode);
}


int  pandalog_close(void) {
    return gzclose(pandalog_file);  
}

extern int panda_in_main_loop;


#ifndef PANDALOG_READER
void pandalog_write_entry(Panda__LogEntry *entry) {
    // fill in required fields. 
    // NOTE: any other fields will already have been filled in 
    // by the plugin that made this call.  
    if (panda_in_main_loop) {
        entry->pc = panda_current_pc(cpu_single_env);
        entry->instr = rr_get_guest_instr_count ();
    }
    else {        
        entry->pc = -1;
        entry->instr = -1;
    }
    size_t n = panda__log_entry__get_packed_size(entry);   
    resize_pandalog(n);
    panda__log_entry__pack(entry, pandalog_buf);
    // write size of log entry
    gzwrite(pandalog_file, (void *) &n, sizeof(n));
    // and then the entry itself
    gzwrite(pandalog_file, pandalog_buf, n);        
}
#endif

Panda__LogEntry *pandalog_read_entry(void) {
    // read the size of the log entry
    size_t n,nbr;
    nbr = gzread(pandalog_file, (void *) &n, sizeof(n));
    if (nbr == 0) {
        return NULL;
    }
    resize_pandalog(n);
    // and then read the entry iself
    gzread(pandalog_file, pandalog_buf, n);
    // and unpack it
    return panda__log_entry__unpack(NULL, n, pandalog_buf);                                             
}


void pandalog_free_entry(Panda__LogEntry *entry) {    
    panda__log_entry__free_unpacked(entry, NULL);
}



