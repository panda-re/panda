
#ifndef PANDALOG_READER
#include "panda_common.h"
#include "rr_log.h"
#endif


#include "pandalog.pb-c.h"
#include "pandalog.h"
#include "pandalog_print.h"
#include <zlib.h>
#include <stdlib.h>




// directory mapping instructions to chunks in the chunksfile
// say el[0].instr, el[1].instr = 0,1234
// that means chunk 0 contains all pandalog info for instructions 0..1233
// additionally, the data for compressed chunk 0 is in the chunksfile
// from pos[0] .. pos[1]-1
// invariants:
// el[i].start <= el[i].end
// el[i].end < el[i+1].start (they are in order)
// this means you can find the chunk for an instruction with binary search
typedef struct pandalog_dir_struct {
    uint32_t size;     // number of intervals
    uint64_t *instr;   // array of instr
    uint64_t *pos;     // array of file positions for start of chunk 
} PandalogDir;


typedef struct pandalog_struct {
    char *filename;       // filename of compressed log
    z_stream strm;        // zlib stream
    uint32_t chunk_size;  // in mb 
    uint32_t chunk;       // current chunk
    FILE *chunksfile;     // file to which we write compressed chunks
    PandalogDir dir;       
    uint8_t writep;       // 1 if log is open for write. 0 otherwise
} Pandalog;


Pandalog pandalog;


unsigned char *chunk_buf = 0;
unsigned char *chunk_buf_p = 0;



// compress current chunk and write it to chunksfile,
// also updating directory 
void write_current_chunk() {
    // actual chunk size
    uint32_t cs = chunk_buf_p - chunk_buf;
    if (cs == 0) return;
    pandalog.strm.avail_in = cs;
    pandalog.strm.next_in = chunk_buf;
    int ret = deflate(&(pandalog.strm), Z_NO_FLUSH);
    assert(ret != Z_STREAM_ERROR); 
    assert(pandalog.strm.avail_in == 0);
    uint32_t css = pandalog.strm.avail_out;
    assert(css > 0);
    assert(cs >= css);
    // size of compressed chunk
    printf ("writing chunk %d of pandalog %d / %d = %.2f compression\n",
            pandalog.chunk, cs, css, ((float) cs) / ((float) css)); 
    // position in chunksfile of start of this chunk
    uint64_t pos = ftell(pandalog.chunksfile);
    fwrite(chunk_buf, 1, css, pandalog.chunksfile);
    pandalog.dir
}


// we need to write n bytes to chunk_buf.  will it fit?
void check_write(size_t n) {
    // initial alloc
    if (chunk_buf == 0) {
        chunk_buf = (unsigned char *) malloc(pandalog.chunk_size);
        chunk_buf_p = chunk_buf;
        assert(n < pandalog.chunk_size);
        return;
    }
    if (chunk_buf_p - chunk_buf > n) {
        // find to write -- it fits
        return;
    }
    // write won't fit in current chunk.  
    // we need to move on to next chunk first
    write_current_chunk();
    // rewind chunk buf and inc chunk #
    chunk_buf_p = chunk_buf;
    pandalog.chunk ++;
}



// compression level
#define PL_Z_LEVEL 9
// 16 MB chunk
#define PL_CHUNKSIZE (1024 * 1024 * 16)

void __grow_pandalog_dir(uint32_t new_size) {
    assert (new_size > pandalog.dir.size);
    pandalog.dir.size = new_size;
    pandalog.dir.instr = (uint64_t *) realloc(pandalog.dir.instr, sizeof(uint64_t) * pandalog.dir.size);
    pandalog.dir.pos = (uint64_t *) realloc(pandalog.dir.pos, sizeof(uint64_t) * pandalog.dir.size);
}


// open pandalog for write
void pandalog_open_write(const char *path) {
    pandalog.writep = 1;
    pandalog.filename = path;
    pandalog.chunksfile = fopen(path, "w");
    pandalog.strm.zalloc = Z_NULL;
    pandalog.strm.zfree = Z_NULL;
    pandalog.strm.opaque = Z_NULL;
    int ret = deflateInit(&pandalog.strm, PL_Z_LEVEL);
    assert (ret == Z_OK);
    pandalog.chunk_size = PL_CHUNKSIZE;
    pandalog.chunk = 0;   
    // NB: dir will grow later if we need more than 128 chunks
    pandalog.dir.max_size = 128;
    pandalog.dir.size = 0;
    pandalog.dir.instr = (uint64_t *) malloc(sizeof(uint64_t) * pandalog.dir.max_size);
    pandalog.dir.pos = (uint64_t *) malloc(sizeof(uint64_t) * pandalog.dir.max_size);   
}


void pandalog_open(const char *path, const char *mode) {
    if (0 == strcmp(mode, "w")) {
        pandalog_open_write(path);
    }
    else {
        printf ("pandalog_open mode=[%s] not supported\n", mode);
        abort();
    }
}


int  pandalog_close(void) {
    if (pandalog.writep) {
        // finish current chunk & close chunksfile 
        write_current_chunk();
        // write out directory 
        uint32_t n = strlen(pandalog.filename);
        char *dirfilename = (char*) malloc(strlen(pandalog.filename)+4);
        dirfilename[0] = '\0';
        strcat(dirfilename, pandalog.filename);
        strcat(dirfilename, ".dir");
        FILE *dfp = fopen(dirfilename, "w");
        PandalogDir *dir = &(pandalog.dir);
        fwrite(&(dir->size), sizeof(dir->size), 1, dfp);
        uint32_t i;
        for (i=0; i<dir->size; i++) {
            fwrite(&(dir->el[i].instr), sizeof(dir->el[i].start), 1, dfp);
            fwrite(&(dir->pos[i]), sizeof(dir->pos[i]), 1, dfp);
        }
        fclose(dfp);
    }
    fclose(pandalog.chunksfile);
}
extern int panda_in_main_loop;


uint64_t instr_last_entry = 0;

#ifndef PANDALOG_READER
void pandalog_write_entry(Panda__LogEntry *entry) {
    // fill in required fields. 
    if (panda_in_main_loop) {
        entry->pc = panda_current_pc(cpu_single_env);
        entry->instr = rr_get_guest_instr_count ();
    }
    else {        
        entry->pc = -1;
        entry->instr = -1;
    }
    size_t n = panda__log_entry__get_packed_size(entry);   
    // possibly compress and write current chunk
    // but dont 
    if (instr_last_entry != entr->instr) {
        check_write(n+4);
    }
    // write size of log entry first
    *((uint32_t *) chunk_buf_p) = n;
    chunk_buf_p += sizeof(uin32_t);
    // and then the entry itself (packed)
    panda__log_entry__pack(entry, chunk_buf_p);
    instr_last_entry = entry->instr;
}
#endif

/*
Panda__LogEntry *pandalog_read_entry(void) {
    // read the size of the log entry
    size_t n,nbr;
    nbr = gzread(pandalog_file, (void *) &n, sizeof(n));
    if (nbr == 0) {
        return NULL;
    }
    resize_pandalog(n);
    // and then read the entry iself
    gzread(pandalog_file, chunk_buf, n);
    // and unpack it
    Panda__LogEntry *ple = panda__log_entry__unpack(NULL, n, chunk_buf);                                             
    if (ple == NULL) {
	return (Panda__LogEntry *)1; //yay special values
    }
    return ple;
}
*/

void pandalog_free_entry(Panda__LogEntry *entry) {    
    panda__log_entry__free_unpacked(entry, NULL);
}



