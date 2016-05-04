/*
  The Pandalog has three sections. 


  Section 1: The header
  ---------------------
  Bytes 0 .. PL_HEADER_SIZE-1

  Currently, the header consists of just three ints

  u32 version      (a version number)
  u64 dir_pos     (file position of directory)
  u32 chunk_size  (size of an uncompressed chunk for this log)

  That's just 16 bytes.  Header is currently 128 so lots of room


  Section 2: The chunks
  ---------------------
  Byte PL_HEADER_SIZE .. dir_pos-1

  This is where the compressed chunks go.  As we write the pandalog,
  we fill a buffer with raw, uncompressed entries.  When we have gone
  over the chunk_size and done with all entries for an instruction, we
  compress that chunk of pandalog and write it to the file, keeping
  track in an array the file position of the start of each chunk.  The
  next compressed chunk data will go right after the previous
  compressed chunk data.

  CHUNKS section is just a sequence of compressed chunk data, varying
  in length.  Only way to tell where one compressed chunk starts and
  next ends is via the DIRECTORY.


  Section 3: The directory 
  ------------------------
  Byte dir_pos .. end of file

  The directory goes here.  It contains a map which one can use to
  locate the compressed chunk corresponding to a particular
  instruction in the CHUNKS section of the pandalog file. 

  uint32_t num_chunks               How many chunks are in CHUNKS sec 
  uint64_t start_instr_chunk_0      First instruction in chunk 0
  uint64_t start_pos_chunk_0        File position of beginning of chunk 0
  uint64_t start_instr_chunk_1      ... for chunk 1
  uint64_t start_pos_chunk_1        ... for chunk 1
  ...
  uint64_t start_instr_chunk_n      ... for chunk n, where n == num_chunks-1
  uint64_t start_pos_chunk_n        ... for chunk n

*/

#ifndef PANDALOG_READER
#include "panda_common.h"
#include "rr_log.h"
#endif

#include <string.h>
#include <math.h>
#include "pandalog.pb-c.h"
#include "pandalog.h"
#include "pandalog_print.h"
#include <zlib.h>
#include <stdlib.h>

Pandalog *thePandalog = NULL;

void pandalog_create(uint32_t chunk_size);
void add_dir_entry(uint32_t chunk);
void write_current_chunk(void);
void write_header(PlHeader *plh);
void write_dir(void);
void pandalog_open_write(const char *path, uint32_t chunk_size);
void pandalog_write_entry(Panda__LogEntry *entry);
int pandalog_close_write(void);
int pandalog_close_write(void);
uint8_t in_read_mode(void);
PlHeader *read_header(void);
void read_dir(void);
void pandalog_open_read(const char *path, uint32_t pl_mode);
void pandalog_open_read_fwd(const char *path);
void pandalog_open_read_bwd(const char *path);
void pandalog_open(const char *path, const char *mode);
int  pandalog_close(void);
void unmarshall_chunk(uint32_t c);
Panda__LogEntry *pandalog_read_entry(void);
uint32_t find_chunk(uint64_t instr, uint32_t i1, uint32_t i2);
void pandalog_free_entry(Panda__LogEntry *entry);
void pandalog_seek(uint64_t instr);
uint32_t find_ind(uint64_t instr, uint32_t i1, uint32_t i2);
 
void pandalog_create(uint32_t chunk_size) {
    assert (thePandalog == NULL);
    thePandalog = (Pandalog *) malloc(sizeof(Pandalog));
    thePandalog->mode = PL_MODE_UNKNOWN;
    thePandalog->filename = NULL;
    thePandalog->file = NULL;
    thePandalog->dir.max_chunks = 0;
    thePandalog->dir.instr = 0;
    thePandalog->dir.pos = 0;
    thePandalog->dir.num_entries = 0;
    thePandalog->chunk.size = chunk_size;
    thePandalog->chunk.zsize = chunk_size;
    // NB: malloc chunk a little big since we need to maintain
    // the invariant that all log entries for an instruction reside in same
    // chunk.  this should be big enough but don't worry, we'll be monitoring it.
    thePandalog->chunk.buf = (unsigned char *) malloc(thePandalog->chunk.size * SLACK_MULT);
    thePandalog->chunk.buf_p = thePandalog->chunk.buf;
    thePandalog->chunk.zbuf = (unsigned char *) malloc(thePandalog->chunk.zsize * SLACK_MULT);
    thePandalog->chunk.start_instr = 0;
    thePandalog->chunk.start_pos = PL_HEADER_SIZE;
    thePandalog->chunk.entry = 0;
    thePandalog->chunk.num_entries = 0;
    thePandalog->chunk.max_num_entries = 0;
    thePandalog->chunk.ind_entry = 0;
    return;
}

/*
 this code is all about writing a pandalog which needs PANDA things.
 So it won't compile with reader which is divorced from PANDA 
*/

#ifndef PANDALOG_READER

// add dir entry for this chunk
void add_dir_entry(uint32_t chunk) {
    if (chunk >= thePandalog->dir.max_chunks) {
        uint32_t new_size = thePandalog->dir.max_chunks * 2;
        thePandalog->dir.instr = (uint64_t *) realloc(thePandalog->dir.instr, sizeof(uint64_t) * new_size);
        thePandalog->dir.pos = (uint64_t *) realloc(thePandalog->dir.pos, sizeof(uint64_t) * new_size);
        thePandalog->dir.num_entries = (uint64_t *) 
            realloc(thePandalog->dir.num_entries, sizeof(uint64_t) * new_size);
        thePandalog->dir.max_chunks = new_size;
    }
    assert (chunk <= thePandalog->dir.max_chunks);
    // this is start instr and start file position for this chunk
    thePandalog->dir.instr[chunk] = thePandalog->chunk.start_instr;
    thePandalog->dir.pos[chunk] = thePandalog->chunk.start_pos;
    // and this is the number of entries in this chunk
    thePandalog->dir.num_entries[chunk] = thePandalog->chunk.ind_entry;
}

// compress current chunk and write it to file,
// also update directory map
void write_current_chunk(void) {
    // uncompressed chunk size
    unsigned long cs = thePandalog->chunk.buf_p - thePandalog->chunk.buf;
    unsigned long ccs = thePandalog->chunk.zsize;
    int ret;
    // loop allows compress2 to fail and resize output buffer as needed
    // not sure why compress2 needs output buf to be bigger than input
    // even though ultimately it is smaller.  scratch space?
    // 10 is just a random guess.  shouldn't need more than 1 re-try
    uint32_t i;
    for (i=0; i<10; i++) {
        ret = compress2(thePandalog->chunk.zbuf, &ccs, thePandalog->chunk.buf, cs, Z_BEST_COMPRESSION);
        if (ret == Z_OK) break;
        // bigger output buffer needed to perform compression?
        thePandalog->chunk.zsize *= SLACK_MULT;
        thePandalog->chunk.zbuf = (unsigned char *) realloc(thePandalog->chunk.zbuf, thePandalog->chunk.zsize);
        assert (thePandalog->chunk.zbuf != NULL);
    }
    // ccs is final compressed chunk size
    assert (ret == Z_OK);
    assert(ccs > 0);
    assert(cs >= ccs);
    printf ("writing chunk %d of pandalog %d / %d = %.2f compression\n",
            (int) thePandalog->chunk_num, (int) cs, (int) ccs, ((float) cs) / ((float) ccs)); 
    fwrite(thePandalog->chunk.zbuf, 1, ccs, thePandalog->file);
    add_dir_entry(thePandalog->chunk_num);
    // reset start instr / pos
    thePandalog->chunk.start_instr = rr_get_guest_instr_count();
    thePandalog->chunk.start_pos = ftell(thePandalog->file);
    // rewind chunk buf and inc chunk #
    thePandalog->chunk.buf_p = thePandalog->chunk.buf;
    thePandalog->chunk_num ++;
    thePandalog->chunk.ind_entry = 0;
}

// write the pandalog header
void write_header(PlHeader *plh) {
    assert (thePandalog->file != NULL);
    // rewind to start of logfile and write header
    fseek(thePandalog->file, 0, SEEK_SET);
    fwrite(plh, sizeof(*plh), 1, thePandalog->file); 
}

// write the directory and header
// assumes we have written entire pandalog and thus
// have directory info to actualy write
void write_dir(void) {
    assert (thePandalog->file != NULL);
    PandalogDir *dir = &(thePandalog->dir);
    uint32_t num_chunks = thePandalog->chunk_num;
    assert (num_chunks > 0);
    // create header
    PlHeader plh;
    plh.version = PL_CURRENT_VERSION;
    // file position of directory info
    plh.dir_pos = ftell(thePandalog->file);        
    plh.chunk_size = thePandalog->chunk.size;
    printf ("header: version=%d  dir_pos=%" PRIx64 " chunk_size=%d\n",
            plh.version, plh.dir_pos, plh.chunk_size);   
    // now go ahead and write dir where we are in logfile
    fwrite(&(num_chunks), sizeof(num_chunks), 1, thePandalog->file);
    uint32_t i;
    for (i=0; i<num_chunks; i++) {
        fwrite(&(dir->instr[i]), sizeof(dir->instr[i]), 1, thePandalog->file);
        fwrite(&(dir->pos[i]), sizeof(dir->pos[i]), 1, thePandalog->file);
        fwrite(&(dir->num_entries[i]), sizeof(dir->num_entries[i]), 1, thePandalog->file);
    }
    // finally write header
    write_header(&plh);
}

// open pandalog for write
// path is the chunks file
// path + '.dir' is the directory
void pandalog_open_write(const char *path, uint32_t chunk_size) {
    pandalog_create(chunk_size);
    thePandalog->mode = PL_MODE_WRITE;
    thePandalog->filename = strdup(path);
    thePandalog->file = fopen(path, "w");
    // skip over header to be ready to write first chunk
    // NB: we will write the header later, when we write the directory.
    fseek(thePandalog->file, thePandalog->chunk.start_pos, SEEK_SET);
    // NB: dir will grow later if we need more than 128 chunks
    thePandalog->dir.max_chunks = 128;
    thePandalog->dir.instr = (uint64_t *) malloc(sizeof(uint64_t) * thePandalog->dir.max_chunks);
    thePandalog->dir.pos = (uint64_t *) malloc(sizeof(uint64_t) * thePandalog->dir.max_chunks);       
    thePandalog->dir.num_entries = (uint64_t *) malloc(sizeof(uint64_t) * thePandalog->dir.max_chunks);       
    thePandalog->chunk_num = 0;
    printf ("max_chunks = %d\n", thePandalog->dir.max_chunks);
}

extern int panda_in_main_loop;

uint64_t instr_last_entry = -1;

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
    // possibly compress and write current chunk and move on to next chunk
    // but dont do so if it would spread log entries for same instruction between chunks
    // invariant: all log entries for an instruction belong in a single chunk
    if ((instr_last_entry != -1)  // first entry written
        && (instr_last_entry != entry->instr) 
        && (thePandalog->chunk.buf_p + n >= thePandalog->chunk.buf + thePandalog->chunk.size)) {
        // entry  won't fit in current chunk
        // and new entry is a different instr from last entry written
        write_current_chunk();
    }
    // sanity check.  If this fails, that means a large number of pandalog entries
    // for same instr went off the end of a chunk, which was already allocated bigger than needed.  
    // possible.  but I'd rather assert its not and understand why before adding auto realloc here.
    assert (thePandalog->chunk.buf_p + sizeof(uint32_t) + n 
            < thePandalog->chunk.buf + ((int)(floor(thePandalog->chunk.size * SLACK_MULT))));
    // now write the entry itself to the buffer.  size then entry itself
    *((uint32_t *) thePandalog->chunk.buf_p) = n;
    thePandalog->chunk.buf_p += sizeof(uint32_t);
    // and then the entry itself (packed)
    panda__log_entry__pack(entry, thePandalog->chunk.buf_p);
    thePandalog->chunk.buf_p += n;
    // remember instr for last entry
    instr_last_entry = entry->instr;
    thePandalog->chunk.ind_entry ++;
}

int pandalog_close_write(void) {
    // finish current chunk then write directory info and header
    write_current_chunk();        
    // Not a mistake!
    // this will add one more dir entry for last instr and file pos
    add_dir_entry(thePandalog->chunk_num);
    write_dir();
    return 0;
}

#endif 

uint8_t in_read_mode(void) {
    if (thePandalog->mode == PL_MODE_READ_FWD
        || thePandalog->mode == PL_MODE_READ_BWD)
        return 1;
    return 0;
}

// read header out of pandalog and return it
PlHeader *read_header(void) {
    assert (thePandalog->file != NULL);
    // header is at start of logfile
    fseek(thePandalog->file, 0, SEEK_SET);
    PlHeader *plh = (PlHeader *) malloc(sizeof(PlHeader));
    int n = fread(plh, 1, sizeof(*plh), thePandalog->file); 
    assert (n == sizeof(*plh));
    return plh;
}

// read directory info out of
// pandalog file
void read_dir(void) {
    assert (thePandalog->file != NULL);
    assert(in_read_mode());
    PlHeader *plh = read_header();
    thePandalog->chunk.size = plh->chunk_size * SLACK_MULT;
    thePandalog->chunk.zsize = plh->chunk_size * SLACK_MULT;
    // realloc those chunk bufs
    thePandalog->chunk.buf = (unsigned char *)
        realloc(thePandalog->chunk.buf, thePandalog->chunk.size);
    thePandalog->chunk.buf_p = thePandalog->chunk.buf;
    thePandalog->chunk.zbuf = (unsigned char *)
        realloc(thePandalog->chunk.zbuf, thePandalog->chunk.zsize);
    fseek(thePandalog->file, plh->dir_pos, SEEK_SET);
    uint32_t nc;
    int n = fread(&(nc), 1, sizeof(nc), thePandalog->file);
    assert (n == sizeof(nc));
    PandalogDir *dir = &(thePandalog->dir);
    dir->max_chunks = nc;
    dir->instr = (uint64_t *) malloc(sizeof(uint64_t) * nc);
    dir->pos = (uint64_t *) malloc(sizeof(uint64_t) * (1+nc));
    dir->num_entries = (uint64_t *) malloc(sizeof(uint64_t) * nc);
    uint32_t i;
    for (i=0; i<nc; i++) {
        int n = fread(&(dir->instr[i]), 1, sizeof(dir->instr[i]), thePandalog->file);
        assert (n == sizeof(dir->instr[i]));
        n = fread(&(dir->pos[i]), 1, sizeof(dir->pos[i]), thePandalog->file);        
        assert (n == sizeof(dir->pos[i]));
        n = fread(&(dir->num_entries[i]), 1, sizeof(dir->num_entries[i]), thePandalog->file);
        assert (n == sizeof(dir->num_entries[i]));
    }
    // a little hack so unmarshall_chunk will work
    dir->pos[nc] = plh->dir_pos;
}    

void pandalog_open_read(const char *path, uint32_t pl_mode) {
    // NB: 0 chunk size for now -- read_dir will figure this out
    pandalog_create(0);
    thePandalog->mode = (PlMode) pl_mode;
    assert (in_read_mode());
    thePandalog->filename = strdup(path);
    thePandalog->file = fopen(path, "r");
    // read directory (and header)
    read_dir();    
    thePandalog->chunk_num = 0;   
    if (pl_mode == PL_MODE_READ_FWD) {
        // seek to first chunk and unmarshall it
        pandalog_seek(0);
    }
    if (pl_mode == PL_MODE_READ_BWD) {
        // seek to last chunk and unmarshall it
        pandalog_seek(-1);
    }
}

void pandalog_open_read_fwd(const char *path) {
    pandalog_open_read(path, PL_MODE_READ_FWD);
}

void pandalog_open_read_bwd(const char *path) {
    pandalog_open_read(path, PL_MODE_READ_BWD);
}

void pandalog_open(const char *path, const char *mode) {
    if (0==strcmp(mode, "w")) {
#ifndef PANDALOG_READER   
        pandalog_open_write((const char *) path, (uint32_t) PL_CHUNKSIZE);
#endif
    }
    if (0==strcmp(mode, "r")) {
        pandalog_open_read_fwd(path);
    }
}

int  pandalog_close(void) {
    if (thePandalog->mode == PL_MODE_WRITE) {
#ifndef PANDALOG_READER
        pandalog_close_write();
#endif
    }
    fclose(thePandalog->file);
    return 0;
}

static void __pandalog_free_entry(Panda__LogEntry *entry) {    
    panda__log_entry__free_unpacked(entry, NULL);
}

uint8_t unmarshall_chunk_first_time = 1;
    
// uncompress this chunk, ready for use
void unmarshall_chunk(uint32_t c) {
    printf ("unmarshalling chunk %d\n", c);
    PandalogChunk *chunk = &(thePandalog->chunk);
    // read compressed chunk data off disk
    int ret = fseek(thePandalog->file, thePandalog->dir.pos[c], SEEK_SET);
    assert (ret == 0);
    unsigned long ccs = thePandalog->dir.pos[c+1] - thePandalog->dir.pos[c] + 1;
    uint32_t n = fread(chunk->zbuf, 1, ccs, thePandalog->file);
    assert (ccs == n);
    unsigned long cs = chunk->size;
    // uncompress it
    printf ("cs=%d ccs=%d\n", (int) cs, (int) ccs);
    ret = uncompress(chunk->buf, &cs, chunk->zbuf, ccs);
    assert (ret == Z_OK);
    thePandalog->chunk_num = c;
    // realloc current chunk arrays if necessary
    if (chunk->max_num_entries < thePandalog->dir.num_entries[c]) {
        chunk->max_num_entries = thePandalog->dir.num_entries[c] * SLACK_MULT;
        chunk->entry = 
            (Panda__LogEntry **) 
            realloc(chunk->entry, 
                    sizeof(Panda__LogEntry *) * chunk->max_num_entries);
    }      
    chunk->num_entries = thePandalog->dir.num_entries[c];
    // unpack pandalog entries out of uncompressed buffer into array of pl entries
    unsigned char *p = chunk->buf;
    uint32_t i;
    for (i=0; i<chunk->num_entries; i++) {
        if (!unmarshall_chunk_first_time && chunk->entry[i] != NULL) {
            // need to free previous chunk's pandalog entries
            __pandalog_free_entry(chunk->entry[i]);
        }
        assert (p < chunk->buf + cs);
        uint32_t n = *((uint32_t *) p);
        p += sizeof(uint32_t);
        Panda__LogEntry *ple = panda__log_entry__unpack(NULL, n, p);
        p += n;
        chunk->entry[i] = ple;
    }
    chunk->ind_entry = 0;  // a guess 
    unmarshall_chunk_first_time = 0;
}

Panda__LogEntry *pandalog_read_entry(void) {
    assert (in_read_mode);
    PandalogChunk *plc = &(thePandalog->chunk);
    uint8_t done = 0;
    uint8_t new_chunk = 0;
    uint32_t new_chunk_num;
    if (thePandalog->mode == PL_MODE_READ_FWD) {
        if (plc->ind_entry == plc->num_entries-1) {
            if (thePandalog->chunk_num == thePandalog->dir.max_chunks - 1) done = 1;                
            else {
                new_chunk_num = thePandalog->chunk_num + 1;            
                new_chunk = 1;
            }
        }
        else plc->ind_entry ++;
    }
    if (thePandalog->mode == PL_MODE_READ_BWD) {
        if (plc->ind_entry == 0) {
            if (thePandalog->chunk_num == 0) done = 1;
            else {
                new_chunk_num = thePandalog->chunk_num - 1;
                new_chunk = 1;
            }
        }
        else plc->ind_entry --;
    }
    if (done) {
        // no more entries to read -- last chunk complete
        return NULL;
    }
    if (new_chunk) {
        thePandalog->chunk_num = new_chunk_num;
        unmarshall_chunk(new_chunk_num);        
        // can't use plc anymore
        plc = &(thePandalog->chunk);
        if (thePandalog->mode == PL_MODE_READ_FWD) 
            plc->ind_entry = 0;
        else 
            plc->ind_entry = thePandalog->dir.num_entries[new_chunk_num]-1;
    }
    return plc->entry[plc->ind_entry];
}

// binary search to find chunk for this instr
uint32_t find_chunk(uint64_t instr, uint32_t c1, uint32_t c2) {
    assert (c1 <= c2);
    if (c1 == c2) return c1;
    uint32_t mid = (c1 + c2) / 2;
    // if we ask for instr that is before every instr in log or after every one, 
    // return first / last chunk
    if (instr < thePandalog->dir.instr[c1]) return c1;
    if (instr > thePandalog->dir.instr[c2]) return c2;
    if (thePandalog->dir.instr[c1] <= instr && instr <= thePandalog->dir.instr[mid]) {
        return find_chunk(instr, c1, mid);
    }
    assert (thePandalog->dir.instr[mid] <= instr && instr <= thePandalog->dir.instr[c2]);
    return find_chunk(instr, mid, c2);
}


void pandalog_free_entry(Panda__LogEntry *entry) {    
    // ok no, you aren't allowed to do this from outside anymore
    // the chunk owns that data and frees it when it wants
}

// another binary search to find first index into current chunk for this instr
uint32_t find_ind(uint64_t instr, uint32_t i1, uint32_t i2) {
    assert (i1 <= i2);
    if (i1 == i2) return i1;
    uint32_t mid = (i1 + i2) / 2;
    PandalogChunk *chunk = &(thePandalog->chunk);
    if (instr < chunk->entry[i1]->instr) {
        // just means first instr in log is after what we want
        return i1;
    }
    if (instr > chunk->entry[i2]->instr) {
        // just means we asked for instr that is after last instr in log
        return i2;
    }
    if (chunk->entry[i1]->instr <= instr && instr <= chunk->entry[mid]->instr) {
        return find_chunk(instr, i1, mid);
    }
    assert (chunk->entry[mid]->instr <= instr && instr <= chunk->entry[i2]->instr);
    return find_chunk(instr, mid, i2);
}


void pandalog_seek(uint64_t instr) {
    assert(in_read_mode());
    // figure out which chunk this instr in is
    uint32_t c = find_chunk(instr, 0, thePandalog->dir.max_chunks-1);
    thePandalog->chunk_num = c;
    unmarshall_chunk(c);
    // figure out ind
    uint32_t ind = find_ind(instr, 0, thePandalog->dir.num_entries[c]-1);
    if (thePandalog->mode == PL_MODE_READ_BWD) {
        // need *last* entry with that instr for backward mode
        uint32_t i;
        //        uint8_t found_entry = 0;
        for (i=ind; i<thePandalog->dir.num_entries[c]; i++) {
            Panda__LogEntry *ple = thePandalog->chunk.entry[i];
            if (ple->instr != instr || instr > ple->instr) {
                ind --;
                break;
            }
        }
    }
    thePandalog->chunk.ind_entry = ind;
}
                                                               


