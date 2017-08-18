#include <iostream>
#include <math.h>
#include <fstream>
#include <memory>
#include "panda/plog.hpp"

extern "C" {

}

using namespace std; 

Pandalog *thePandalog = NULL;
//XXX: Remove later
int rr_fake_guest_instr_count = 0;
int rr_fake_pc = 0;

PlHeader* pandalog_read_header();
void pandalog_read_dir();
void unmarshall_chunk(uint32_t chunk_num);
void pandalog_open_file(const char * fname);
void add_dir_entry(uint32_t chunk_num);
void write_current_chunk();

void pandalog_create(uint32_t chunk_size) {
    assert (thePandalog == NULL);
    /*thePandalog = (Pandalog *) malloc(sizeof(Pandalog));*/
    thePandalog = new Pandalog();
    thePandalog->mode = PL_MODE_UNKNOWN;
    thePandalog->filename = NULL;
    thePandalog->file = NULL;
    /*thePandalog->dir.instr = std::vector<uint64_t>(0);*/
    /*thePandalog->dir.pos = std::vector<uint64_t>(0);*/
    /*thePandalog->dir.num_entries = std::vector<uint64_t>(0); */
    thePandalog->chunk.size = chunk_size;
    thePandalog->chunk.zsize = chunk_size;
    // NB: malloc chunk a little big since we need to maintain
    // the invariant that all log entries for an instruction reside in same
    // chunk.  this should be big enough but don't worry, we'll be monitoring it.
    thePandalog->chunk.buf = (unsigned char *) malloc(thePandalog->chunk.size);
    thePandalog->chunk.buf_p = thePandalog->chunk.buf;
    thePandalog->chunk.zbuf = (unsigned char *) malloc(thePandalog->chunk.zsize);
    thePandalog->chunk.start_instr = 0;
    thePandalog->chunk.start_pos = PL_HEADER_SIZE;
    thePandalog->chunk.entries = std::vector<std::unique_ptr<panda::LogEntry>>();
    thePandalog->chunk.num_entries = 0;
    thePandalog->chunk.max_num_entries = 0;
    thePandalog->chunk.ind_entry = 0;
    return;
}

void pandalog_read_dir(){
    PlHeader *plh = pandalog_read_header();
    
    thePandalog->chunk.size = plh->chunk_size;
    thePandalog->chunk.zsize = plh->chunk_size;
    
    thePandalog->chunk.buf = (unsigned char *) realloc(thePandalog->chunk.buf, thePandalog->chunk.size);
    thePandalog->chunk.buf_p = thePandalog->chunk.buf;

    thePandalog->chunk.zbuf = (unsigned char *) realloc(thePandalog->chunk.zbuf, thePandalog->chunk.size);

    thePandalog->file->seekg(plh->dir_pos);
    uint32_t num_chunks;
    thePandalog->file->read((char*)&num_chunks, sizeof(num_chunks));
    
    PandalogDir *dir = &(thePandalog->dir);
    dir->max_chunks = num_chunks;
    //dir->instr = (uint64_t *) malloc(sizeof(uint64_t) * num_chunks);
    //dir->pos = (uint64_t *) malloc(sizeof(uint64_t) * (1+num_chunks));
    //dir->num_entries = (uint64_t *) malloc(sizeof(uint64_t) * num_chunks);
    
    uint32_t i;
    
    for (i = 0; i < num_chunks; i++) {
        uint64_t read_val;
        thePandalog->file->read((char *) &(read_val), sizeof(uint64_t));
        thePandalog->dir.instr.push_back(read_val);

        thePandalog->file->read((char *) &(read_val), sizeof(uint64_t));
        thePandalog->dir.pos.push_back(read_val);
        
        thePandalog->file->read((char *) &(read_val), sizeof(uint64_t));
        thePandalog->dir.num_entries.push_back(read_val);
    }

    // a little hack so unmarshall_chunk will work
    dir->pos[num_chunks] = plh->dir_pos;
}

PlHeader* pandalog_read_header(){
    PlHeader *plh = new PlHeader();
    printf("sizeof plheader %lu", sizeof(PlHeader));
    thePandalog->file->read((char *)plh, sizeof(PlHeader));
    printf("gcount %lu\n", thePandalog->file->gcount());
    assert(thePandalog->file->gcount() == sizeof(PlHeader));
    
    //TODO: Insert failure checks
    return plh;
}


void pandalog_open_read(const char * fname, PlMode mode){
    std::fstream *plog_file = new fstream();
    printf("filename %s\n", fname);

    pandalog_create(0);
    plog_file->open(fname, ios::in|ios::binary);
    if(plog_file->fail()){
        printf("File open failed");
        exit(1);
    }

    thePandalog->filename = fname;
    thePandalog->mode = mode;
    thePandalog->file = plog_file;

    // read directory and header
    pandalog_read_dir();

    if (thePandalog->mode == PL_MODE_READ_FWD){
        pandalog_seek(0);
    } else {
        pandalog_seek(-1);
    }
}

void pandalog_open(const char *path, const char* mode){
    if (0==strcmp(mode, "w")) {
        pandalog_open_write((const char *) path, (uint32_t) PL_CHUNKSIZE);
    }
    if (0==strcmp(mode, "r")) {
        pandalog_open_read_fwd(path);
    }

}

void pandalog_open_read_bwd(const char *fname){
    pandalog_open_read(fname, PL_MODE_READ_BWD);
}

void pandalog_open_read_fwd(const char* fname){
    pandalog_open_read(fname, PL_MODE_READ_FWD);
}

std::unique_ptr<panda::LogEntry> pandalog_read_entry(){
    
    PandalogChunk *plc = &(thePandalog->chunk);
    uint8_t new_chunk = 0;
    uint32_t new_chunk_num;
    std::unique_ptr<panda::LogEntry> returnEntry (new panda::LogEntry());
    
    // start by unmarshalling chunk, if necessary
    if (thePandalog->mode == PL_MODE_READ_FWD) {
        // if we've gone past the end of the current chunk
        if (plc->ind_entry > plc->num_entries-1){

            //if this is the last chunk, just return NULL. We've read everything!
            if (thePandalog->chunk_num == thePandalog->dir.max_chunks-1) return NULL;

            // otherwise, unmarshall next chunk
            new_chunk_num = thePandalog->chunk_num+1;
            thePandalog->chunk_num = new_chunk_num;

            unmarshall_chunk(new_chunk_num);
            plc = &(thePandalog->chunk);
            //reset ind_entry and return first element of new chunk
            plc->ind_entry = 0;
            returnEntry->CopyFrom(*plc->entries[plc->ind_entry]);
            plc->ind_entry++;
        } else {
            //more to read in this chunk
            returnEntry->CopyFrom(*plc->entries[plc->ind_entry]);
            plc->ind_entry++;
        }
        
    }

    if (thePandalog->mode == PL_MODE_READ_BWD) {
        if (plc->ind_entry < 0){
            // if we've gone past beginning of current chunk

            //if this is first chunk, return NULL.
            if (thePandalog->chunk_num == 0) return NULL;
            
            //otherwise, unmarshall next chunk
            new_chunk_num = thePandalog->chunk_num-1;
            thePandalog->chunk_num = new_chunk_num;

            unmarshall_chunk(new_chunk_num);
            plc = &(thePandalog->chunk);

            //reset ind_entry and return last element of new chunk
            plc->ind_entry = thePandalog->dir.num_entries[new_chunk_num]-1;
            returnEntry->CopyFrom(*plc->entries[plc->ind_entry]);
            plc->ind_entry--;
        } else {
            //more to read in this chunk
            returnEntry->CopyFrom(*plc->entries[plc->ind_entry]);
            plc->ind_entry--;
        }

    }

    return returnEntry;
} 

void pandalog_open_write(const char* filepath, uint32_t chunk_size){
    pandalog_create(chunk_size);

    fstream *plog_file = new fstream();

    thePandalog->mode = PL_MODE_WRITE;
    thePandalog->filename = strdup(filepath);
    plog_file->open(filepath, ios::binary|ios::out);
    thePandalog->file = plog_file;
    // skip over header to be ready to write first chunk
    // NB: we will write the header later, when we write the directory.
    
    thePandalog->file->seekg(thePandalog->chunk.start_pos);

    thePandalog->dir.max_chunks = 128;
    thePandalog->dir.instr = std::vector<uint64_t>(thePandalog->dir.max_chunks);
    thePandalog->dir.pos = std::vector<uint64_t>(thePandalog->dir.max_chunks);
    thePandalog->dir.num_entries = std::vector<uint64_t>(thePandalog->dir.max_chunks);
    //TODO: Do i need to reserve memory for vectors?
    thePandalog->chunk_num = 0;
    printf ("max_chunks = %d\n", thePandalog->dir.max_chunks);
    // write bogus initial chunk
    std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
    pandalog_write_entry(std::move(ple));
}


void write_header(PlHeader* plh){
    //go to beginning of file
    thePandalog->file->seekg(0);
    thePandalog->file->write((char *)plh, sizeof(*plh));
}

void pandalog_write_dir(){
    PandalogDir *dir = &(thePandalog->dir);
    uint32_t num_chunks = thePandalog->chunk_num;

    //create header
    PlHeader plh;
    plh.version = PL_CURRENT_VERSION;
    
    plh.dir_pos = thePandalog->file->tellp();
    plh.chunk_size = thePandalog->chunk.size;

    printf("header: version=%d  dir_pos=%lu chunk_size=%d\n",
            plh.version, plh.dir_pos, plh.chunk_size);
    // now go ahead and write dir where we are in logfile
    //fwrite(&(num_chunks), sizeof(num_chunks), 1, thePandalog->file);

    thePandalog->file->write((char*) &num_chunks, sizeof(num_chunks));

    uint32_t i;
    for (i=0; i<num_chunks; i++) {
        thePandalog->file->write((char*) &dir->instr[i], sizeof(dir->instr[i]));
        //fwrite(&(dir->instr[i]), sizeof(dir->instr[i]), 1, thePandalog->file);
        //fwrite(&(dir->pos[i]), sizeof(dir->pos[i]), 1, thePandalog->file);
        thePandalog->file->write((char*) &dir->pos[i], sizeof(dir->pos[i]));
        //fwrite(&(dir->num_entries[i]), sizeof(dir->num_entries[i]), 1, thePandalog->file);
        thePandalog->file->write((char*) &dir->num_entries[i], sizeof(dir->num_entries[i]));
    }

    write_header(&plh);

}

void add_dir_entry(uint32_t chunk){
   //where do we write dir entry? 
   printf("adding dir entry for chunk\n");
   
    if (chunk >= thePandalog->dir.max_chunks) {
        uint32_t new_size = thePandalog->dir.max_chunks * 2;
        thePandalog->dir.instr.resize(new_size);
        thePandalog->dir.pos.resize(new_size);
        thePandalog->dir.num_entries.resize(new_size);
        //HA! Using a vector now, so no more of this realloc bullshit
        //thePandalog->dir.instr = (uint64_t *) realloc(thePandalog->dir.instr, sizeof(uint64_t) * new_size);
        //thePandalog->dir.pos = (uint64_t *) realloc(thePandalog->dir.pos, sizeof(uint64_t) * new_size);
        //thePandalog->dir.num_entries = (uint64_t *)
            //realloc(thePandalog->dir.num_entries, sizeof(uint64_t) * new_size);

        thePandalog->dir.max_chunks = new_size;
    }

    assert (chunk <= thePandalog->dir.max_chunks);
    // this is start instr and start file position for this chunk
    thePandalog->dir.instr[chunk] = thePandalog->chunk.start_instr;
    thePandalog->dir.pos[chunk] = thePandalog->chunk.start_pos;
    // and this is the number of entries in this chunk
    thePandalog->dir.num_entries[chunk] = thePandalog->chunk.ind_entry;
}

int pandalog_close(){

    if (thePandalog->mode == PL_MODE_WRITE){
        write_current_chunk();
        add_dir_entry(thePandalog->chunk_num);
        pandalog_write_dir();
    }
    thePandalog->file->close();
}

//TODO: Do Zlib in a more C++-like fashion
void write_current_chunk(){
    
    unsigned long chunk_sz = thePandalog->chunk.buf_p - thePandalog->chunk.buf;
    unsigned long ccs = thePandalog->chunk.zsize;
    int ret;

    uint32_t i;
    for (i=0; i<10; i++) {
        printf("about to compress\n");
        ret = compress2(thePandalog->chunk.zbuf, &ccs, thePandalog->chunk.buf, chunk_sz, Z_BEST_COMPRESSION);
        
        printf("finished compress\n");
        if (ret == Z_OK) break;
        // bigger output buffer needed to perform compression?
        thePandalog->chunk.zsize *= 2;
        thePandalog->chunk.zbuf = (unsigned char *) realloc(thePandalog->chunk.zbuf, thePandalog->chunk.zsize);
        assert (thePandalog->chunk.zbuf != NULL);
    }

    // ccs is final compressed chunk size
    assert(ret == Z_OK);
    printf("writing chunk %u of pandalog, %lu / %lu = %.2f compression, %u entries\n",
            thePandalog->chunk_num, chunk_sz, ccs, ((float)chunk_sz) / ccs,
            thePandalog->chunk.ind_entry);
    if (thePandalog->chunk.ind_entry == 0) {
        printf("WARNING: Empty chunk written to pandalog. Did you forget?\n");
    }

    thePandalog->file->write((char*)thePandalog->chunk.zbuf, ccs);
    add_dir_entry(thePandalog->chunk_num);
    // reset start instr / pos
    //TODO: Fix here 
    //thePandalog->chunk.start_instr = rr_get_guest_instr_count();
    thePandalog->chunk.start_instr = rr_fake_guest_instr_count;
    thePandalog->chunk.start_pos = thePandalog->file->tellg();
    // rewind chunk buf and inc chunk #
    thePandalog->chunk.buf_p = thePandalog->chunk.buf;
    thePandalog->chunk_num ++;
    thePandalog->chunk.ind_entry = 0;
}

uint64_t instr_last_entry = -1;

void pandalog_write_entry(std::unique_ptr<panda::LogEntry> entry){

    //if (panda_in_main_loop) {
    if (1) {
        //entry->set_pc(panda_current_pc(first_cpu));
        entry->set_pc(rr_fake_pc);
        rr_fake_pc++;
        entry->set_instr(rr_fake_guest_instr_count);
        rr_fake_guest_instr_count++;
    }
    else {
        entry->set_pc(-1);
        entry->set_instr(-1);
    }

    size_t n = entry->ByteSize();

    // invariant: all log entries for an instruction belong in a single chunk
    if(instr_last_entry == -1 
        && (instr_last_entry != entry->instr())
        && (thePandalog->chunk.buf_p + n  >= thePandalog->chunk.buf + thePandalog->chunk.size)) {
        // entry  won't fit in current chunk
        // and new entry is a different instr from last entry written
            write_current_chunk();
    }

    // create another chunk
    //TODO: WTF is this? Can i remove by not managing my own fucking memory in C++?
    if (thePandalog->chunk.buf_p + sizeof(uint32_t) + n
        >= thePandalog->chunk.buf + ((int)(floor(thePandalog->chunk.size)))) {

        uint32_t offset = thePandalog->chunk.buf_p - thePandalog->chunk.buf;
        uint32_t new_size = offset * 2;
        thePandalog->chunk.buf = (unsigned char *) realloc(thePandalog->chunk.buf, new_size);
        thePandalog->chunk.buf_p = thePandalog->chunk.buf + offset;
        assert (thePandalog->chunk.buf != NULL);
    }

    // now write the entry itself to the buffer.  size then entry itself
    *((uint32_t *) thePandalog->chunk.buf_p) = n;
    thePandalog->chunk.buf_p += sizeof(uint32_t);
    // and then the entry itself (packed)
    entry->SerializeToArray(thePandalog->chunk.buf_p, n);
    thePandalog->chunk.buf_p += n;
    // remember instr for last entry
    instr_last_entry = entry->instr();
    thePandalog->chunk.ind_entry ++;
}

void unmarshall_chunk(uint32_t chunk_num){  
    printf ("unmarshalling chunk %d\n", chunk_num);
    PandalogChunk *chunk = &(thePandalog->chunk);
    // read compressed chunk data off disk
    printf("Seeking to %lu\n", thePandalog->dir.pos[chunk_num]);
    thePandalog->file->seekg(thePandalog->dir.pos[chunk_num]);

    unsigned long compressed_size = thePandalog->dir.pos[chunk_num+1] - thePandalog->dir.pos[chunk_num] + 1;
     thePandalog->file->read((char* ) chunk->zbuf, compressed_size);
    assert (thePandalog->file->gcount() == compressed_size);
    unsigned long uncompressed_size = chunk->size;

    // uncompress it
    printf ("chunk size=%lu compressed=%lu\n", uncompressed_size, compressed_size);

    int ret;
    while (true) {
        ret = uncompress(chunk->buf, &uncompressed_size, chunk->zbuf, compressed_size);

        printf ("ret = %d\n", ret);

        if (ret == Z_BUF_ERROR) {
            // need a bigger buffer
            // make sure we won't int overflow
            assert (chunk->size < UINT32_MAX/2);
            chunk->size *= 2;
            printf ("grew chunk buffer to %d\n", chunk->size);
            free(chunk->buf);
            chunk->buf = (unsigned char *)malloc(chunk->size);
            chunk->buf_p = chunk->buf;
            uncompressed_size = chunk->size;
        } else if (ret == Z_OK) {
            break;
        } else {
            assert(false && "Decompression failed");
        }
    }

    // clear previous chunk's entries 
    chunk->entries.clear();

    if (chunk->max_num_entries < thePandalog->dir.num_entries[chunk_num]) {
        chunk->max_num_entries = thePandalog->dir.num_entries[chunk_num];
    }
    chunk->num_entries = thePandalog->dir.num_entries[chunk_num];

    printf("num_entries %u\n", chunk->num_entries);
    unsigned char *p = chunk->buf;
    for (int i = 0; i < chunk->num_entries; i++) {
        assert (p < chunk->buf + chunk->size);
        uint32_t entry_size = *((uint32_t *) p);
        p += sizeof(uint32_t);
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->ParseFromArray(p, entry_size);
        p += entry_size;
        chunk->entries.push_back(std::move(ple));
    }
    chunk->ind_entry = 0;  // a guess
}

uint32_t find_ind(uint64_t instr, uint32_t lo_idx, uint32_t high_idx){
    assert(lo_idx <= high_idx);
    if(lo_idx == high_idx) return lo_idx;

    //First entry of log always has pc = -1 and instr = -1
    // skip it if that's the case
    
    PandalogChunk *chunk = &(thePandalog->chunk);
    if (chunk->entries[lo_idx]->instr() == -1 && chunk->entries[lo_idx]->pc() == -1){
        lo_idx++;
    }

    if (instr < chunk->entries[lo_idx]->instr()) return lo_idx;
    if (instr > chunk->entries[high_idx]->instr()) return high_idx;

    uint32_t mid_idx = (lo_idx + high_idx)/2;
    if (chunk->entries[lo_idx]->instr() <= instr && instr <= chunk->entries[mid_idx]->instr()){
        return find_ind(instr, lo_idx, mid_idx);
    }

    assert(chunk->entries[mid_idx]->instr() <= instr && instr <= chunk->entries[high_idx]->instr());

    return find_ind(instr, mid_idx, high_idx);
}

uint32_t find_chunk(uint64_t instr, uint32_t lo, uint32_t high){
    assert(lo <= high);
    
    //base cases
    if (lo == high) return lo;
    if (instr < thePandalog->dir.instr[lo])   return lo;
    if (instr > thePandalog->dir.instr[high]) return high;

    uint32_t mid_chunk = (lo+high)/2;
    // recursive search in lower half
    if(thePandalog->dir.instr[lo] <= instr && instr <= thePandalog->dir.instr[mid_chunk]){
        return find_chunk(instr, lo, mid_chunk);    
    }

    //else, search in upper half
    assert(thePandalog->dir.instr[mid_chunk] < instr && instr <= thePandalog->dir.instr[high]);
    return find_chunk(instr, mid_chunk, high);

}

void pandalog_seek(uint64_t instr){
    // do a Binary search for this idx 
    uint32_t chunk_num = find_chunk(instr, 0, thePandalog->dir.max_chunks-1);
    thePandalog->chunk_num = chunk_num;
    unmarshall_chunk(chunk_num);

    uint32_t ind = find_ind(instr, 0, thePandalog->dir.num_entries[chunk_num]-1);

    std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry);
    ple->CopyFrom(*thePandalog->chunk.entries[ind]);
    assert(ple->instr() == instr);

    if(thePandalog->mode == PL_MODE_READ_BWD && instr != -1){
        //search forward for last index with this instr number

        for (uint32_t i = ind; i < thePandalog->dir.num_entries[chunk_num]; i++){
            ple->CopyFrom(*thePandalog->chunk.entries[i]);
            if (ple->instr() != instr){
                // we've gone past the last entry with that instr num
                // backtrack by one and return
                ind --;
                break;
            }
        }
    }

    thePandalog->chunk.ind_entry = ind;
}





