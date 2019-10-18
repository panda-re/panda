
#include <iostream>
#include <math.h>
#include <fstream>
#include <memory>
#include "panda/plog-cc.hpp"
#include "panda/plog-cc-bridge.h"

using namespace std; 

extern int panda_in_main_loop;

void PandaLog::create(uint32_t chunk_size) {
    this->chunk.size = chunk_size;
    this->chunk.zsize = chunk_size;
    // NB: malloc chunk a little big since we need to maintain
    // the invariant that all log entries for an instruction reside in same
    // chunk.  this should be big enough but don't worry, we'll be monitoring it.
    this->chunk.buf = (unsigned char *) malloc(this->chunk.size);
    this->chunk.buf_p = this->chunk.buf;
    this->chunk.zbuf = (unsigned char *) malloc(this->chunk.zsize);
    this->chunk.start_pos = PL_HEADER_SIZE;
    this->chunk.entries = std::vector<std::unique_ptr<panda::LogEntry>>();
    return;
}

void PandaLog::read_dir(){
    PlHeader *plh = read_header();

    printf("Header: version: %u dir_pos: %" PRIu64 " chunk_size: %u\n", plh->version, plh->dir_pos, plh->chunk_size);
    
    this->chunk.size = plh->chunk_size;
    this->chunk.zsize = plh->chunk_size;
    
    this->chunk.buf = (unsigned char *) realloc(this->chunk.buf, this->chunk.size);
    this->chunk.buf_p = this->chunk.buf;

    this->chunk.zbuf = (unsigned char *) realloc(this->chunk.zbuf, this->chunk.size);

    this->file->seekg(plh->dir_pos);
    uint32_t num_chunks;
    this->file->read((char*)&num_chunks, sizeof(num_chunks));
    
    this->dir.num_chunks = num_chunks;
    
    uint32_t i;
    for (i = 0; i < num_chunks; i++) {
        uint64_t read_val;
        this->file->read((char *) &(read_val), sizeof(uint64_t));
        this->dir.instr.push_back(read_val);

        this->file->read((char *) &(read_val), sizeof(uint64_t));
        this->dir.pos.push_back(read_val);
        
        this->file->read((char *) &(read_val), sizeof(uint64_t));
        this->dir.num_entries.push_back(read_val);
    }

    for (int i = 0; i< num_chunks; ++i){
        printf("i: %d dirinstr: %" PRIu64 " dirpos: %" PRIu64 " dir.num_entries: %" PRIu64 "\n", i, dir.instr[i], dir.pos[i], dir.num_entries[i]);
    }

    // a little hack so unmarshall_chunk will work
    this->dir.pos[num_chunks] = plh->dir_pos;
}

PlHeader* PandaLog::read_header(){
    PlHeader *plh = new PlHeader();
    this->file->read((char *)plh, sizeof(PlHeader));
    assert(this->file->gcount() == sizeof(PlHeader));
    
    return plh;
}


void PandaLog::open_read(const char * fname, PlMode mode){
    std::fstream *plog_file = new fstream();

    create(0);
    plog_file->open(fname, ios::in|ios::binary);
    if(plog_file->fail()){
        printf("Pandalog open for read failed\n");
        exit(1);
    }

    this->filename = fname;
    this->mode = mode;
    this->file = plog_file;

    // read directory and header
    read_dir();

    if (this->mode == PL_MODE_READ_FWD){
        seek(0);
    } else {
        seek(-1);
    }
}

void PandaLog::open(const char *path, const char* mode){
    if (0==strcmp(mode, "w")) {
        open_write((const char *) path, (uint32_t) PL_CHUNKSIZE);
    }
    if (0==strcmp(mode, "r")) {
        open_read_fwd(path);
    }
}

void PandaLog::open_write(const char* filepath, uint32_t chunk_size){
    create(chunk_size);

    fstream *plog_file = new fstream();

    this->mode = PL_MODE_WRITE;
    this->filename = strdup(filepath);
    plog_file->open(filepath, ios::binary|ios::out);
    if (plog_file->fail()){
        printf("Pandalog open for write failed\n");
        exit(1);
    }
    this->file = plog_file;
    // skip over header to be ready to write first chunk
    // NB: we will write the header later, when we write the directory.
    
    this->file->seekg(this->chunk.start_pos);

    this->chunk_num = 0;
    // write bogus initial chunk
    std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
    write_entry(std::move(ple));
}

void PandaLog::open_read_bwd(const char *fname){
    open_read(fname, PL_MODE_READ_BWD);
}

void PandaLog::open_read_fwd(const char* fname){
    open_read(fname, PL_MODE_READ_FWD);
}

std::unique_ptr<panda::LogEntry> PandaLog::read_entry(){
    
    PandalogCcChunk *plc = &(this->chunk);
    uint32_t new_chunk_num;
    std::unique_ptr<panda::LogEntry> returnEntry (new panda::LogEntry());
    
    // start by unmarshalling chunk, if necessary
    if (this->mode == PL_MODE_READ_FWD) {
        // if we've gone past the end of the current chunk
        if (plc->ind_entry > plc->num_entries-1){

            //if this is the last chunk, just return NULL. We've read everything!
            if (this->chunk_num == this->dir.num_chunks-1) return NULL;

            // otherwise, unmarshall next chunk
            new_chunk_num = this->chunk_num+1;
            this->chunk_num = new_chunk_num;

            unmarshall_chunk(new_chunk_num);
            plc = &(this->chunk);
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

    if (this->mode == PL_MODE_READ_BWD) {
        if (plc->ind_entry == -1){
            // if we've gone past beginning of current chunk

            //if this is first chunk, return NULL.
            if (this->chunk_num == 0) return NULL;
            
            //otherwise, unmarshall next chunk
            new_chunk_num = this->chunk_num-1;
            this->chunk_num = new_chunk_num;

            unmarshall_chunk(new_chunk_num);
            plc = &(this->chunk);

            //reset ind_entry and return last element of new chunk
            plc->ind_entry = this->dir.num_entries[new_chunk_num]-1;
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

void PandaLog::write_header(PlHeader* plh){
    //go to beginning of file
    this->file->seekg(0);
    this->file->write((char *)plh, sizeof(*plh));
}

//write the directory and header
void PandaLog::write_dir(){
    uint32_t num_chunks = this->chunk_num;

    //create header
    PlHeader plh;
    plh.version = PL_CURRENT_VERSION;
    
    plh.dir_pos = this->file->tellp();
    plh.chunk_size = this->chunk.size;

    printf("header: version=%d  dir_pos=%" PRIu64 " chunk_size=%d\n",
            plh.version, plh.dir_pos, plh.chunk_size);

    // now go ahead and write dir where we are in logfile
    this->file->write((char*) &num_chunks, sizeof(num_chunks));

    uint32_t i;
    for (i=0; i<num_chunks; i++) {
        this->file->write((char*) &this->dir.instr[i], sizeof(this->dir.instr[i]));
        this->file->write((char*) &this->dir.pos[i], sizeof(this->dir.pos[i]));
        this->file->write((char*) &this->dir.num_entries[i], sizeof(this->dir.num_entries[i]));
    }

    write_header(&plh);
}

void PandaLog::add_dir_entry(){
    // this is start instr and start file position for this chunk
    this->dir.instr.push_back(this->chunk.start_instr);
    this->dir.pos.push_back(this->chunk.start_pos);
    // and this is the number of entries in this chunk
    this->dir.num_entries.push_back(this->chunk.ind_entry);
}

int PandaLog::close(){

    if (this->mode == PL_MODE_WRITE){
        write_current_chunk();
        add_dir_entry();
        write_dir();
    }

    this->file->close();
    return 0;
}

// compress current chunk and write it to file,
// also update directory map
void PandaLog::write_current_chunk(){
#ifndef PLOG_READER 
    //uncompressed chunk size
    unsigned long chunk_sz = this->chunk.buf_p - this->chunk.buf;
    unsigned long ccs = this->chunk.zsize;
    int ret;

    // loop allows compress2 to fail and resize output buffer as needed
    uint32_t i;
    for (i=0; i<10; i++) {
        ret = compress2(this->chunk.zbuf, &ccs, this->chunk.buf, chunk_sz, Z_BEST_COMPRESSION);
        
        if (ret == Z_OK) break;
        // bigger output buffer needed to perform compression?
        this->chunk.zsize *= 2;
        this->chunk.zbuf = (unsigned char *) realloc(this->chunk.zbuf, this->chunk.zsize);
        assert (this->chunk.zbuf != NULL);
    }

    // ccs is final compressed chunk size
    assert(ret == Z_OK);
    printf("writing chunk %u of pandalog, %lu / %lu = %.2f compression, %u entries\n",
            this->chunk_num, chunk_sz, ccs, ((float)chunk_sz) / ccs,
            this->chunk.ind_entry);
    if (this->chunk.ind_entry == 0) {
        printf("WARNING: Empty chunk written to pandalog. Did you forget?\n");
    }

    this->file->write((char*)this->chunk.zbuf, ccs);
    //assert(this->)
    add_dir_entry();
    // reset start instr / pos
    this->chunk.start_instr = rr_get_guest_instr_count();
    this->chunk.start_pos = this->file->tellg();
    // rewind chunk buf and inc chunk #
    this->chunk.buf_p = this->chunk.buf;
    this->chunk_num ++;
    this->chunk.ind_entry = 0;
#endif
}

uint64_t last_instr_entry = -1;

void PandaLog::write_entry(std::unique_ptr<panda::LogEntry> entry){
#ifndef PLOG_READER 
    if (panda_in_main_loop) {
        entry->set_pc(panda_current_pc(first_cpu));
        entry->set_instr(rr_get_guest_instr_count());
    }
    else {
        entry->set_pc(-1);
        entry->set_instr(-1);
    }

    size_t n = entry->ByteSize();

    // invariant: all log entries for an instruction belong in a single chunk
    if(last_instr_entry != -1 
        && (last_instr_entry != entry->instr())
        && (this->chunk.buf_p + n  >= this->chunk.buf + this->chunk.size)) {
        // if entry won't fit in current chunk
        // and new entry is a different instr from last entry written
            write_current_chunk();
    }

    // create another chunk
    if (this->chunk.buf_p + sizeof(uint32_t) + n
        >= this->chunk.buf + ((int)(floor(this->chunk.size)))) {

        uint32_t offset = this->chunk.buf_p - this->chunk.buf;
        uint32_t new_size = offset * 2;
        this->chunk.buf = (unsigned char *) realloc(this->chunk.buf, new_size);
        this->chunk.buf_p = this->chunk.buf + offset;
        assert (this->chunk.buf != NULL);
    }

    // now write the entry itself to the buffer.  size then entry itself
    *((uint32_t *) this->chunk.buf_p) = n;
    this->chunk.buf_p += sizeof(uint32_t);
    // and then the entry itself (packed)
    entry->SerializeToArray(this->chunk.buf_p, n);
    this->chunk.buf_p += n;
    // remember instr for last entry
    last_instr_entry = entry->instr();
    this->chunk.ind_entry ++;
#endif
}

void PandaLog::unmarshall_chunk(uint32_t chunk_num){  
    printf ("unmarshalling chunk %d\n", chunk_num);
    PandalogCcChunk *chunk = &(this->chunk);
    // read compressed chunk data off disk
    this->file->seekg(this->dir.pos[chunk_num]);

    unsigned long compressed_size = this->dir.pos[chunk_num+1] - this->dir.pos[chunk_num] + 1;
     this->file->read((char* ) chunk->zbuf, compressed_size);
    assert (this->file->gcount() == compressed_size);
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

    if (chunk->max_num_entries < this->dir.num_entries[chunk_num]) {
        chunk->max_num_entries = this->dir.num_entries[chunk_num];
    }
    chunk->num_entries = this->dir.num_entries[chunk_num];

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

uint32_t PandaLog::find_ind(uint64_t instr, uint32_t lo_idx, uint32_t high_idx){
    assert(lo_idx <= high_idx);
    if(lo_idx == high_idx) return lo_idx;

    //First entry of log always has pc = -1 and instr = -1
    // skip it if that's the case
    PandalogCcChunk *chunk = &(this->chunk);
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

uint32_t PandaLog::find_chunk(uint64_t instr, uint32_t lo, uint32_t high){
    assert(lo <= high);
    
    //base cases
    if (lo == high) return lo;
    if (instr < this->dir.instr[lo])   return lo;
    if (instr > this->dir.instr[high]) return high;

    uint32_t mid_chunk = (lo+high)/2;
    // recursive search in lower half
    if(this->dir.instr[lo] <= instr && instr <= this->dir.instr[mid_chunk]){
        return find_chunk(instr, lo, mid_chunk);    
    }

    //else, search in upper half
    assert(this->dir.instr[mid_chunk] < instr && instr <= this->dir.instr[high]);
    return find_chunk(instr, mid_chunk, high);

}

void PandaLog::seek(uint64_t instr){
    // do a Binary search for this idx 
    uint32_t chunk_num = find_chunk(instr, 0, this->dir.num_chunks-1);
    this->chunk_num = chunk_num;
    unmarshall_chunk(chunk_num);

    uint32_t ind = find_ind(instr, 0, this->dir.num_entries[chunk_num]-1);

    std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry);
    ple->CopyFrom(*this->chunk.entries[ind]);

    if(this->mode == PL_MODE_READ_BWD && instr != -1){
        //search forward for last index with this instr number

        for (uint32_t i = ind; i < this->dir.num_entries[chunk_num]; i++){
            ple->CopyFrom(*this->chunk.entries[i]);
            if (ple->instr() != instr){
                // we've gone past the last entry with that instr num
                // backtrack by one and return
                ind --;
                break;
            }
        }
    }

    this->chunk.ind_entry = ind;
}


//---------------------------------------------------------------------
// These functions are accessible to C plugins/files
// And declared in plog-cc-bridge.h

PandaLog globalLog;

void pandalog_cc_init_write(const char * fname){
    globalLog.open(fname, "w");
}

void pandalog_cc_init_read(const char * fname){
    globalLog.open(fname, "r");
}

void pandalog_cc_init_read_bwd(const char * fname){
    globalLog.open_read_bwd(fname);
}

void pandalog_cc_seek(uint64_t instr){
    globalLog.seek(instr);
}

void pandalog_cc_close(){
    globalLog.close();
}


// Unpack entry from buffer into C++ protobuf object
// and write it to the log
void pandalog_write_packed(size_t entry_size, unsigned char* buf){
    
    std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
    ple->ParseFromArray(buf, entry_size);
    
    globalLog.write_entry(std::move(ple));
}

// Pack an entry into binary protobuf data
// return packed data
unsigned char* pandalog_read_packed(void){
    
    std::unique_ptr<panda::LogEntry> ple = globalLog.read_entry();
    if (!ple){
        return NULL;
    }
    size_t n = ple->ByteSize();
    unsigned char* buf = (unsigned char *) malloc(n + sizeof(size_t));

    *((size_t*) buf) = n;
    
    ple->SerializeToArray((unsigned char*)(buf + sizeof(size_t)), n);

    return buf;
}
