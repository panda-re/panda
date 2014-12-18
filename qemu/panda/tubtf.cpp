#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tubtf.h"

// yes, this is a global.  I assume you only want one trace.
int tubtf_on = 0;
TubtfTrace *tubtf=NULL;


/*
   returns size of a tubtf row, in bytes
   */
uint32_t tubtf_element_size(void) {
    if (tubtf->colw == TUBTF_COLW_32) {
        return 4 * TUBTF_NUM_COL;
    }
    if (tubtf->colw == TUBTF_COLW_64) {
        return 8 * TUBTF_NUM_COL;
    }
    // fail
    assert ((tubtf->colw == TUBTF_COLW_32) || (tubtf->colw == TUBTF_COLW_64));
    // unreachable but compiler is stoopid
    return 0;
}


/* write this 32-bit val at this position in the trace.
   makes sure to put file pointer back where it was before the write. */
static void tubtf_write_u32_at(uint32_t val, uint64_t pos) {
    assert (tubtf != NULL);
    FILE *fp = (FILE*) tubtf->fp;
    uint64_t current_pos = ftell(fp);
    fseek(fp, pos, SEEK_SET);
    fwrite(&(val), sizeof(val), 1, fp);
    // leave fp in same position you found it
    fseek(fp, current_pos, SEEK_SET);
}

// write this 32-bit val at this position in the trace.
// makes sure to put file pointer back where it was before the write.
static void tubtf_write_u64_at(uint64_t val, uint64_t pos) {
    assert (tubtf != NULL);
    FILE *fp = (FILE*) tubtf->fp;
    uint64_t current_pos = ftell(fp);
    fseek(fp, pos, SEEK_SET);
    fwrite(&(val), sizeof(val), 1, fp);
    // leave fp in same position you found it
    fseek(fp, current_pos, SEEK_SET);
}

static void tubtf_write_contents_bits(void) {
    assert (tubtf != NULL);
    tubtf_write_u64_at(tubtf->contents_bits, 8);
}

void tubtf_open(char *filename, TubtfColw colw) {
    assert (tubtf == NULL);
    assert ((colw == TUBTF_COLW_32) || (colw == TUBTF_COLW_64));
    tubtf = (TubtfTrace *) malloc(sizeof(TubtfTrace));
    tubtf->version = 0;
    tubtf->colw = colw;
    tubtf->contents_bits = 0;
    tubtf->num_rows = 0;
    tubtf->filename = strdup(filename);
    tubtf->fp = fopen(filename, "w");
    // write the header
    tubtf_write_u32_at(tubtf->version, 0);
    tubtf_write_u32_at(tubtf->colw, 4);
    tubtf_write_u64_at(tubtf->contents_bits, 8);
    tubtf_write_u32_at(tubtf->num_rows, 16);
    // advance past header to leave fp in right place to start writing trace body
    uint32_t header_size = sizeof (tubtf->version) + sizeof(tubtf->colw) + sizeof(tubtf->contents_bits) + sizeof(tubtf->num_rows);
    fseek((FILE*) tubtf->fp, header_size, SEEK_SET);
}


void tubtf_write_el_32(uint32_t cr3, uint32_t eip, uint32_t type, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4)  {
    assert (tubtf != NULL);
    assert (tubtf->colw == TUBTF_COLW_32);
    fwrite(&(cr3),  sizeof(cr3),  1, (FILE*) tubtf->fp);
    fwrite(&(eip),  sizeof(eip),  1, (FILE*) tubtf->fp);
    fwrite(&(type), sizeof(type), 1, (FILE*) tubtf->fp);
    fwrite(&(arg1), sizeof(arg1), 1, (FILE*) tubtf->fp);
    fwrite(&(arg2), sizeof(arg2), 1, (FILE*) tubtf->fp);
    fwrite(&(arg3), sizeof(arg3), 1, (FILE*) tubtf->fp);
    fwrite(&(arg4), sizeof(arg4), 1, (FILE*) tubtf->fp);
    tubtf->num_rows ++;
}


void tubtf_write_el_64(uint64_t cr3, uint64_t eip, uint64_t type, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
    assert (tubtf != NULL);
    assert (tubtf->colw == TUBTF_COLW_64);
    fwrite(&(cr3),  sizeof(cr3),  1, (FILE*) tubtf->fp);
    fwrite(&(eip),  sizeof(eip),  1, (FILE*) tubtf->fp);
    fwrite(&(type), sizeof(type), 1, (FILE*) tubtf->fp);
    fwrite(&(arg1), sizeof(arg1), 1, (FILE*) tubtf->fp);
    fwrite(&(arg2), sizeof(arg2), 1, (FILE*) tubtf->fp);
    fwrite(&(arg3), sizeof(arg3), 1, (FILE*) tubtf->fp);
    fwrite(&(arg4), sizeof(arg4), 1, (FILE*) tubtf->fp);
    tubtf->num_rows ++;
}


void tubtf_close(void) {
    assert (tubtf != NULL);
    tubtf_write_contents_bits();
    // fill in number of rows in matrix
    fseek((FILE*) tubtf->fp, sizeof (tubtf->version) + sizeof(tubtf->colw) + sizeof(tubtf->contents_bits), SEEK_SET);
    printf ("%d rows in trace\n", tubtf->num_rows);
    fwrite(&(tubtf->num_rows), sizeof(tubtf->num_rows), 1, (FILE*) tubtf->fp);
    fclose((FILE*) tubtf->fp);
}


