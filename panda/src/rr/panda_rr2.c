#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>

#include "config-host.h"
#include "panda/rr/panda_rr2.h"

// Forward decels for helper functions
bool write_file_to_archive(struct rr_file_state* rstate, const char* fname,
                           const uint8_t* contents, size_t len);
void write_magic_file(struct rr_file_state* rstate);
void write_hash_to_log(struct rr_file_state* rstate, const char* fname, EVP_MD_CTX* mdctx);
bool is_valid_rrv2_file(const char* state);
void add_file_hash_for_content(struct rr_file_state* rstate, const char* fname,
                               const void* content, size_t len);

struct rr_file_state {
    struct archive* archive;
    char* hash_fpath;
    FILE* hash_fp;
};

// Used to hold state between rr_do_begin_record and rr_do_end_record
// Add back in for second release of rr2
struct rr_file_state* g_rr_file_state = NULL;

void rrfile_set_working(struct rr_file_state* rr_archive)
{
    g_rr_file_state = rr_archive;
}

struct rr_file_state* rrfile_get_working(void) { return g_rr_file_state; }

// Valid components of an RRv2 tar file
const char* MAGIC_FILE    = "RRv2";
const char* SNAPSHOT_FILE = "snapshot";
const char* COMMAND_FILE  = "capture.cmd";
const char* NONDET_FILE   = "nondetlog";
const char* HASHES_FILE   = "sha1";
const char* METADATA_FILE = "metadata.json";

bool is_valid_rrv2_file(const char* state)
{
    if (strcmp(state, MAGIC_FILE) == 0) {
        return true;
    } else if (strcmp(state, SNAPSHOT_FILE) == 0) {
        return true;
    } else if (strcmp(state, COMMAND_FILE) == 0) {
        return true;
    } else if (strcmp(state, NONDET_FILE) == 0) {
        return true;
    } else if (strcmp(state, HASHES_FILE) == 0) {
        return true;
    } else if (strcmp(state, METADATA_FILE) == 0) {
        return true;
    } else {
        return false;
    }
}

/////////////////
// RRv2 Reading
/////////////////

ssize_t rrfile_qemu_getbuffer(void* opaque, uint8_t* buffer, int64_t pos, size_t size)
{
    struct rr_file* rr = (struct rr_file*)opaque;
    return archive_read_data(rr->archive, buffer, size);
}

int rrfile_qemu_close(void* opaque)
{
    if (opaque) {
        rrfile_free((struct rr_file*)opaque);
    }
    return 0;
}

int rrfile_read_cmdline(const char* fpath, char** cmdline)
{
    return rrfile_read_contents_as_string(fpath, COMMAND_FILE, cmdline, true);
}

int rrfile_read_metadata(const char* fpath, char** metadata)
{
    return rrfile_read_contents_as_string(fpath, METADATA_FILE, metadata, true);
}

int rrfile_read_hashes(const char* fpath, char** hashes)
{
    return rrfile_read_contents_as_string(fpath, HASHES_FILE, hashes, true);
}

int rrfile_read_contents_as_string(const char* fpath, const char* section,
                                   char** contents, bool strip)
{
    struct rr_file* rr = NULL;
    int status = rrfile_open_read(fpath, section, &rr);
    if (!RRFILE_SUCCESS(status)) {
        *contents = NULL;
        return status;
    }
    int64_t contents_size = archive_entry_size(rr->entry);
    if (contents_size <= 0) {
        rrfile_free(rr);
        *contents = NULL;
        return 5;
    }
    *contents = calloc(1, contents_size + 1);
    ssize_t read_size = archive_read_data(rr->archive, *contents, contents_size);
    if (read_size != contents_size) {
        fprintf(stderr, "Failed to read entire command line\n");
        return 6;
    }
    // Strip trailing newlines
    if (strip) {
        for (int64_t idx = contents_size - 1; idx > 0; --idx) {
            if ((*contents)[idx] == '\n') {
                (*contents)[idx] = '\0';
            } else {
                break;
            }
        }
    }
    rrfile_free(rr);
    return 0;
}

int64_t rrfile_section_size(struct rr_file* rr)
{
    if (!rr->entry) {
        return 0;
    }
    return archive_entry_size(rr->entry);
}

int rrfile_open_read(const char* fpath, const char* section, struct rr_file** rr)
{
    // Allocate a libarchive object for the RR file
    struct archive_entry* entry = NULL;
    struct rr_file* rrfile = calloc(1, sizeof(struct rr_file));
    *rr = rrfile;
    if (!rrfile) {
        return 2;
    }
    rrfile->section = strdup(section);
    struct archive* archive = archive_read_new();
    rrfile->archive = archive;

    // Open the archive (supporting anything libarchive can parse)
    archive_read_support_filter_all(archive);
    archive_read_support_format_all(archive);
    int status = archive_read_open_filename(archive, fpath, 2048);
    if (status != ARCHIVE_OK) {
        archive_read_free(archive);
        rrfile->archive = NULL;
        return 3;
    }

    // Find the requested section
    int found_section = 0;
    entry = archive_entry_new();
    while (archive_read_next_header2(archive, entry) == ARCHIVE_OK) {
        if (strcmp(section, archive_entry_pathname(entry)) == 0) {
            found_section = 1;
            break;
        }
        archive_read_data_skip(archive);
        archive_entry_clear(entry);
    }
    // If we didn't find it, exit
    if (!found_section) {
        archive_read_free(archive);
        archive_entry_free(entry);
        rrfile->archive = NULL;
        return 4;
    }
    // Otherwise, capture it
    rrfile->entry = entry;
    return 0;
}

int rrfile_free(struct rr_file* rr)
{
    if (rr && rr->archive) {
        archive_read_free(rr->archive);
        rr->archive = 0;
    }
    if (rr->section) {
        free(rr->section);
        rr->section = 0;
    }
    if (rr->entry) {
        archive_entry_free(rr->entry);
        rr->entry = 0;
    }
    if (rr) {
        free(rr);
    }
    return 0;
}

size_t rrfile_fread(void* input_ptr, size_t size, size_t nmemb, struct rr_file* rr)
{
    uint8_t* ptr = (uint8_t*)input_ptr;
    size_t n = 0;
    while (n < nmemb) {
        int bytes_read = archive_read_data(rr->archive, ptr, size);
        // Failed to read all the chunks, return the short item count
        if (bytes_read != size) {
            return n;
        }
	ptr += size;
        n += 1;
    }
    return n;
}

/////////////////
// RRv2 Writing
/////////////////

struct rr_file_state* rrfile_open_write(const char* fpath)
{
    struct rr_file_state* rstate =
        (struct rr_file_state*)malloc(sizeof(struct rr_file_state));
    // Allocate a libarchive object for the RR file
    struct archive* archive = archive_write_new();
    rstate->archive = archive;
    if (ARCHIVE_OK != archive_write_add_filter_gzip(archive)) {
        fprintf(stderr, "failed to set gzip mode %s\n", archive_error_string(archive));
    }
    if (ARCHIVE_OK != archive_write_set_format_pax(archive)) {
        fprintf(stderr, "failed to set posix tar mode: %s\n", archive_error_string(archive));
    }

    // Open a temporary file to write hashes to
    size_t needed = snprintf(NULL, 0, "%s-hashtmp", fpath);
    rstate->hash_fpath = malloc(needed+1);
    snprintf(rstate->hash_fpath, needed+1, "%s-hashtmp", fpath);

    rstate->hash_fp = fopen(rstate->hash_fpath, "w");
    if (rstate->hash_fp < 0) {
        fprintf(stderr, "Failed to open temporary hash file at %s\n", rstate->hash_fpath);
        return NULL;
    }

    // Open the archive (supporting anything libarchive can parse)
    int status = archive_write_open_filename(archive, fpath);
    if (status != ARCHIVE_OK) {
        fprintf(stderr, "%s\n", archive_error_string(archive));
        archive_write_free(archive);
        return NULL;
    }
    write_magic_file(rstate);
    return rstate;
}

bool rrfile_add_recording_file(struct rr_file_state* rstate, const char* type,
                               const char* fpath)
{
    if (!is_valid_rrv2_file(type)) {
        fprintf(stderr, "Invalid rrv2 file type: %s\n", type);
        return false;
    }
    struct archive* a = rstate->archive;
    struct stat st;
    stat(fpath, &st);
    struct archive_entry* entry = NULL;
    entry = archive_entry_new();
    archive_entry_set_pathname(entry, type);
    archive_entry_set_filetype(entry, AE_IFREG);
    FILE* fp = fopen(fpath, "rb");
    fseek(fp, 0, SEEK_END);
    archive_entry_set_size(entry, ftell(fp));
    fseek(fp, 0, SEEK_SET);
    archive_entry_copy_stat(entry, &st);
    if (ARCHIVE_OK != archive_write_header(a, entry)) {
        fprintf(stderr, "Failed to write archive header!\n");
        fprintf(stderr, "Error: %s\n", archive_error_string(a));
        archive_entry_free(entry);
    }

    // Initialize a EVP_MD_CTX for openssl for this file
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_sha1();
    if (!mdctx || !md || !EVP_DigestInit_ex(mdctx, md, NULL)) {
        fprintf(stderr, "Failed to find hash for file contents of %s\n", type);
        if (mdctx) {
            EVP_MD_CTX_destroy(mdctx);
        }
        return false;
    }

    // Add the file contents
    int len;
    uint8_t buffer[1024 * 1024];
    len = fread(buffer, 1, sizeof(buffer), fp);
    while (len > 0) {
        EVP_DigestUpdate(mdctx, buffer, len);
        int status = archive_write_data(a, buffer, len);
        if (status <= 0) {
            fprintf(stderr, "Failed to archive_write_data\n");
        }
        len = fread(buffer, 1, sizeof(buffer), fp);
    }
    fclose(fp);
    if (ARCHIVE_OK != archive_write_finish_entry(a)) {
        fprintf(stderr, "Failed to finish entry: %s\n", archive_error_string(a));
    }
    unlink(fpath);
    // Write the hash for this file out to the log
    write_hash_to_log(rstate, type, mdctx);
    EVP_MD_CTX_destroy(mdctx);
    return true;
}

int rrfile_copy_recording_file(struct rr_file_state* rstate, const char* type,
			       char * replay_name)
{
    if (!is_valid_rrv2_file(type)) {
        fprintf(stderr, "Invalid rrv2 file type: %s\n", type);
        return false;
    }
    struct rr_file* rr = NULL;
    int status = rrfile_open_read(replay_name, type, &(rr));
    if (!RRFILE_SUCCESS(status)) {
        return status;
    }
    int64_t contents_size = archive_entry_size(rr->entry);
    if (contents_size <= 0) {
        rrfile_free(rr);
        return 7;
    }
    if (ARCHIVE_OK != archive_write_header(rstate->archive, rr->entry)) {
        fprintf(stderr, "Failed to write archive header!\n");
        fprintf(stderr, "Error: %s\n", archive_error_string(rstate->archive));
        rrfile_free(rr);
        return 8;
    }
    void *buff;
    buff = calloc(1, contents_size + 1);
    ssize_t read_size = archive_read_data(rr->archive, buff, contents_size);
    if (read_size != contents_size) {
        fprintf(stderr, "Failed to read entire command line\n");
        rrfile_free(rr);
        free(buff);
        return 9;
    }
    status = archive_write_data(rstate->archive, buff, contents_size);
    rrfile_free(rr);
    free(buff);
    if (status <= 0) {
        fprintf(stderr, "Failed to archive_write_data\n");
        return 10;
    }
    return 0;
}

void rrfile_finalize(struct rr_file_state* rstate)
{
    if (rstate->hash_fp) {
        fclose(rstate->hash_fp);
        rstate->hash_fp = NULL;
        if (!rrfile_add_recording_file(rstate, HASHES_FILE, rstate->hash_fpath)) {
            fprintf(stderr, "Failed to write hash file to archive!\n");
        }
        free(rstate->hash_fpath);
        rstate->hash_fpath = 0;
    }
    // Don't store the hash of the metadata file
    archive_write_free(rstate->archive);
    rstate->archive = 0;
}

bool write_file_to_archive(struct rr_file_state* rstate, const char* fname,
                           const uint8_t* contents, size_t len)
{
    // Create the header for this
    struct archive* a = rstate->archive;
    struct archive_entry* entry = NULL;
    entry = archive_entry_new();
    archive_entry_set_pathname(entry, fname);
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_entry_set_size(entry, len);
    if (ARCHIVE_OK != archive_write_header(a, entry)) {
        fprintf(stderr, "Failed to write archive header!\n");
        fprintf(stderr, "Error: %s\n", archive_error_string(a));
        archive_entry_free(entry);
        return false;
    }

    // Free the archive entry
    archive_entry_free(entry);
    entry = NULL;

    // Write the file to the archive
    size_t sent = 0;
    while (len) {
        int bytes = archive_write_data(a, contents + sent, len);
        if (bytes <= 0) {
            fprintf(stderr, "Failed to call to archive_write_data\n");
            return false;
        }
        sent += bytes;
        len -= bytes;
    }
    if (ARCHIVE_OK != archive_write_finish_entry(a)) {
        fprintf(stderr, "Failed to finish entry: %s\n", archive_error_string(a));
    }

    return true;
}

void write_hash_to_log(struct rr_file_state* rstate, const char* fname, EVP_MD_CTX* mdctx)
{
    // If the log isn't open for writing, exit
    if (!rstate->hash_fp) {
        return;
    }

    size_t hexsize = 41;
    unsigned char* hash_md = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
    char* hex = (char*)calloc(1, hexsize);

    // Finalize the hash and snprintf the hexified string for it
    if (!EVP_DigestFinal_ex(mdctx, hash_md, 0)) {
        fprintf(stderr, "Failed to find hash for file contents of %s\n", fname);
        goto cleanup;
    }
    for (int idx = 0; idx < 20; ++idx) {
        snprintf(hex + 2 * idx, hexsize - 2 * idx, "%02x", hash_md[idx]);
    }

    // Write the hash out to the log in the format: fname hash\n
    fprintf(rstate->hash_fp, "%s: %s\n", fname, hex);

cleanup:
    if (hash_md) {
        free(hash_md);
    }
    if (hex) {
        free(hex);
    }
}

void add_file_hash_for_content(struct rr_file_state* rstate, const char* fname,
                               const void* content, size_t len)
{
    // Initialize a EVP_MD_CTX for openssl
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_sha1();
    if (!mdctx || !md || !EVP_DigestInit_ex(mdctx, md, NULL)) {
        fprintf(stderr, "Failed to find hash for file contents of %s\n", fname);
        goto cleanup;
    }
    // Calculate the SHA1 hash for these file contents
    if (!EVP_DigestUpdate(mdctx, content, len)) {
        fprintf(stderr, "Failed to find hash for file contents of %s\n", fname);
        goto cleanup;
    }
    // Write it to the log
    write_hash_to_log(rstate, fname, mdctx);

cleanup:
    if (mdctx) {
        EVP_MD_CTX_destroy(mdctx);
    }
}

void rrfile_write_metadata_file(struct rr_file_state* rstate, const char* contents)
{
    if (!write_file_to_archive(rstate, METADATA_FILE, (const uint8_t*)contents,
                               strlen(contents))) {
        fprintf(stderr, "Failed to write metadata file to archive!\n");
    }
}

void write_magic_file(struct rr_file_state* rstate)
{
    const char* contents = "Created with QEMU version " QEMU_VERSION "!\n";
    const char* rr_v2_fname = MAGIC_FILE;
    if (!write_file_to_archive(rstate, rr_v2_fname, (const uint8_t*)contents,
                               strlen(contents))) {
        fprintf(stderr, "Failed to write magic file to archive!\n");
    }
    add_file_hash_for_content(rstate, rr_v2_fname, contents, strlen(contents));
}

void rrfile_fseek_cur(struct rr_file* rr, size_t len) {
    uint8_t* buffer = (uint8_t*)malloc(len);
    rrfile_qemu_getbuffer(rr, buffer, 0, len);
    free(buffer);
}

void rrfile_fseek_set(struct rr_file** rr, const char *filename, size_t len) {
    struct rr_file* copy = *rr;
    uint8_t* buffer = (uint8_t*)malloc(len);
    rrfile_open_read(filename, "nondetlog", rr);
    rrfile_qemu_getbuffer(*rr, buffer, 0, len);
    rrfile_free(copy);
    free(buffer);
}

bool has_rr2_file_extention(const char *filename){
    char* ext;
    if ((ext = strrchr(filename,'.')) != NULL && strcmp(ext,".rr2") == 0){
          return true;
        }
    return false;
}

bool is_gzip(const char *filename){
    FILE *fp;
    fp = fopen(filename,"r");
    unsigned char buffer[2];
    size_t nmemb = 2;
    size_t result = fread(buffer,1,nmemb,fp);
    if (result != nmemb){return false;}
    if (buffer[0] == 0x1f && buffer[1] == 0x8b){return true;}
    return false;
}

char* rr2_name(const char* fpath)
{
    char* rr2_name;
    if (has_rr2_file_extention(fpath)){
        rr2_name = strdup(fpath);
    } else {
        size_t needed = snprintf(NULL, 0, "%s.rr2", fpath);
        rr2_name = malloc(needed+1);
        if (!rr2_name) {
            return NULL;
        }
        snprintf(rr2_name, needed+1, "%s.rr2", fpath);
    }
    return rr2_name;
}

bool is_rr2_file(const char *filename){
    bool rr2_file;
    struct stat buffer;
    if (has_rr2_file_extention(filename) &&
        stat(filename,&buffer) == 0 &&
        is_gzip(filename))
    {
        rr2_file = true;
    } else {
        rr2_file = false;
    }
    return rr2_file;
}

char* remove_rr2_ext(const char* base_name){
    char* rr_name;
    if (has_rr2_file_extention(base_name)){
        size_t size = strlen(base_name);
        rr_name = malloc(size-4);
        memcpy(rr_name, base_name, size-4);
        rr_name[size-4] = '\0';
     } else {
        rr_name = strdup(base_name);
     }
     return rr_name;
}

