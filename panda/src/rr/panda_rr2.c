#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <archive.h>
#include <archive_entry.h>
#include <openssl/sha.h>

#include "config-host.h"
#include "panda/rr/panda_rr2.h"

// Forward decels for helper functions
bool write_file_to_archive(struct rr_file_state* rstate, const char* fname,
                           const uint8_t* contents, size_t len);
void write_metadata_file(struct rr_file_state* rstate);
void write_magic_file(struct rr_file_state* rstate);
void write_hash_to_log(struct rr_file_state* rstate, const char* fname, SHA_CTX* ctx);
bool is_valid_rrv2_file(const char* state);
void add_file_hash_for_content(struct rr_file_state* rstate, const char* fname,
                               const void* content, size_t len);

struct rr_file_state {
    struct archive* archive;
    char* hash_fpath;
    FILE* hash_fp;
};

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
    if (ARCHIVE_OK != archive_write_set_format_ustar(archive)) {
        fprintf(stderr, "failed to set ustar mode: %s\n", archive_error_string(archive));
    }

    // Open a temporary file to write hashes to
    size_t hash_fpath_len = strlen(fpath) + 10;
    rstate->hash_fpath = (char*)malloc(hash_fpath_len);
    strncpy(rstate->hash_fpath, fpath, hash_fpath_len);
    strncat(rstate->hash_fpath, "-hashtmp", hash_fpath_len);
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

    // Initialize a SHA_CTX for openssl for this file
    SHA_CTX* ctx = (SHA_CTX*)malloc(sizeof(SHA_CTX));
    if (!ctx || !SHA1_Init(ctx)) {
        fprintf(stderr, "Failed to find hash for file contents of %s\n", type);
        if (ctx) {
            free(ctx);
        }
        return false;
    }

    // Add the file contents
    int len;
    uint8_t buffer[1024 * 1024];
    len = fread(buffer, 1, sizeof(buffer), fp);
    while (len > 0) {
        SHA1_Update(ctx, buffer, len);
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
    write_hash_to_log(rstate, type, ctx);
    free(ctx);
    return true;
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
    write_metadata_file(rstate);
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
    archive_entry_set_pathname(entry, MAGIC_FILE);
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

void write_hash_to_log(struct rr_file_state* rstate, const char* fname, SHA_CTX* ctx)
{
    // If the log isn't open for writing, exit
    if (!rstate->hash_fp) {
        return;
    }

    size_t hexsize = 41;
    unsigned char* hash_md = (unsigned char*)malloc(SHA_DIGEST_LENGTH);
    char* hex = (char*)calloc(1, hexsize);

    // Finalize the hash and snprintf the hexified string for it
    if (!SHA1_Final(hash_md, ctx)) {
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
    // Initialize a SHA_CTX for openssl
    SHA_CTX* ctx = (SHA_CTX*)malloc(sizeof(SHA_CTX));
    if (!ctx || !SHA1_Init(ctx)) {
        fprintf(stderr, "Failed to find hash for file contents of %s\n", fname);
        goto cleanup;
    }
    // Calculate the SHA1 hash for these file contents
    if (!SHA1_Update(ctx, content, len)) {
        fprintf(stderr, "Failed to find hash for file contents of %s\n", fname);
        goto cleanup;
    }
    // Write it to the log
    write_hash_to_log(rstate, fname, ctx);

cleanup:
    if (ctx) {
        free(ctx);
    }
}

void write_metadata_file(struct rr_file_state* rstate)
{
    const char* contents = "{}\n";
    if (!write_file_to_archive(rstate, METADATA_FILE, (const uint8_t*)contents,
                               strlen(contents))) {
        fprintf(stderr, "Failed to write metadata file to archive!\n");
    }
}

void write_magic_file(struct rr_file_state* rstate)
{
    const char* contents = "Created with " QEMU_VERSION "!\n";
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
