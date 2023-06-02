#ifndef __RR2_H
#define __RR2_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <archive.h>
#include <archive_entry.h>

#define RRFILE_SUCCESS(X) ((X) == 0)

struct rr_file {
    char* section;
    struct archive* archive;
    struct archive_entry* entry;
};

// Used to hold path and name info when creating a new recording
struct rr_file_info {
    char* path;
    char* name;
};
void rrfile_info_create(struct rr_file_info** rr_info, char* rr_path, char* rr_name);
void rrfile_info_clear(struct rr_file_info** rr_info);

// Used to hold state when creating a new recording
struct rr_file_state;

int rrfile_open_read(const char* fpath, const char* section, struct rr_file** rr);
int rrfile_read_cmdline(const char* fpath, char** cmdline);
int rrfile_read_metadata(const char* fpath, char** metadata);
int rrfile_read_hashes(const char* fpath, char** hashes);
int rrfile_read_contents_as_string(const char* fpath, const char* section,
                                   char** contents, bool strip);
int rrfile_free(struct rr_file* rr);

int64_t rrfile_section_size(struct rr_file* rr);

void rrfile_fseek_cur(struct rr_file* rr, size_t len);
void rrfile_fseek_set(struct rr_file** rr, const char *filename, size_t len);

/** 
 * rrfile_qemu_getbuffer implements QEMUFileGetBufferFunc
 *
 * The pos argument is ignored because the tar file can only stream
 *
 * Returns:
 *   The number of bytes actually read
 */
ssize_t rrfile_qemu_getbuffer(void* opaque, uint8_t* buffer, int64_t pos, size_t size);

/**
 * rrfile_close implements QEMUFileCloseFunc *close
 *
 * Returns:
 *   An error code
 */
int rrfile_qemu_close(void* opaque);

/**
 * An fread like wrapper for an rrfile
 */
size_t rrfile_fread(void* ptr, size_t size, size_t nmemb, struct rr_file* rr);

/**
 * Open an rr2 file for writing. This creates the archive and the magic file,
 * but does not create the snapshot
 */
struct rr_file_state* rrfile_open_write(const char* fpath);

/**
 * Add a file to the recording archive, deleting the original
 */
bool rrfile_add_recording_file(struct rr_file_state* rstate, const char* type,
                               const char* fpath);

void rrfile_write_metadata_file(struct rr_file_state* rstate, const char* contents);
/**
 * copy a file file from one recording archive to another recording archive
 */
int rrfile_copy_recording_file(struct rr_file_state* rstate, const char* type,
                               char * replay_name);

/**
 * Close a newly create rr2 file, calculating file hashes, etc
 */
void rrfile_finalize(struct rr_file_state*);

/**
 * Update the rrfile module to use rr_archive as its working archive.
 * This is used to store the open archive file while the vm is writing
 * and the nondetlog is being written
 */
void rrfile_set_working(struct rr_file_state* rr_archive);

struct rr_file_state* rrfile_get_working(void);

bool has_rr2_file_extention(const char *filename);
bool is_gzip(const char *filename);
char* rr2_name(const char* fpath);
bool is_rr2_file(const char *filename);
char* remove_rr2_ext(const char* base_name);
#endif
