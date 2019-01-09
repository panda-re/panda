/*
 * 9p Posix callback
 *
 * Copyright IBM, Corp. 2010
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "9p.h"
#include "9p-local.h"
#include "9p-xattr.h"
#include "9p-util.h"
#include "fsdev/qemu-fsdev.h"   /* local_ops */
#include <arpa/inet.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "qemu/xattr.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include <libgen.h>
#include <linux/fs.h>
#ifdef CONFIG_LINUX_MAGIC_H
#include <linux/magic.h>
#endif
#include <sys/ioctl.h>

#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC  0x58465342
#endif
#ifndef EXT2_SUPER_MAGIC
#define EXT2_SUPER_MAGIC 0xEF53
#endif
#ifndef REISERFS_SUPER_MAGIC
#define REISERFS_SUPER_MAGIC 0x52654973
#endif
#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC 0x9123683E
#endif

typedef struct {
    int mountfd;
} LocalData;

int local_open_nofollow(FsContext *fs_ctx, const char *path, int flags,
                        mode_t mode)
{
    LocalData *data = fs_ctx->private;

    /* All paths are relative to the path data->mountfd points to */
    while (*path == '/') {
        path++;
    }

    return relative_openat_nofollow(data->mountfd, path, flags, mode);
}

int local_opendir_nofollow(FsContext *fs_ctx, const char *path)
{
    return local_open_nofollow(fs_ctx, path, O_DIRECTORY | O_RDONLY, 0);
}

static void renameat_preserve_errno(int odirfd, const char *opath, int ndirfd,
                                    const char *npath)
{
    int serrno = errno;
    renameat(odirfd, opath, ndirfd, npath);
    errno = serrno;
}

static void unlinkat_preserve_errno(int dirfd, const char *path, int flags)
{
    int serrno = errno;
    unlinkat(dirfd, path, flags);
    errno = serrno;
}

#define VIRTFS_META_DIR ".virtfs_metadata"

static FILE *local_fopenat(int dirfd, const char *name, const char *mode)
{
    int fd, o_mode = 0;
    FILE *fp;
    int flags;
    /*
     * only supports two modes
     */
    if (mode[0] == 'r') {
        flags = O_RDONLY;
    } else if (mode[0] == 'w') {
        flags = O_WRONLY | O_TRUNC | O_CREAT;
        o_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    } else {
        return NULL;
    }
    fd = openat_file(dirfd, name, flags, o_mode);
    if (fd == -1) {
        return NULL;
    }
    fp = fdopen(fd, mode);
    if (!fp) {
        close(fd);
    }
    return fp;
}

#define ATTR_MAX 100
static void local_mapped_file_attr(int dirfd, const char *name,
                                   struct stat *stbuf)
{
    FILE *fp;
    char buf[ATTR_MAX];
    int map_dirfd;

    map_dirfd = openat_dir(dirfd, VIRTFS_META_DIR);
    if (map_dirfd == -1) {
        return;
    }

    fp = local_fopenat(map_dirfd, name, "r");
    close_preserve_errno(map_dirfd);
    if (!fp) {
        return;
    }
    memset(buf, 0, ATTR_MAX);
    while (fgets(buf, ATTR_MAX, fp)) {
        if (!strncmp(buf, "virtfs.uid", 10)) {
            stbuf->st_uid = atoi(buf+11);
        } else if (!strncmp(buf, "virtfs.gid", 10)) {
            stbuf->st_gid = atoi(buf+11);
        } else if (!strncmp(buf, "virtfs.mode", 11)) {
            stbuf->st_mode = atoi(buf+12);
        } else if (!strncmp(buf, "virtfs.rdev", 11)) {
            stbuf->st_rdev = atoi(buf+12);
        }
        memset(buf, 0, ATTR_MAX);
    }
    fclose(fp);
}

static int local_lstat(FsContext *fs_ctx, V9fsPath *fs_path, struct stat *stbuf)
{
    int err = -1;
    char *dirpath = g_path_get_dirname(fs_path->data);
    char *name = g_path_get_basename(fs_path->data);
    int dirfd;

    dirfd = local_opendir_nofollow(fs_ctx, dirpath);
    if (dirfd == -1) {
        goto out;
    }

    err = fstatat(dirfd, name, stbuf, AT_SYMLINK_NOFOLLOW);
    if (err) {
        goto err_out;
    }
    if (fs_ctx->export_flags & V9FS_SM_MAPPED) {
        /* Actual credentials are part of extended attrs */
        uid_t tmp_uid;
        gid_t tmp_gid;
        mode_t tmp_mode;
        dev_t tmp_dev;

        if (fgetxattrat_nofollow(dirfd, name, "user.virtfs.uid", &tmp_uid,
                                 sizeof(uid_t)) > 0) {
            stbuf->st_uid = le32_to_cpu(tmp_uid);
        }
        if (fgetxattrat_nofollow(dirfd, name, "user.virtfs.gid", &tmp_gid,
                                 sizeof(gid_t)) > 0) {
            stbuf->st_gid = le32_to_cpu(tmp_gid);
        }
        if (fgetxattrat_nofollow(dirfd, name, "user.virtfs.mode", &tmp_mode,
                                 sizeof(mode_t)) > 0) {
            stbuf->st_mode = le32_to_cpu(tmp_mode);
        }
        if (fgetxattrat_nofollow(dirfd, name, "user.virtfs.rdev", &tmp_dev,
                                 sizeof(dev_t)) > 0) {
            stbuf->st_rdev = le64_to_cpu(tmp_dev);
        }
    } else if (fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        local_mapped_file_attr(dirfd, name, stbuf);
    }

err_out:
    close_preserve_errno(dirfd);
out:
    g_free(name);
    g_free(dirpath);
    return err;
}

static int local_set_mapped_file_attrat(int dirfd, const char *name,
                                        FsCred *credp)
{
    FILE *fp;
    int ret;
    char buf[ATTR_MAX];
    int uid = -1, gid = -1, mode = -1, rdev = -1;
    int map_dirfd;

    ret = mkdirat(dirfd, VIRTFS_META_DIR, 0700);
    if (ret < 0 && errno != EEXIST) {
        return -1;
    }

    map_dirfd = openat_dir(dirfd, VIRTFS_META_DIR);
    if (map_dirfd == -1) {
        return -1;
    }

    fp = local_fopenat(map_dirfd, name, "r");
    if (!fp) {
        if (errno == ENOENT) {
            goto update_map_file;
        } else {
            close_preserve_errno(map_dirfd);
            return -1;
        }
    }
    memset(buf, 0, ATTR_MAX);
    while (fgets(buf, ATTR_MAX, fp)) {
        if (!strncmp(buf, "virtfs.uid", 10)) {
            uid = atoi(buf + 11);
        } else if (!strncmp(buf, "virtfs.gid", 10)) {
            gid = atoi(buf + 11);
        } else if (!strncmp(buf, "virtfs.mode", 11)) {
            mode = atoi(buf + 12);
        } else if (!strncmp(buf, "virtfs.rdev", 11)) {
            rdev = atoi(buf + 12);
        }
        memset(buf, 0, ATTR_MAX);
    }
    fclose(fp);

update_map_file:
    fp = local_fopenat(map_dirfd, name, "w");
    close_preserve_errno(map_dirfd);
    if (!fp) {
        return -1;
    }

    if (credp->fc_uid != -1) {
        uid = credp->fc_uid;
    }
    if (credp->fc_gid != -1) {
        gid = credp->fc_gid;
    }
    if (credp->fc_mode != -1) {
        mode = credp->fc_mode;
    }
    if (credp->fc_rdev != -1) {
        rdev = credp->fc_rdev;
    }

    if (uid != -1) {
        fprintf(fp, "virtfs.uid=%d\n", uid);
    }
    if (gid != -1) {
        fprintf(fp, "virtfs.gid=%d\n", gid);
    }
    if (mode != -1) {
        fprintf(fp, "virtfs.mode=%d\n", mode);
    }
    if (rdev != -1) {
        fprintf(fp, "virtfs.rdev=%d\n", rdev);
    }
    fclose(fp);

    return 0;
}

static int fchmodat_nofollow(int dirfd, const char *name, mode_t mode)
{
    int fd, ret;

    /* FIXME: this should be handled with fchmodat(AT_SYMLINK_NOFOLLOW).
     * Unfortunately, the linux kernel doesn't implement it yet. As an
     * alternative, let's open the file and use fchmod() instead. This
     * may fail depending on the permissions of the file, but it is the
     * best we can do to avoid TOCTTOU. We first try to open read-only
     * in case name points to a directory. If that fails, we try write-only
     * in case name doesn't point to a directory.
     */
    fd = openat_file(dirfd, name, O_RDONLY, 0);
    if (fd == -1) {
        /* In case the file is writable-only and isn't a directory. */
        if (errno == EACCES) {
            fd = openat_file(dirfd, name, O_WRONLY, 0);
        }
        if (fd == -1 && errno == EISDIR) {
            errno = EACCES;
        }
    }
    if (fd == -1) {
        return -1;
    }
    ret = fchmod(fd, mode);
    close_preserve_errno(fd);
    return ret;
}

static int local_set_xattrat(int dirfd, const char *path, FsCred *credp)
{
    int err;

    if (credp->fc_uid != -1) {
        uint32_t tmp_uid = cpu_to_le32(credp->fc_uid);
        err = fsetxattrat_nofollow(dirfd, path, "user.virtfs.uid", &tmp_uid,
                                   sizeof(uid_t), 0);
        if (err) {
            return err;
        }
    }
    if (credp->fc_gid != -1) {
        uint32_t tmp_gid = cpu_to_le32(credp->fc_gid);
        err = fsetxattrat_nofollow(dirfd, path, "user.virtfs.gid", &tmp_gid,
                                   sizeof(gid_t), 0);
        if (err) {
            return err;
        }
    }
    if (credp->fc_mode != -1) {
        uint32_t tmp_mode = cpu_to_le32(credp->fc_mode);
        err = fsetxattrat_nofollow(dirfd, path, "user.virtfs.mode", &tmp_mode,
                                   sizeof(mode_t), 0);
        if (err) {
            return err;
        }
    }
    if (credp->fc_rdev != -1) {
        uint64_t tmp_rdev = cpu_to_le64(credp->fc_rdev);
        err = fsetxattrat_nofollow(dirfd, path, "user.virtfs.rdev", &tmp_rdev,
                                   sizeof(dev_t), 0);
        if (err) {
            return err;
        }
    }
    return 0;
}

static int local_set_cred_passthrough(FsContext *fs_ctx, int dirfd,
                                      const char *name, FsCred *credp)
{
    if (fchownat(dirfd, name, credp->fc_uid, credp->fc_gid,
                 AT_SYMLINK_NOFOLLOW) < 0) {
        /*
         * If we fail to change ownership and if we are
         * using security model none. Ignore the error
         */
        if ((fs_ctx->export_flags & V9FS_SEC_MASK) != V9FS_SM_NONE) {
            return -1;
        }
    }

    return fchmodat_nofollow(dirfd, name, credp->fc_mode & 07777);
}

static ssize_t local_readlink(FsContext *fs_ctx, V9fsPath *fs_path,
                              char *buf, size_t bufsz)
{
    ssize_t tsize = -1;

    if ((fs_ctx->export_flags & V9FS_SM_MAPPED) ||
        (fs_ctx->export_flags & V9FS_SM_MAPPED_FILE)) {
        int fd;

        fd = local_open_nofollow(fs_ctx, fs_path->data, O_RDONLY, 0);
        if (fd == -1) {
            return -1;
        }
        do {
            tsize = read(fd, (void *)buf, bufsz);
        } while (tsize == -1 && errno == EINTR);
        close_preserve_errno(fd);
    } else if ((fs_ctx->export_flags & V9FS_SM_PASSTHROUGH) ||
               (fs_ctx->export_flags & V9FS_SM_NONE)) {
        char *dirpath = g_path_get_dirname(fs_path->data);
        char *name = g_path_get_basename(fs_path->data);
        int dirfd;

        dirfd = local_opendir_nofollow(fs_ctx, dirpath);
        if (dirfd == -1) {
            goto out;
        }

        tsize = readlinkat(dirfd, name, buf, bufsz);
        close_preserve_errno(dirfd);
    out:
        g_free(name);
        g_free(dirpath);
    }
    return tsize;
}

static int local_close(FsContext *ctx, V9fsFidOpenState *fs)
{
    return close(fs->fd);
}

static int local_closedir(FsContext *ctx, V9fsFidOpenState *fs)
{
    return closedir(fs->dir.stream);
}

static int local_open(FsContext *ctx, V9fsPath *fs_path,
                      int flags, V9fsFidOpenState *fs)
{
    int fd;

    fd = local_open_nofollow(ctx, fs_path->data, flags, 0);
    if (fd == -1) {
        return -1;
    }
    fs->fd = fd;
    return fs->fd;
}

static int local_opendir(FsContext *ctx,
                         V9fsPath *fs_path, V9fsFidOpenState *fs)
{
    int dirfd;
    DIR *stream;

    dirfd = local_opendir_nofollow(ctx, fs_path->data);
    if (dirfd == -1) {
        return -1;
    }

    stream = fdopendir(dirfd);
    if (!stream) {
        close(dirfd);
        return -1;
    }
    fs->dir.stream = stream;
    return 0;
}

static void local_rewinddir(FsContext *ctx, V9fsFidOpenState *fs)
{
    rewinddir(fs->dir.stream);
}

static off_t local_telldir(FsContext *ctx, V9fsFidOpenState *fs)
{
    return telldir(fs->dir.stream);
}

static struct dirent *local_readdir(FsContext *ctx, V9fsFidOpenState *fs)
{
    struct dirent *entry;

again:
    entry = readdir(fs->dir.stream);
    if (!entry) {
        return NULL;
    }

    if (ctx->export_flags & V9FS_SM_MAPPED) {
        entry->d_type = DT_UNKNOWN;
    } else if (ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        if (!strcmp(entry->d_name, VIRTFS_META_DIR)) {
            /* skp the meta data directory */
            goto again;
        }
        entry->d_type = DT_UNKNOWN;
    }

    return entry;
}

static void local_seekdir(FsContext *ctx, V9fsFidOpenState *fs, off_t off)
{
    seekdir(fs->dir.stream, off);
}

static ssize_t local_preadv(FsContext *ctx, V9fsFidOpenState *fs,
                            const struct iovec *iov,
                            int iovcnt, off_t offset)
{
#ifdef CONFIG_PREADV
    return preadv(fs->fd, iov, iovcnt, offset);
#else
    int err = lseek(fs->fd, offset, SEEK_SET);
    if (err == -1) {
        return err;
    } else {
        return readv(fs->fd, iov, iovcnt);
    }
#endif
}

static ssize_t local_pwritev(FsContext *ctx, V9fsFidOpenState *fs,
                             const struct iovec *iov,
                             int iovcnt, off_t offset)
{
    ssize_t ret;
#ifdef CONFIG_PREADV
    ret = pwritev(fs->fd, iov, iovcnt, offset);
#else
    int err = lseek(fs->fd, offset, SEEK_SET);
    if (err == -1) {
        return err;
    } else {
        ret = writev(fs->fd, iov, iovcnt);
    }
#endif
#ifdef CONFIG_SYNC_FILE_RANGE
    if (ret > 0 && ctx->export_flags & V9FS_IMMEDIATE_WRITEOUT) {
        /*
         * Initiate a writeback. This is not a data integrity sync.
         * We want to ensure that we don't leave dirty pages in the cache
         * after write when writeout=immediate is sepcified.
         */
        sync_file_range(fs->fd, offset, ret,
                        SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE);
    }
#endif
    return ret;
}

static int local_chmod(FsContext *fs_ctx, V9fsPath *fs_path, FsCred *credp)
{
    char *dirpath = g_path_get_dirname(fs_path->data);
    char *name = g_path_get_basename(fs_path->data);
    int ret = -1;
    int dirfd;

    dirfd = local_opendir_nofollow(fs_ctx, dirpath);
    if (dirfd == -1) {
        goto out;
    }

    if (fs_ctx->export_flags & V9FS_SM_MAPPED) {
        ret = local_set_xattrat(dirfd, name, credp);
    } else if (fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        ret = local_set_mapped_file_attrat(dirfd, name, credp);
    } else if (fs_ctx->export_flags & V9FS_SM_PASSTHROUGH ||
               fs_ctx->export_flags & V9FS_SM_NONE) {
        ret = fchmodat_nofollow(dirfd, name, credp->fc_mode);
    }
    close_preserve_errno(dirfd);

out:
    g_free(dirpath);
    g_free(name);
    return ret;
}

static int local_mknod(FsContext *fs_ctx, V9fsPath *dir_path,
                       const char *name, FsCred *credp)
{
    int err = -1;
    int dirfd;

    dirfd = local_opendir_nofollow(fs_ctx, dir_path->data);
    if (dirfd == -1) {
        return -1;
    }

    if (fs_ctx->export_flags & V9FS_SM_MAPPED ||
        fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        err = mknodat(dirfd, name, SM_LOCAL_MODE_BITS | S_IFREG, 0);
        if (err == -1) {
            goto out;
        }

        if (fs_ctx->export_flags & V9FS_SM_MAPPED) {
            err = local_set_xattrat(dirfd, name, credp);
        } else {
            err = local_set_mapped_file_attrat(dirfd, name, credp);
        }
        if (err == -1) {
            goto err_end;
        }
    } else if (fs_ctx->export_flags & V9FS_SM_PASSTHROUGH ||
               fs_ctx->export_flags & V9FS_SM_NONE) {
        err = mknodat(dirfd, name, credp->fc_mode, credp->fc_rdev);
        if (err == -1) {
            goto out;
        }
        err = local_set_cred_passthrough(fs_ctx, dirfd, name, credp);
        if (err == -1) {
            goto err_end;
        }
    }
    goto out;

err_end:
    unlinkat_preserve_errno(dirfd, name, 0);
out:
    close_preserve_errno(dirfd);
    return err;
}

static int local_mkdir(FsContext *fs_ctx, V9fsPath *dir_path,
                       const char *name, FsCred *credp)
{
    int err = -1;
    int dirfd;

    dirfd = local_opendir_nofollow(fs_ctx, dir_path->data);
    if (dirfd == -1) {
        return -1;
    }

    if (fs_ctx->export_flags & V9FS_SM_MAPPED ||
        fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        err = mkdirat(dirfd, name, SM_LOCAL_DIR_MODE_BITS);
        if (err == -1) {
            goto out;
        }
        credp->fc_mode = credp->fc_mode | S_IFDIR;

        if (fs_ctx->export_flags & V9FS_SM_MAPPED) {
            err = local_set_xattrat(dirfd, name, credp);
        } else {
            err = local_set_mapped_file_attrat(dirfd, name, credp);
        }
        if (err == -1) {
            goto err_end;
        }
    } else if (fs_ctx->export_flags & V9FS_SM_PASSTHROUGH ||
               fs_ctx->export_flags & V9FS_SM_NONE) {
        err = mkdirat(dirfd, name, credp->fc_mode);
        if (err == -1) {
            goto out;
        }
        err = local_set_cred_passthrough(fs_ctx, dirfd, name, credp);
        if (err == -1) {
            goto err_end;
        }
    }
    goto out;

err_end:
    unlinkat_preserve_errno(dirfd, name, AT_REMOVEDIR);
out:
    close_preserve_errno(dirfd);
    return err;
}

static int local_fstat(FsContext *fs_ctx, int fid_type,
                       V9fsFidOpenState *fs, struct stat *stbuf)
{
    int err, fd;

    if (fid_type == P9_FID_DIR) {
        fd = dirfd(fs->dir.stream);
    } else {
        fd = fs->fd;
    }

    err = fstat(fd, stbuf);
    if (err) {
        return err;
    }
    if (fs_ctx->export_flags & V9FS_SM_MAPPED) {
        /* Actual credentials are part of extended attrs */
        uid_t tmp_uid;
        gid_t tmp_gid;
        mode_t tmp_mode;
        dev_t tmp_dev;

        if (fgetxattr(fd, "user.virtfs.uid", &tmp_uid, sizeof(uid_t)) > 0) {
            stbuf->st_uid = le32_to_cpu(tmp_uid);
        }
        if (fgetxattr(fd, "user.virtfs.gid", &tmp_gid, sizeof(gid_t)) > 0) {
            stbuf->st_gid = le32_to_cpu(tmp_gid);
        }
        if (fgetxattr(fd, "user.virtfs.mode", &tmp_mode, sizeof(mode_t)) > 0) {
            stbuf->st_mode = le32_to_cpu(tmp_mode);
        }
        if (fgetxattr(fd, "user.virtfs.rdev", &tmp_dev, sizeof(dev_t)) > 0) {
            stbuf->st_rdev = le64_to_cpu(tmp_dev);
        }
    } else if (fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return err;
}

static int local_open2(FsContext *fs_ctx, V9fsPath *dir_path, const char *name,
                       int flags, FsCred *credp, V9fsFidOpenState *fs)
{
    int fd = -1;
    int err = -1;
    int dirfd;

    /*
     * Mark all the open to not follow symlinks
     */
    flags |= O_NOFOLLOW;

    dirfd = local_opendir_nofollow(fs_ctx, dir_path->data);
    if (dirfd == -1) {
        return -1;
    }

    /* Determine the security model */
    if (fs_ctx->export_flags & V9FS_SM_MAPPED ||
        fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        fd = openat_file(dirfd, name, flags, SM_LOCAL_MODE_BITS);
        if (fd == -1) {
            goto out;
        }
        credp->fc_mode = credp->fc_mode|S_IFREG;
        if (fs_ctx->export_flags & V9FS_SM_MAPPED) {
            /* Set cleint credentials in xattr */
            err = local_set_xattrat(dirfd, name, credp);
        } else {
            err = local_set_mapped_file_attrat(dirfd, name, credp);
        }
        if (err == -1) {
            goto err_end;
        }
    } else if ((fs_ctx->export_flags & V9FS_SM_PASSTHROUGH) ||
               (fs_ctx->export_flags & V9FS_SM_NONE)) {
        fd = openat_file(dirfd, name, flags, credp->fc_mode);
        if (fd == -1) {
            goto out;
        }
        err = local_set_cred_passthrough(fs_ctx, dirfd, name, credp);
        if (err == -1) {
            goto err_end;
        }
    }
    err = fd;
    fs->fd = fd;
    goto out;

err_end:
    unlinkat_preserve_errno(dirfd, name,
                            flags & O_DIRECTORY ? AT_REMOVEDIR : 0);
    close_preserve_errno(fd);
out:
    close_preserve_errno(dirfd);
    return err;
}


static int local_symlink(FsContext *fs_ctx, const char *oldpath,
                         V9fsPath *dir_path, const char *name, FsCred *credp)
{
    int err = -1;
    int dirfd;

    dirfd = local_opendir_nofollow(fs_ctx, dir_path->data);
    if (dirfd == -1) {
        return -1;
    }

    /* Determine the security model */
    if (fs_ctx->export_flags & V9FS_SM_MAPPED ||
        fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        int fd;
        ssize_t oldpath_size, write_size;

        fd = openat_file(dirfd, name, O_CREAT | O_EXCL | O_RDWR,
                         SM_LOCAL_MODE_BITS);
        if (fd == -1) {
            goto out;
        }
        /* Write the oldpath (target) to the file. */
        oldpath_size = strlen(oldpath);
        do {
            write_size = write(fd, (void *)oldpath, oldpath_size);
        } while (write_size == -1 && errno == EINTR);
        close_preserve_errno(fd);

        if (write_size != oldpath_size) {
            goto err_end;
        }
        /* Set cleint credentials in symlink's xattr */
        credp->fc_mode = credp->fc_mode | S_IFLNK;

        if (fs_ctx->export_flags & V9FS_SM_MAPPED) {
            err = local_set_xattrat(dirfd, name, credp);
        } else {
            err = local_set_mapped_file_attrat(dirfd, name, credp);
        }
        if (err == -1) {
            goto err_end;
        }
    } else if (fs_ctx->export_flags & V9FS_SM_PASSTHROUGH ||
               fs_ctx->export_flags & V9FS_SM_NONE) {
        err = symlinkat(oldpath, dirfd, name);
        if (err) {
            goto out;
        }
        err = fchownat(dirfd, name, credp->fc_uid, credp->fc_gid,
                       AT_SYMLINK_NOFOLLOW);
        if (err == -1) {
            /*
             * If we fail to change ownership and if we are
             * using security model none. Ignore the error
             */
            if ((fs_ctx->export_flags & V9FS_SEC_MASK) != V9FS_SM_NONE) {
                goto err_end;
            } else {
                err = 0;
            }
        }
    }
    goto out;

err_end:
    unlinkat_preserve_errno(dirfd, name, 0);
out:
    close_preserve_errno(dirfd);
    return err;
}

static int local_link(FsContext *ctx, V9fsPath *oldpath,
                      V9fsPath *dirpath, const char *name)
{
    char *odirpath = g_path_get_dirname(oldpath->data);
    char *oname = g_path_get_basename(oldpath->data);
    int ret = -1;
    int odirfd, ndirfd;

    odirfd = local_opendir_nofollow(ctx, odirpath);
    if (odirfd == -1) {
        goto out;
    }

    ndirfd = local_opendir_nofollow(ctx, dirpath->data);
    if (ndirfd == -1) {
        close_preserve_errno(odirfd);
        goto out;
    }

    ret = linkat(odirfd, oname, ndirfd, name, 0);
    if (ret < 0) {
        goto out_close;
    }

    /* now link the virtfs_metadata files */
    if (ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        int omap_dirfd, nmap_dirfd;

        ret = mkdirat(ndirfd, VIRTFS_META_DIR, 0700);
        if (ret < 0 && errno != EEXIST) {
            goto err_undo_link;
        }

        omap_dirfd = openat_dir(odirfd, VIRTFS_META_DIR);
        if (omap_dirfd == -1) {
            goto err;
        }

        nmap_dirfd = openat_dir(ndirfd, VIRTFS_META_DIR);
        if (nmap_dirfd == -1) {
            close_preserve_errno(omap_dirfd);
            goto err;
        }

        ret = linkat(omap_dirfd, oname, nmap_dirfd, name, 0);
        close_preserve_errno(nmap_dirfd);
        close_preserve_errno(omap_dirfd);
        if (ret < 0 && errno != ENOENT) {
            goto err_undo_link;
        }

        ret = 0;
    }
    goto out_close;

err:
    ret = -1;
err_undo_link:
    unlinkat_preserve_errno(ndirfd, name, 0);
out_close:
    close_preserve_errno(ndirfd);
    close_preserve_errno(odirfd);
out:
    g_free(oname);
    g_free(odirpath);
    return ret;
}

static int local_truncate(FsContext *ctx, V9fsPath *fs_path, off_t size)
{
    int fd, ret;

    fd = local_open_nofollow(ctx, fs_path->data, O_WRONLY, 0);
    if (fd == -1) {
        return -1;
    }
    ret = ftruncate(fd, size);
    close_preserve_errno(fd);
    return ret;
}

static int local_chown(FsContext *fs_ctx, V9fsPath *fs_path, FsCred *credp)
{
    char *dirpath = g_path_get_dirname(fs_path->data);
    char *name = g_path_get_basename(fs_path->data);
    int ret = -1;
    int dirfd;

    dirfd = local_opendir_nofollow(fs_ctx, dirpath);
    if (dirfd == -1) {
        goto out;
    }

    if ((credp->fc_uid == -1 && credp->fc_gid == -1) ||
        (fs_ctx->export_flags & V9FS_SM_PASSTHROUGH) ||
        (fs_ctx->export_flags & V9FS_SM_NONE)) {
        ret = fchownat(dirfd, name, credp->fc_uid, credp->fc_gid,
                       AT_SYMLINK_NOFOLLOW);
    } else if (fs_ctx->export_flags & V9FS_SM_MAPPED) {
        ret = local_set_xattrat(dirfd, name, credp);
    } else if (fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        ret = local_set_mapped_file_attrat(dirfd, name, credp);
    }

    close_preserve_errno(dirfd);
out:
    g_free(name);
    g_free(dirpath);
    return ret;
}

static int local_utimensat(FsContext *s, V9fsPath *fs_path,
                           const struct timespec *buf)
{
    char *dirpath = g_path_get_dirname(fs_path->data);
    char *name = g_path_get_basename(fs_path->data);
    int dirfd, ret = -1;

    dirfd = local_opendir_nofollow(s, dirpath);
    if (dirfd == -1) {
        goto out;
    }

    ret = utimensat(dirfd, name, buf, AT_SYMLINK_NOFOLLOW);
    close_preserve_errno(dirfd);
out:
    g_free(dirpath);
    g_free(name);
    return ret;
}

static int local_unlinkat_common(FsContext *ctx, int dirfd, const char *name,
                                 int flags)
{
    int ret = -1;

    if (ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        int map_dirfd;

        if (flags == AT_REMOVEDIR) {
            int fd;

            fd = openat_dir(dirfd, name);
            if (fd == -1) {
                goto err_out;
            }
            /*
             * If directory remove .virtfs_metadata contained in the
             * directory
             */
            ret = unlinkat(fd, VIRTFS_META_DIR, AT_REMOVEDIR);
            close_preserve_errno(fd);
            if (ret < 0 && errno != ENOENT) {
                /*
                 * We didn't had the .virtfs_metadata file. May be file created
                 * in non-mapped mode ?. Ignore ENOENT.
                 */
                goto err_out;
            }
        }
        /*
         * Now remove the name from parent directory
         * .virtfs_metadata directory.
         */
        map_dirfd = openat_dir(dirfd, VIRTFS_META_DIR);
        ret = unlinkat(map_dirfd, name, 0);
        close_preserve_errno(map_dirfd);
        if (ret < 0 && errno != ENOENT) {
            /*
             * We didn't had the .virtfs_metadata file. May be file created
             * in non-mapped mode ?. Ignore ENOENT.
             */
            goto err_out;
        }
    }

    ret = unlinkat(dirfd, name, flags);
err_out:
    return ret;
}

static int local_remove(FsContext *ctx, const char *path)
{
    struct stat stbuf;
    char *dirpath = g_path_get_dirname(path);
    char *name = g_path_get_basename(path);
    int flags = 0;
    int dirfd;
    int err = -1;

    dirfd = local_opendir_nofollow(ctx, dirpath);
    if (dirfd == -1) {
        goto out;
    }

    if (fstatat(dirfd, path, &stbuf, AT_SYMLINK_NOFOLLOW) < 0) {
        goto err_out;
    }

    if (S_ISDIR(stbuf.st_mode)) {
        flags |= AT_REMOVEDIR;
    }

    err = local_unlinkat_common(ctx, dirfd, name, flags);
err_out:
    close_preserve_errno(dirfd);
out:
    g_free(name);
    g_free(dirpath);
    return err;
}

static int local_fsync(FsContext *ctx, int fid_type,
                       V9fsFidOpenState *fs, int datasync)
{
    int fd;

    if (fid_type == P9_FID_DIR) {
        fd = dirfd(fs->dir.stream);
    } else {
        fd = fs->fd;
    }

    if (datasync) {
        return qemu_fdatasync(fd);
    } else {
        return fsync(fd);
    }
}

static int local_statfs(FsContext *s, V9fsPath *fs_path, struct statfs *stbuf)
{
    int fd, ret;

    fd = local_open_nofollow(s, fs_path->data, O_RDONLY, 0);
    if (fd == -1) {
        return -1;
    }
    ret = fstatfs(fd, stbuf);
    close_preserve_errno(fd);
    return ret;
}

static ssize_t local_lgetxattr(FsContext *ctx, V9fsPath *fs_path,
                               const char *name, void *value, size_t size)
{
    char *path = fs_path->data;

    return v9fs_get_xattr(ctx, path, name, value, size);
}

static ssize_t local_llistxattr(FsContext *ctx, V9fsPath *fs_path,
                                void *value, size_t size)
{
    char *path = fs_path->data;

    return v9fs_list_xattr(ctx, path, value, size);
}

static int local_lsetxattr(FsContext *ctx, V9fsPath *fs_path, const char *name,
                           void *value, size_t size, int flags)
{
    char *path = fs_path->data;

    return v9fs_set_xattr(ctx, path, name, value, size, flags);
}

static int local_lremovexattr(FsContext *ctx, V9fsPath *fs_path,
                              const char *name)
{
    char *path = fs_path->data;

    return v9fs_remove_xattr(ctx, path, name);
}

static int local_name_to_path(FsContext *ctx, V9fsPath *dir_path,
                              const char *name, V9fsPath *target)
{
    if (dir_path) {
        v9fs_path_sprintf(target, "%s/%s", dir_path->data, name);
    } else {
        v9fs_path_sprintf(target, "%s", name);
    }
    return 0;
}

static int local_renameat(FsContext *ctx, V9fsPath *olddir,
                          const char *old_name, V9fsPath *newdir,
                          const char *new_name)
{
    int ret;
    int odirfd, ndirfd;

    odirfd = local_opendir_nofollow(ctx, olddir->data);
    if (odirfd == -1) {
        return -1;
    }

    ndirfd = local_opendir_nofollow(ctx, newdir->data);
    if (ndirfd == -1) {
        close_preserve_errno(odirfd);
        return -1;
    }

    ret = renameat(odirfd, old_name, ndirfd, new_name);
    if (ret < 0) {
        goto out;
    }

    if (ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        int omap_dirfd, nmap_dirfd;

        ret = mkdirat(ndirfd, VIRTFS_META_DIR, 0700);
        if (ret < 0 && errno != EEXIST) {
            goto err_undo_rename;
        }

        omap_dirfd = openat_dir(odirfd, VIRTFS_META_DIR);
        if (omap_dirfd == -1) {
            goto err;
        }

        nmap_dirfd = openat_dir(ndirfd, VIRTFS_META_DIR);
        if (nmap_dirfd == -1) {
            close_preserve_errno(omap_dirfd);
            goto err;
        }

        /* rename the .virtfs_metadata files */
        ret = renameat(omap_dirfd, old_name, nmap_dirfd, new_name);
        close_preserve_errno(nmap_dirfd);
        close_preserve_errno(omap_dirfd);
        if (ret < 0 && errno != ENOENT) {
            goto err_undo_rename;
        }

        ret = 0;
    }
    goto out;

err:
    ret = -1;
err_undo_rename:
    renameat_preserve_errno(ndirfd, new_name, odirfd, old_name);
out:
    close_preserve_errno(ndirfd);
    close_preserve_errno(odirfd);
    return ret;
}

static void v9fs_path_init_dirname(V9fsPath *path, const char *str)
{
    path->data = g_path_get_dirname(str);
    path->size = strlen(path->data) + 1;
}

static int local_rename(FsContext *ctx, const char *oldpath,
                        const char *newpath)
{
    int err;
    char *oname = g_path_get_basename(oldpath);
    char *nname = g_path_get_basename(newpath);
    V9fsPath olddir, newdir;

    v9fs_path_init_dirname(&olddir, oldpath);
    v9fs_path_init_dirname(&newdir, newpath);

    err = local_renameat(ctx, &olddir, oname, &newdir, nname);

    v9fs_path_free(&newdir);
    v9fs_path_free(&olddir);
    g_free(nname);
    g_free(oname);

    return err;
}

static int local_unlinkat(FsContext *ctx, V9fsPath *dir,
                          const char *name, int flags)
{
    int ret;
    int dirfd;

    dirfd = local_opendir_nofollow(ctx, dir->data);
    if (dirfd == -1) {
        return -1;
    }

    ret = local_unlinkat_common(ctx, dirfd, name, flags);
    close_preserve_errno(dirfd);
    return ret;
}

static int local_ioc_getversion(FsContext *ctx, V9fsPath *path,
                                mode_t st_mode, uint64_t *st_gen)
{
#ifdef FS_IOC_GETVERSION
    int err;
    V9fsFidOpenState fid_open;

    /*
     * Do not try to open special files like device nodes, fifos etc
     * We can get fd for regular files and directories only
     */
    if (!S_ISREG(st_mode) && !S_ISDIR(st_mode)) {
        errno = ENOTTY;
        return -1;
    }
    err = local_open(ctx, path, O_RDONLY, &fid_open);
    if (err < 0) {
        return err;
    }
    err = ioctl(fid_open.fd, FS_IOC_GETVERSION, st_gen);
    local_close(ctx, &fid_open);
    return err;
#else
    errno = ENOTTY;
    return -1;
#endif
}

static int local_init(FsContext *ctx)
{
    struct statfs stbuf;
    LocalData *data = g_malloc(sizeof(*data));

    data->mountfd = open(ctx->fs_root, O_DIRECTORY | O_RDONLY);
    if (data->mountfd == -1) {
        goto err;
    }

#ifdef FS_IOC_GETVERSION
    /*
     * use ioc_getversion only if the ioctl is definied
     */
    if (fstatfs(data->mountfd, &stbuf) < 0) {
        close_preserve_errno(data->mountfd);
        goto err;
    }
    switch (stbuf.f_type) {
    case EXT2_SUPER_MAGIC:
    case BTRFS_SUPER_MAGIC:
    case REISERFS_SUPER_MAGIC:
    case XFS_SUPER_MAGIC:
        ctx->exops.get_st_gen = local_ioc_getversion;
        break;
    }
#endif

    if (ctx->export_flags & V9FS_SM_PASSTHROUGH) {
        ctx->xops = passthrough_xattr_ops;
    } else if (ctx->export_flags & V9FS_SM_MAPPED) {
        ctx->xops = mapped_xattr_ops;
    } else if (ctx->export_flags & V9FS_SM_NONE) {
        ctx->xops = none_xattr_ops;
    } else if (ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        /*
         * xattr operation for mapped-file and passthrough
         * remain same.
         */
        ctx->xops = passthrough_xattr_ops;
    }
    ctx->export_flags |= V9FS_PATHNAME_FSCONTEXT;

    ctx->private = data;
    return 0;

err:
    g_free(data);
    return -1;
}

static void local_cleanup(FsContext *ctx)
{
    LocalData *data = ctx->private;

    close(data->mountfd);
    g_free(data);
}

static int local_parse_opts(QemuOpts *opts, struct FsDriverEntry *fse)
{
    const char *sec_model = qemu_opt_get(opts, "security_model");
    const char *path = qemu_opt_get(opts, "path");
    Error *err = NULL;

    if (!sec_model) {
        error_report("Security model not specified, local fs needs security model");
        error_printf("valid options are:"
                     "\tsecurity_model=[passthrough|mapped-xattr|mapped-file|none]\n");
        return -1;
    }

    if (!strcmp(sec_model, "passthrough")) {
        fse->export_flags |= V9FS_SM_PASSTHROUGH;
    } else if (!strcmp(sec_model, "mapped") ||
               !strcmp(sec_model, "mapped-xattr")) {
        fse->export_flags |= V9FS_SM_MAPPED;
    } else if (!strcmp(sec_model, "none")) {
        fse->export_flags |= V9FS_SM_NONE;
    } else if (!strcmp(sec_model, "mapped-file")) {
        fse->export_flags |= V9FS_SM_MAPPED_FILE;
    } else {
        error_report("Invalid security model %s specified", sec_model);
        error_printf("valid options are:"
                     "\t[passthrough|mapped-xattr|mapped-file|none]\n");
        return -1;
    }

    if (!path) {
        error_report("fsdev: No path specified");
        return -1;
    }

    fsdev_throttle_parse_opts(opts, &fse->fst, &err);
    if (err) {
        error_reportf_err(err, "Throttle configuration is not valid: ");
        return -1;
    }

    fse->path = g_strdup(path);

    return 0;
}

FileOperations local_ops = {
    .parse_opts = local_parse_opts,
    .init  = local_init,
    .cleanup = local_cleanup,
    .lstat = local_lstat,
    .readlink = local_readlink,
    .close = local_close,
    .closedir = local_closedir,
    .open = local_open,
    .opendir = local_opendir,
    .rewinddir = local_rewinddir,
    .telldir = local_telldir,
    .readdir = local_readdir,
    .seekdir = local_seekdir,
    .preadv = local_preadv,
    .pwritev = local_pwritev,
    .chmod = local_chmod,
    .mknod = local_mknod,
    .mkdir = local_mkdir,
    .fstat = local_fstat,
    .open2 = local_open2,
    .symlink = local_symlink,
    .link = local_link,
    .truncate = local_truncate,
    .rename = local_rename,
    .chown = local_chown,
    .utimensat = local_utimensat,
    .remove = local_remove,
    .fsync = local_fsync,
    .statfs = local_statfs,
    .lgetxattr = local_lgetxattr,
    .llistxattr = local_llistxattr,
    .lsetxattr = local_lsetxattr,
    .lremovexattr = local_lremovexattr,
    .name_to_path = local_name_to_path,
    .renameat  = local_renameat,
    .unlinkat = local_unlinkat,
};
