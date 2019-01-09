/* Code to mangle pathnames into those matching a given prefix.
   eg. open("/lib/foo.so") => open("/usr/gnemul/i386-linux/lib/foo.so");

   The assumption is that this area does not change.
*/
#include "qemu/osdep.h"
#include <sys/param.h>
#include <dirent.h>
#include "qemu/cutils.h"
#include "qemu/path.h"

struct pathelem
{
    /* Name of this, eg. lib */
    char *name;
    /* Full path name, eg. /usr/gnemul/x86-linux/lib. */
    char *pathname;
    struct pathelem *parent;
    /* Children */
    unsigned int num_entries;
    struct pathelem *entries[0];
};

static struct pathelem *base;

/* First N chars of S1 match S2, and S2 is N chars long. */
static int strneq(const char *s1, unsigned int n, const char *s2)
{
    unsigned int i;

    for (i = 0; i < n; i++)
        if (s1[i] != s2[i])
            return 0;
    return s2[i] == 0;
}

static struct pathelem *add_entry(struct pathelem *root, const char *name,
                                  unsigned type);

static struct pathelem *new_entry(const char *root,
                                  struct pathelem *parent,
                                  const char *name)
{
    struct pathelem *new = g_malloc(sizeof(*new));
    new->name = g_strdup(name);
    new->pathname = g_strdup_printf("%s/%s", root, name);
    new->num_entries = 0;
    return new;
}

#define streq(a,b) (strcmp((a), (b)) == 0)

/* Not all systems provide this feature */
#if defined(DT_DIR) && defined(DT_UNKNOWN) && defined(DT_LNK)
# define dirent_type(dirent) ((dirent)->d_type)
# define is_dir_maybe(type) \
    ((type) == DT_DIR || (type) == DT_UNKNOWN || (type) == DT_LNK)
#else
# define dirent_type(dirent) (1)
# define is_dir_maybe(type)  (type)
#endif

static struct pathelem *add_dir_maybe(struct pathelem *path)
{
    DIR *dir;

    if ((dir = opendir(path->pathname)) != NULL) {
        struct dirent *dirent;

        while ((dirent = readdir(dir)) != NULL) {
            if (!streq(dirent->d_name,".") && !streq(dirent->d_name,"..")){
                path = add_entry(path, dirent->d_name, dirent_type(dirent));
            }
        }
        closedir(dir);
    }
    return path;
}

static struct pathelem *add_entry(struct pathelem *root, const char *name,
                                  unsigned type)
{
    struct pathelem **e;

    root->num_entries++;

    root = g_realloc(root, sizeof(*root)
                   + sizeof(root->entries[0])*root->num_entries);
    e = &root->entries[root->num_entries-1];

    *e = new_entry(root->pathname, root, name);
    if (is_dir_maybe(type)) {
        *e = add_dir_maybe(*e);
    }

    return root;
}

/* This needs to be done after tree is stabilized (ie. no more reallocs!). */
static void set_parents(struct pathelem *child, struct pathelem *parent)
{
    unsigned int i;

    child->parent = parent;
    for (i = 0; i < child->num_entries; i++)
        set_parents(child->entries[i], child);
}

/* FIXME: Doesn't handle DIR/.. where DIR is not in emulated dir. */
static const char *
follow_path(const struct pathelem *cursor, const char *name)
{
    unsigned int i, namelen;

    name += strspn(name, "/");
    namelen = strcspn(name, "/");

    if (namelen == 0)
        return cursor->pathname;

    if (strneq(name, namelen, ".."))
        return follow_path(cursor->parent, name + namelen);

    if (strneq(name, namelen, "."))
        return follow_path(cursor, name + namelen);

    for (i = 0; i < cursor->num_entries; i++)
        if (strneq(name, namelen, cursor->entries[i]->name))
            return follow_path(cursor->entries[i], name + namelen);

    /* Not found */
    return NULL;
}

void init_paths(const char *prefix)
{
    char pref_buf[PATH_MAX];

    if (prefix[0] == '\0' ||
        !strcmp(prefix, "/"))
        return;

    if (prefix[0] != '/') {
        char *cwd = getcwd(NULL, 0);
        size_t pref_buf_len = sizeof(pref_buf);

        if (!cwd)
            abort();
        pstrcpy(pref_buf, sizeof(pref_buf), cwd);
        pstrcat(pref_buf, pref_buf_len, "/");
        pstrcat(pref_buf, pref_buf_len, prefix);
        free(cwd);
    } else
        pstrcpy(pref_buf, sizeof(pref_buf), prefix + 1);

    base = new_entry("", NULL, pref_buf);
    base = add_dir_maybe(base);
    if (base->num_entries == 0) {
        g_free(base->pathname);
        g_free(base->name);
        g_free(base);
        base = NULL;
    } else {
        set_parents(base, base);
    }
}

/* Look for path in emulation dir, otherwise return name. */
const char *path(const char *name)
{
    /* Only do absolute paths: quick and dirty, but should mostly be OK.
       Could do relative by tracking cwd. */
    if (!base || !name || name[0] != '/')
        return name;

    return follow_path(base, name) ?: name;
}
