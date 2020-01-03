#ifndef CHAR_PD_H
#define CHAR_PD_H

#include "io/channel.h"
#include "sysemu/char.h"

typedef struct PandaChardev {
    Chardev parent;
    Chardev *chr;
    char *buf;
} PandaChardev;

#define TYPE_CHARDEV_PANDA "chardev-panda"

#define PANDA_CHARDEV(obj) OBJECT_CHECK(PandaChardev, (obj), TYPE_CHARDEV_PANDA)
// Only defined functions are static so no need to describe them here
#endif /* CHAR_PD_H */
