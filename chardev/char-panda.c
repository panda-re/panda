#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "sysemu/char.h"
#include "char-panda.h"

static void chardev_open(Chardev *chr, ChardevBackend *backend,
                             bool *be_opened, Error **errp)
{
    *be_opened = false;
}

// Response to command comes in here
static int chardev_monitor_write(Chardev *chr, const uint8_t *buf, int len)
{
  //printf("Panda chardev recving message: %s\n", buf);
  // store buffer in PandaChardev's buf
  PandaChardev *s = PANDA_CHARDEV(chr);
  char *b = (char*)malloc(len+1);
  memcpy(b, buf, len);
  s->buf = b;
  s->buf[len] =0;
  return 0;
}

static void fd_chr_update_read_handler(Chardev *chr,
                                       GMainContext *context)
{
  PandaChardev *s = PANDA_CHARDEV(chr);
  s->buf = NULL; // Zero results buffer. TODO: memory leak?
}

static void char_panda_class_init(ObjectClass *oc, void *data)
{
  ChardevClass *cc = CHARDEV_CLASS(oc);
  cc->internal = true;
  cc->chr_write = chardev_monitor_write;
  cc->open = chardev_open;
  cc->chr_update_read_handler = fd_chr_update_read_handler;
}

static const TypeInfo char_panda_type_info = {
    .name = TYPE_CHARDEV_PANDA,
    .parent = TYPE_CHARDEV,
    .class_init = char_panda_class_init,
};

static void register_types(void)
{
    type_register_static(&char_panda_type_info);
}

type_init(register_types);
