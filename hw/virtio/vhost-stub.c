#include "qemu/osdep.h"
#include "hw/virtio/vhost.h"
#include "hw/virtio/vhost-user.h"

bool vhost_has_free_slot(void)
{
    return true;
}

bool vhost_user_init(VhostUserState *user, CharBackend *chr, Error **errp)
{
    return false;
}

void vhost_user_cleanup(VhostUserState *user)
{
}