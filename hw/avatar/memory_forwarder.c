/*
 *  Avatar memory forwarder fake peripheral
 *  Written by Dario Nisi
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"

#define TYPE_AVATAR_FWD "avatar-fwd"
#define AVATAR_FWD(obj) OBJECT_CHECK(AvatarFwdState, (obj), TYPE_AVATAR_FWD)

typedef struct AvatarFwdState {
    SysBusDevice parent_obj;

    MemoryRegion iomem;

    uint64_t address;
    uint32_t size;
    char *mq_name;
    qemu_irq irq;
} AvatarFwdState;

#define PL011_INT_TX 0x20
#define PL011_INT_RX 0x10

#define PL011_FLAG_TXFE 0x80
#define PL011_FLAG_RXFF 0x40
#define PL011_FLAG_TXFF 0x20
#define PL011_FLAG_RXFE 0x10

static uint64_t avatar_fwd_read(void *opaque, hwaddr offset,
                           unsigned size)
{
//    AvatarFwdState *s = (AvatarFwdState *)opaque;
    return 0;
}


static void avatar_fwd_write(void *opaque, hwaddr offset,
                        uint64_t value, unsigned size)
{
//    AvatarFwdState *s = (AvatarFwdState *)opaque;
}

static const MemoryRegionOps avatar_fwd_ops = {
    .read = avatar_fwd_read,
    .write = avatar_fwd_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static Property avatar_fwd_properties[] = {
    DEFINE_PROP_UINT64("address", AvatarFwdState, address, 0xffffff00),
    DEFINE_PROP_UINT32("size", AvatarFwdState, size, 0x100),
    DEFINE_PROP_STRING("msq_queue", AvatarFwdState, mq_name),
    DEFINE_PROP_END_OF_LIST(),
};

static void avatar_fwd_init(Object *obj)
{
//    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
//    AvatarFwdState *s = AVATAR_FWD(obj);

//    memory_region_init_io(&s->iomem, OBJECT(s), &avatar_fwd_ops, s, "avatar-fwd", s->size);
//    sysbus_init_mmio(sbd, &s->iomem);
//    sysbus_init_irq(sbd, &s->irq);

}

static void avatar_fwd_realize(DeviceState *dev, Error **errp)
{
    AvatarFwdState *s = AVATAR_FWD(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(s);
    memory_region_init_io(&s->iomem, OBJECT(s), &avatar_fwd_ops, s, "avatar-fwd", s->size);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);

}

static void avatar_fwd_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->realize = avatar_fwd_realize;
    dc->props = avatar_fwd_properties;
}

static const TypeInfo avatar_fwd_arm_info = {
    .name          = TYPE_AVATAR_FWD,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AvatarFwdState),
    .instance_init = avatar_fwd_init,
    .class_init    = avatar_fwd_class_init,
};

static void avatar_fwd_register_types(void)
{
    type_register_static(&avatar_fwd_arm_info);
}

type_init(avatar_fwd_register_types)
