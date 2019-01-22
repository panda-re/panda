/*
 * QEMU ISA IPMI BT emulation
 *
 * Copyright (c) 2015 Corey Minyard, MontaVista Software, LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/hw.h"
#include "hw/ipmi/ipmi.h"
#include "hw/isa/isa.h"
#include "hw/i386/pc.h"

/* Control register */
#define IPMI_BT_CLR_WR_BIT         0
#define IPMI_BT_CLR_RD_BIT         1
#define IPMI_BT_H2B_ATN_BIT        2
#define IPMI_BT_B2H_ATN_BIT        3
#define IPMI_BT_SMS_ATN_BIT        4
#define IPMI_BT_HBUSY_BIT          6
#define IPMI_BT_BBUSY_BIT          7

#define IPMI_BT_GET_CLR_WR(d)      (((d) >> IPMI_BT_CLR_WR_BIT) & 0x1)

#define IPMI_BT_GET_CLR_RD(d)      (((d) >> IPMI_BT_CLR_RD_BIT) & 0x1)

#define IPMI_BT_GET_H2B_ATN(d)     (((d) >> IPMI_BT_H2B_ATN_BIT) & 0x1)

#define IPMI_BT_B2H_ATN_MASK       (1 << IPMI_BT_B2H_ATN_BIT)
#define IPMI_BT_GET_B2H_ATN(d)     (((d) >> IPMI_BT_B2H_ATN_BIT) & 0x1)
#define IPMI_BT_SET_B2H_ATN(d, v)  ((d) = (((d) & ~IPMI_BT_B2H_ATN_MASK) | \
                                        (((v) & 1) << IPMI_BT_B2H_ATN_BIT)))

#define IPMI_BT_SMS_ATN_MASK       (1 << IPMI_BT_SMS_ATN_BIT)
#define IPMI_BT_GET_SMS_ATN(d)     (((d) >> IPMI_BT_SMS_ATN_BIT) & 0x1)
#define IPMI_BT_SET_SMS_ATN(d, v)  ((d) = (((d) & ~IPMI_BT_SMS_ATN_MASK) | \
                                        (((v) & 1) << IPMI_BT_SMS_ATN_BIT)))

#define IPMI_BT_HBUSY_MASK         (1 << IPMI_BT_HBUSY_BIT)
#define IPMI_BT_GET_HBUSY(d)       (((d) >> IPMI_BT_HBUSY_BIT) & 0x1)
#define IPMI_BT_SET_HBUSY(d, v)    ((d) = (((d) & ~IPMI_BT_HBUSY_MASK) | \
                                       (((v) & 1) << IPMI_BT_HBUSY_BIT)))

#define IPMI_BT_BBUSY_MASK         (1 << IPMI_BT_BBUSY_BIT)
#define IPMI_BT_SET_BBUSY(d, v)    ((d) = (((d) & ~IPMI_BT_BBUSY_MASK) | \
                                       (((v) & 1) << IPMI_BT_BBUSY_BIT)))


/* Mask register */
#define IPMI_BT_B2H_IRQ_EN_BIT     0
#define IPMI_BT_B2H_IRQ_BIT        1

#define IPMI_BT_B2H_IRQ_EN_MASK      (1 << IPMI_BT_B2H_IRQ_EN_BIT)
#define IPMI_BT_GET_B2H_IRQ_EN(d)    (((d) >> IPMI_BT_B2H_IRQ_EN_BIT) & 0x1)
#define IPMI_BT_SET_B2H_IRQ_EN(d, v) ((d) = (((d) & ~IPMI_BT_B2H_IRQ_EN_MASK) |\
                                        (((v) & 1) << IPMI_BT_B2H_IRQ_EN_BIT)))

#define IPMI_BT_B2H_IRQ_MASK         (1 << IPMI_BT_B2H_IRQ_BIT)
#define IPMI_BT_GET_B2H_IRQ(d)       (((d) >> IPMI_BT_B2H_IRQ_BIT) & 0x1)
#define IPMI_BT_SET_B2H_IRQ(d, v)    ((d) = (((d) & ~IPMI_BT_B2H_IRQ_MASK) | \
                                        (((v) & 1) << IPMI_BT_B2H_IRQ_BIT)))

typedef struct IPMIBT {
    IPMIBmc *bmc;

    bool do_wake;

    qemu_irq irq;

    uint32_t io_base;
    unsigned long io_length;
    MemoryRegion io;

    bool obf_irq_set;
    bool atn_irq_set;
    bool use_irq;
    bool irqs_enabled;

    uint8_t outmsg[MAX_IPMI_MSG_SIZE];
    uint32_t outpos;
    uint32_t outlen;

    uint8_t inmsg[MAX_IPMI_MSG_SIZE];
    uint32_t inlen;

    uint8_t control_reg;
    uint8_t mask_reg;

    /*
     * This is a response number that we send with the command to make
     * sure that the response matches the command.
     */
    uint8_t waiting_rsp;
    uint8_t waiting_seq;
} IPMIBT;

#define IPMI_CMD_GET_BT_INTF_CAP        0x36

static void ipmi_bt_handle_event(IPMIInterface *ii)
{
    IPMIInterfaceClass *iic = IPMI_INTERFACE_GET_CLASS(ii);
    IPMIBT *ib = iic->get_backend_data(ii);

    if (ib->inlen < 4) {
        goto out;
    }
    /* Note that overruns are handled by handle_command */
    if (ib->inmsg[0] != (ib->inlen - 1)) {
        /* Length mismatch, just ignore. */
        IPMI_BT_SET_BBUSY(ib->control_reg, 1);
        ib->inlen = 0;
        goto out;
    }
    if ((ib->inmsg[1] == (IPMI_NETFN_APP << 2)) &&
                        (ib->inmsg[3] == IPMI_CMD_GET_BT_INTF_CAP)) {
        /* We handle this one ourselves. */
        ib->outmsg[0] = 9;
        ib->outmsg[1] = ib->inmsg[1] | 0x04;
        ib->outmsg[2] = ib->inmsg[2];
        ib->outmsg[3] = ib->inmsg[3];
        ib->outmsg[4] = 0;
        ib->outmsg[5] = 1; /* Only support 1 outstanding request. */
        if (sizeof(ib->inmsg) > 0xff) { /* Input buffer size */
            ib->outmsg[6] = 0xff;
        } else {
            ib->outmsg[6] = (unsigned char) sizeof(ib->inmsg);
        }
        if (sizeof(ib->outmsg) > 0xff) { /* Output buffer size */
            ib->outmsg[7] = 0xff;
        } else {
            ib->outmsg[7] = (unsigned char) sizeof(ib->outmsg);
        }
        ib->outmsg[8] = 10; /* Max request to response time */
        ib->outmsg[9] = 0; /* Don't recommend retries */
        ib->outlen = 10;
        IPMI_BT_SET_BBUSY(ib->control_reg, 0);
        IPMI_BT_SET_B2H_ATN(ib->control_reg, 1);
        if (ib->use_irq && ib->irqs_enabled &&
                !IPMI_BT_GET_B2H_IRQ(ib->mask_reg) &&
                IPMI_BT_GET_B2H_IRQ_EN(ib->mask_reg)) {
            IPMI_BT_SET_B2H_IRQ(ib->mask_reg, 1);
            qemu_irq_raise(ib->irq);
        }
        goto out;
    }
    ib->waiting_seq = ib->inmsg[2];
    ib->inmsg[2] = ib->inmsg[1];
    {
        IPMIBmcClass *bk = IPMI_BMC_GET_CLASS(ib->bmc);
        bk->handle_command(ib->bmc, ib->inmsg + 2, ib->inlen - 2,
                           sizeof(ib->inmsg), ib->waiting_rsp);
    }
 out:
    return;
}

static void ipmi_bt_handle_rsp(IPMIInterface *ii, uint8_t msg_id,
                                unsigned char *rsp, unsigned int rsp_len)
{
    IPMIInterfaceClass *iic = IPMI_INTERFACE_GET_CLASS(ii);
    IPMIBT *ib = iic->get_backend_data(ii);

    if (ib->waiting_rsp == msg_id) {
        ib->waiting_rsp++;
        if (rsp_len > (sizeof(ib->outmsg) - 2)) {
            ib->outmsg[0] = 4;
            ib->outmsg[1] = rsp[0];
            ib->outmsg[2] = ib->waiting_seq;
            ib->outmsg[3] = rsp[1];
            ib->outmsg[4] = IPMI_CC_CANNOT_RETURN_REQ_NUM_BYTES;
            ib->outlen = 5;
        } else {
            ib->outmsg[0] = rsp_len + 1;
            ib->outmsg[1] = rsp[0];
            ib->outmsg[2] = ib->waiting_seq;
            memcpy(ib->outmsg + 3, rsp + 1, rsp_len - 1);
            ib->outlen = rsp_len + 2;
        }
        IPMI_BT_SET_BBUSY(ib->control_reg, 0);
        IPMI_BT_SET_B2H_ATN(ib->control_reg, 1);
        if (ib->use_irq && ib->irqs_enabled &&
                !IPMI_BT_GET_B2H_IRQ(ib->mask_reg) &&
                IPMI_BT_GET_B2H_IRQ_EN(ib->mask_reg)) {
            IPMI_BT_SET_B2H_IRQ(ib->mask_reg, 1);
            qemu_irq_raise(ib->irq);
        }
    }
}


static uint64_t ipmi_bt_ioport_read(void *opaque, hwaddr addr, unsigned size)
{
    IPMIInterface *ii = opaque;
    IPMIInterfaceClass *iic = IPMI_INTERFACE_GET_CLASS(ii);
    IPMIBT *ib = iic->get_backend_data(ii);
    uint32_t ret = 0xff;

    switch (addr & 3) {
    case 0:
        ret = ib->control_reg;
        break;
    case 1:
        if (ib->outpos < ib->outlen) {
            ret = ib->outmsg[ib->outpos];
            ib->outpos++;
            if (ib->outpos == ib->outlen) {
                ib->outpos = 0;
                ib->outlen = 0;
            }
        } else {
            ret = 0xff;
        }
        break;
    case 2:
        ret = ib->mask_reg;
        break;
    }
    return ret;
}

static void ipmi_bt_signal(IPMIBT *ib, IPMIInterface *ii)
{
    IPMIInterfaceClass *iic = IPMI_INTERFACE_GET_CLASS(ii);

    ib->do_wake = 1;
    while (ib->do_wake) {
        ib->do_wake = 0;
        iic->handle_if_event(ii);
    }
}

static void ipmi_bt_ioport_write(void *opaque, hwaddr addr, uint64_t val,
                                 unsigned size)
{
    IPMIInterface *ii = opaque;
    IPMIInterfaceClass *iic = IPMI_INTERFACE_GET_CLASS(ii);
    IPMIBT *ib = iic->get_backend_data(ii);

    switch (addr & 3) {
    case 0:
        if (IPMI_BT_GET_CLR_WR(val)) {
            ib->inlen = 0;
        }
        if (IPMI_BT_GET_CLR_RD(val)) {
            ib->outpos = 0;
        }
        if (IPMI_BT_GET_B2H_ATN(val)) {
            IPMI_BT_SET_B2H_ATN(ib->control_reg, 0);
        }
        if (IPMI_BT_GET_SMS_ATN(val)) {
            IPMI_BT_SET_SMS_ATN(ib->control_reg, 0);
        }
        if (IPMI_BT_GET_HBUSY(val)) {
            /* Toggle */
            IPMI_BT_SET_HBUSY(ib->control_reg,
                              !IPMI_BT_GET_HBUSY(ib->control_reg));
        }
        if (IPMI_BT_GET_H2B_ATN(val)) {
            IPMI_BT_SET_BBUSY(ib->control_reg, 1);
            ipmi_bt_signal(ib, ii);
        }
        break;

    case 1:
        if (ib->inlen < sizeof(ib->inmsg)) {
            ib->inmsg[ib->inlen] = val;
        }
        ib->inlen++;
        break;

    case 2:
        if (IPMI_BT_GET_B2H_IRQ_EN(val) !=
                        IPMI_BT_GET_B2H_IRQ_EN(ib->mask_reg)) {
            if (IPMI_BT_GET_B2H_IRQ_EN(val)) {
                if (IPMI_BT_GET_B2H_ATN(ib->control_reg) ||
                        IPMI_BT_GET_SMS_ATN(ib->control_reg)) {
                    IPMI_BT_SET_B2H_IRQ(ib->mask_reg, 1);
                    qemu_irq_raise(ib->irq);
                }
                IPMI_BT_SET_B2H_IRQ_EN(ib->mask_reg, 1);
            } else {
                if (IPMI_BT_GET_B2H_IRQ(ib->mask_reg)) {
                    IPMI_BT_SET_B2H_IRQ(ib->mask_reg, 0);
                    qemu_irq_lower(ib->irq);
                }
                IPMI_BT_SET_B2H_IRQ_EN(ib->mask_reg, 0);
            }
        }
        if (IPMI_BT_GET_B2H_IRQ(val) && IPMI_BT_GET_B2H_IRQ(ib->mask_reg)) {
            IPMI_BT_SET_B2H_IRQ(ib->mask_reg, 0);
            qemu_irq_lower(ib->irq);
        }
        break;
    }
}

static const MemoryRegionOps ipmi_bt_io_ops = {
    .read = ipmi_bt_ioport_read,
    .write = ipmi_bt_ioport_write,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void ipmi_bt_set_atn(IPMIInterface *ii, int val, int irq)
{
    IPMIInterfaceClass *iic = IPMI_INTERFACE_GET_CLASS(ii);
    IPMIBT *ib = iic->get_backend_data(ii);

    if (!!val == IPMI_BT_GET_SMS_ATN(ib->control_reg)) {
        return;
    }

    IPMI_BT_SET_SMS_ATN(ib->control_reg, val);
    if (val) {
        if (irq && ib->use_irq && ib->irqs_enabled &&
                !IPMI_BT_GET_B2H_ATN(ib->control_reg) &&
                IPMI_BT_GET_B2H_IRQ_EN(ib->mask_reg)) {
            IPMI_BT_SET_B2H_IRQ(ib->mask_reg, 1);
            qemu_irq_raise(ib->irq);
        }
    } else {
        if (!IPMI_BT_GET_B2H_ATN(ib->control_reg) &&
                IPMI_BT_GET_B2H_IRQ(ib->mask_reg)) {
            IPMI_BT_SET_B2H_IRQ(ib->mask_reg, 0);
            qemu_irq_lower(ib->irq);
        }
    }
}

static void ipmi_bt_handle_reset(IPMIInterface *ii, bool is_cold)
{
    IPMIInterfaceClass *iic = IPMI_INTERFACE_GET_CLASS(ii);
    IPMIBT *ib = iic->get_backend_data(ii);

    if (is_cold) {
        /* Disable the BT interrupt on reset */
        if (IPMI_BT_GET_B2H_IRQ(ib->mask_reg)) {
            IPMI_BT_SET_B2H_IRQ(ib->mask_reg, 0);
            qemu_irq_lower(ib->irq);
        }
        IPMI_BT_SET_B2H_IRQ_EN(ib->mask_reg, 0);
    }
}

static void ipmi_bt_set_irq_enable(IPMIInterface *ii, int val)
{
    IPMIInterfaceClass *iic = IPMI_INTERFACE_GET_CLASS(ii);
    IPMIBT *ib = iic->get_backend_data(ii);

    ib->irqs_enabled = val;
}

static void ipmi_bt_init(IPMIInterface *ii, Error **errp)
{
    IPMIInterfaceClass *iic = IPMI_INTERFACE_GET_CLASS(ii);
    IPMIBT *ib = iic->get_backend_data(ii);

    ib->io_length = 3;

    memory_region_init_io(&ib->io, NULL, &ipmi_bt_io_ops, ii, "ipmi-bt", 3);
}


#define TYPE_ISA_IPMI_BT "isa-ipmi-bt"
#define ISA_IPMI_BT(obj) OBJECT_CHECK(ISAIPMIBTDevice, (obj), \
                                       TYPE_ISA_IPMI_BT)

typedef struct ISAIPMIBTDevice {
    ISADevice dev;
    int32_t isairq;
    IPMIBT bt;
    uint32_t uuid;
} ISAIPMIBTDevice;

static void ipmi_bt_get_fwinfo(struct IPMIInterface *ii, IPMIFwInfo *info)
{
    ISAIPMIBTDevice *iib = ISA_IPMI_BT(ii);

    info->interface_name = "bt";
    info->interface_type = IPMI_SMBIOS_BT;
    info->ipmi_spec_major_revision = 2;
    info->ipmi_spec_minor_revision = 0;
    info->base_address = iib->bt.io_base;
    info->register_length = iib->bt.io_length;
    info->register_spacing = 1;
    info->memspace = IPMI_MEMSPACE_IO;
    info->irq_type = IPMI_LEVEL_IRQ;
    info->interrupt_number = iib->isairq;
    info->i2c_slave_address = iib->bt.bmc->slave_addr;
    info->uuid = iib->uuid;
}

static void ipmi_bt_class_init(IPMIInterfaceClass *iic)
{
    iic->init = ipmi_bt_init;
    iic->set_atn = ipmi_bt_set_atn;
    iic->handle_rsp = ipmi_bt_handle_rsp;
    iic->handle_if_event = ipmi_bt_handle_event;
    iic->set_irq_enable = ipmi_bt_set_irq_enable;
    iic->reset = ipmi_bt_handle_reset;
    iic->get_fwinfo = ipmi_bt_get_fwinfo;
}

static void isa_ipmi_bt_realize(DeviceState *dev, Error **errp)
{
    ISADevice *isadev = ISA_DEVICE(dev);
    ISAIPMIBTDevice *iib = ISA_IPMI_BT(dev);
    IPMIInterface *ii = IPMI_INTERFACE(dev);
    IPMIInterfaceClass *iic = IPMI_INTERFACE_GET_CLASS(ii);

    if (!iib->bt.bmc) {
        error_setg(errp, "IPMI device requires a bmc attribute to be set");
        return;
    }

    iib->uuid = ipmi_next_uuid();

    iib->bt.bmc->intf = ii;

    iic->init(ii, errp);
    if (*errp)
        return;

    if (iib->isairq > 0) {
        isa_init_irq(isadev, &iib->bt.irq, iib->isairq);
        iib->bt.use_irq = 1;
    }

    qdev_set_legacy_instance_id(dev, iib->bt.io_base, iib->bt.io_length);

    isa_register_ioport(isadev, &iib->bt.io, iib->bt.io_base);
}

static const VMStateDescription vmstate_ISAIPMIBTDevice = {
    .name = TYPE_IPMI_INTERFACE,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields      = (VMStateField[]) {
        VMSTATE_BOOL(bt.obf_irq_set, ISAIPMIBTDevice),
        VMSTATE_BOOL(bt.atn_irq_set, ISAIPMIBTDevice),
        VMSTATE_BOOL(bt.use_irq, ISAIPMIBTDevice),
        VMSTATE_BOOL(bt.irqs_enabled, ISAIPMIBTDevice),
        VMSTATE_UINT32(bt.outpos, ISAIPMIBTDevice),
        VMSTATE_VBUFFER_UINT32(bt.outmsg, ISAIPMIBTDevice, 1, NULL, bt.outlen),
        VMSTATE_VBUFFER_UINT32(bt.inmsg, ISAIPMIBTDevice, 1, NULL, bt.inlen),
        VMSTATE_UINT8(bt.control_reg, ISAIPMIBTDevice),
        VMSTATE_UINT8(bt.mask_reg, ISAIPMIBTDevice),
        VMSTATE_UINT8(bt.waiting_rsp, ISAIPMIBTDevice),
        VMSTATE_UINT8(bt.waiting_seq, ISAIPMIBTDevice),
        VMSTATE_END_OF_LIST()
    }
};

static void isa_ipmi_bt_init(Object *obj)
{
    ISAIPMIBTDevice *iib = ISA_IPMI_BT(obj);

    ipmi_bmc_find_and_link(obj, (Object **) &iib->bt.bmc);

    vmstate_register(NULL, 0, &vmstate_ISAIPMIBTDevice, iib);
}

static void *isa_ipmi_bt_get_backend_data(IPMIInterface *ii)
{
    ISAIPMIBTDevice *iib = ISA_IPMI_BT(ii);

    return &iib->bt;
}

static Property ipmi_isa_properties[] = {
    DEFINE_PROP_UINT32("ioport", ISAIPMIBTDevice, bt.io_base,  0xe4),
    DEFINE_PROP_INT32("irq",   ISAIPMIBTDevice, isairq,  5),
    DEFINE_PROP_END_OF_LIST(),
};

static void isa_ipmi_bt_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    IPMIInterfaceClass *iic = IPMI_INTERFACE_CLASS(oc);

    dc->realize = isa_ipmi_bt_realize;
    dc->props = ipmi_isa_properties;

    iic->get_backend_data = isa_ipmi_bt_get_backend_data;
    ipmi_bt_class_init(iic);
}

static const TypeInfo isa_ipmi_bt_info = {
    .name          = TYPE_ISA_IPMI_BT,
    .parent        = TYPE_ISA_DEVICE,
    .instance_size = sizeof(ISAIPMIBTDevice),
    .instance_init = isa_ipmi_bt_init,
    .class_init    = isa_ipmi_bt_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_IPMI_INTERFACE },
        { }
    }
};

static void ipmi_register_types(void)
{
    type_register_static(&isa_ipmi_bt_info);
}

type_init(ipmi_register_types)
