// Code for handling standard USB hubs.
//
// Copyright (C) 2010  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "util.h" // dprintf
#include "config.h" // CONFIG_USB_HUB
#include "usb-hub.h" // struct usb_hub_descriptor
#include "usb.h" // struct usb_s

static int
get_hub_desc(struct usb_pipe *pipe, struct usb_hub_descriptor *desc)
{
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_DEVICE;
    req.bRequest = USB_REQ_GET_DESCRIPTOR;
    req.wValue = USB_DT_HUB<<8;
    req.wIndex = 0;
    req.wLength = sizeof(*desc);
    return send_default_control(pipe, &req, desc);
}

static int
set_port_feature(struct usbhub_s *hub, int port, int feature)
{
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_OTHER;
    req.bRequest = USB_REQ_SET_FEATURE;
    req.wValue = feature;
    req.wIndex = port + 1;
    req.wLength = 0;
    mutex_lock(&hub->lock);
    int ret = send_default_control(hub->pipe, &req, NULL);
    mutex_unlock(&hub->lock);
    return ret;
}

static int
clear_port_feature(struct usbhub_s *hub, int port, int feature)
{
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_OTHER;
    req.bRequest = USB_REQ_CLEAR_FEATURE;
    req.wValue = feature;
    req.wIndex = port + 1;
    req.wLength = 0;
    mutex_lock(&hub->lock);
    int ret = send_default_control(hub->pipe, &req, NULL);
    mutex_unlock(&hub->lock);
    return ret;
}

static int
get_port_status(struct usbhub_s *hub, int port, struct usb_port_status *sts)
{
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_OTHER;
    req.bRequest = USB_REQ_GET_STATUS;
    req.wValue = 0;
    req.wIndex = port + 1;
    req.wLength = sizeof(*sts);
    mutex_lock(&hub->lock);
    int ret = send_default_control(hub->pipe, &req, sts);
    mutex_unlock(&hub->lock);
    return ret;
}

// Check if device attached to port
static int
usb_hub_detect(struct usbhub_s *hub, u32 port)
{
    // Turn on power to port.
    int ret = set_port_feature(hub, port, USB_PORT_FEAT_POWER);
    if (ret)
        goto fail;

    // Wait for port power to stabilize.
    msleep(hub->powerwait);

    // Check periodically for a device connect.
    struct usb_port_status sts;
    u64 end = calc_future_tsc(USB_TIME_SIGATT);
    for (;;) {
        ret = get_port_status(hub, port, &sts);
        if (ret)
            goto fail;
        if (sts.wPortStatus & USB_PORT_STAT_CONNECTION)
            // Device connected.
            break;
        if (check_tsc(end))
            // No device found.
            return -1;
        msleep(5);
    }

    // XXX - wait USB_TIME_ATTDB time?

    return 0;

fail:
    dprintf(1, "Failure on hub port %d detect\n", port);
    return -1;
}

// Disable port
static void
usb_hub_disconnect(struct usbhub_s *hub, u32 port)
{
    int ret = clear_port_feature(hub, port, USB_PORT_FEAT_ENABLE);
    if (ret)
        dprintf(1, "Failure on hub port %d disconnect\n", port);
}

// Reset device on port
static int
usb_hub_reset(struct usbhub_s *hub, u32 port)
{
    int ret = set_port_feature(hub, port, USB_PORT_FEAT_RESET);
    if (ret)
        goto fail;

    // Wait for reset to complete.
    struct usb_port_status sts;
    u64 end = calc_future_tsc(USB_TIME_DRST * 2);
    for (;;) {
        ret = get_port_status(hub, port, &sts);
        if (ret)
            goto fail;
        if (!(sts.wPortStatus & USB_PORT_STAT_RESET))
            break;
        if (check_tsc(end)) {
            warn_timeout();
            goto fail;
        }
        msleep(5);
    }

    // Reset complete.
    if (!(sts.wPortStatus & USB_PORT_STAT_CONNECTION))
        // Device no longer present
        return -1;

    return ((sts.wPortStatus & USB_PORT_STAT_SPEED_MASK)
            >> USB_PORT_STAT_SPEED_SHIFT);

fail:
    dprintf(1, "Failure on hub port %d reset\n", port);
    usb_hub_disconnect(hub, port);
    return -1;
}

static struct usbhub_op_s HubOp = {
    .detect = usb_hub_detect,
    .reset = usb_hub_reset,
    .disconnect = usb_hub_disconnect,
};

// Configure a usb hub and then find devices connected to it.
int
usb_hub_init(struct usb_pipe *pipe)
{
    ASSERT32FLAT();
    if (!CONFIG_USB_HUB)
        return -1;

    struct usb_hub_descriptor desc;
    int ret = get_hub_desc(pipe, &desc);
    if (ret)
        return ret;

    struct usbhub_s hub;
    memset(&hub, 0, sizeof(hub));
    hub.pipe = pipe;
    hub.cntl = pipe->cntl;
    hub.powerwait = desc.bPwrOn2PwrGood * 2;
    hub.portcount = desc.bNbrPorts;
    hub.op = &HubOp;
    usb_enumerate(&hub);

    dprintf(1, "Initialized USB HUB (%d ports used)\n", hub.devcount);
    if (hub.devcount)
        return 0;
    return -1;
}
