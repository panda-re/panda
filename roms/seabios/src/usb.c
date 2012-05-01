// Main code for handling USB controllers and devices.
//
// Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "util.h" // dprintf
#include "pci.h" // foreachpci
#include "config.h" // CONFIG_*
#include "pci_regs.h" // PCI_CLASS_REVISION
#include "pci_ids.h" // PCI_CLASS_SERIAL_USB_UHCI
#include "usb-uhci.h" // uhci_init
#include "usb-ohci.h" // ohci_init
#include "usb-ehci.h" // ehci_init
#include "usb-hid.h" // usb_keyboard_setup
#include "usb-hub.h" // usb_hub_init
#include "usb-msc.h" // usb_msc_init
#include "usb.h" // struct usb_s
#include "biosvar.h" // GET_GLOBAL


/****************************************************************
 * Controller function wrappers
 ****************************************************************/

// Free an allocated control or bulk pipe.
void
free_pipe(struct usb_pipe *pipe)
{
    ASSERT32FLAT();
    if (!pipe)
        return;
    switch (pipe->type) {
    default:
    case USB_TYPE_UHCI:
        return uhci_free_pipe(pipe);
    case USB_TYPE_OHCI:
        return ohci_free_pipe(pipe);
    case USB_TYPE_EHCI:
        return ehci_free_pipe(pipe);
    }
}

// Allocate a control pipe to a default endpoint (which can only be
// used by 32bit code)
static struct usb_pipe *
alloc_default_control_pipe(struct usb_pipe *dummy)
{
    switch (dummy->type) {
    default:
    case USB_TYPE_UHCI:
        return uhci_alloc_control_pipe(dummy);
    case USB_TYPE_OHCI:
        return ohci_alloc_control_pipe(dummy);
    case USB_TYPE_EHCI:
        return ehci_alloc_control_pipe(dummy);
    }
}

// Send a message on a control pipe using the default control descriptor.
static int
send_control(struct usb_pipe *pipe, int dir, const void *cmd, int cmdsize
             , void *data, int datasize)
{
    ASSERT32FLAT();
    switch (pipe->type) {
    default:
    case USB_TYPE_UHCI:
        return uhci_control(pipe, dir, cmd, cmdsize, data, datasize);
    case USB_TYPE_OHCI:
        return ohci_control(pipe, dir, cmd, cmdsize, data, datasize);
    case USB_TYPE_EHCI:
        return ehci_control(pipe, dir, cmd, cmdsize, data, datasize);
    }
}

// Fill "pipe" endpoint info from an endpoint descriptor.
static void
desc2pipe(struct usb_pipe *newpipe, struct usb_pipe *origpipe
          , struct usb_endpoint_descriptor *epdesc)
{
    memcpy(newpipe, origpipe, sizeof(*newpipe));
    newpipe->ep = epdesc->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK;
    newpipe->maxpacket = epdesc->wMaxPacketSize;
}

struct usb_pipe *
alloc_bulk_pipe(struct usb_pipe *pipe, struct usb_endpoint_descriptor *epdesc)
{
    struct usb_pipe dummy;
    desc2pipe(&dummy, pipe, epdesc);
    switch (pipe->type) {
    default:
    case USB_TYPE_UHCI:
        return uhci_alloc_bulk_pipe(&dummy);
    case USB_TYPE_OHCI:
        return ohci_alloc_bulk_pipe(&dummy);
    case USB_TYPE_EHCI:
        return ehci_alloc_bulk_pipe(&dummy);
    }
}

int
usb_send_bulk(struct usb_pipe *pipe_fl, int dir, void *data, int datasize)
{
    switch (GET_FLATPTR(pipe_fl->type)) {
    default:
    case USB_TYPE_UHCI:
        return uhci_send_bulk(pipe_fl, dir, data, datasize);
    case USB_TYPE_OHCI:
        return ohci_send_bulk(pipe_fl, dir, data, datasize);
    case USB_TYPE_EHCI:
        return ehci_send_bulk(pipe_fl, dir, data, datasize);
    }
}

struct usb_pipe *
alloc_intr_pipe(struct usb_pipe *pipe, struct usb_endpoint_descriptor *epdesc)
{
    struct usb_pipe dummy;
    desc2pipe(&dummy, pipe, epdesc);
    // Find the exponential period of the requested time.
    int period = epdesc->bInterval;
    int frameexp;
    if (pipe->speed != USB_HIGHSPEED)
        frameexp = (period <= 0) ? 0 : __fls(period);
    else
        frameexp = (period <= 4) ? 0 : period - 4;
    switch (pipe->type) {
    default:
    case USB_TYPE_UHCI:
        return uhci_alloc_intr_pipe(&dummy, frameexp);
    case USB_TYPE_OHCI:
        return ohci_alloc_intr_pipe(&dummy, frameexp);
    case USB_TYPE_EHCI:
        return ehci_alloc_intr_pipe(&dummy, frameexp);
    }
}

int noinline
usb_poll_intr(struct usb_pipe *pipe_fl, void *data)
{
    switch (GET_FLATPTR(pipe_fl->type)) {
    default:
    case USB_TYPE_UHCI:
        return uhci_poll_intr(pipe_fl, data);
    case USB_TYPE_OHCI:
        return ohci_poll_intr(pipe_fl, data);
    case USB_TYPE_EHCI:
        return ehci_poll_intr(pipe_fl, data);
    }
}


/****************************************************************
 * Helper functions
 ****************************************************************/

// Find the first endpoing of a given type in an interface description.
struct usb_endpoint_descriptor *
findEndPointDesc(struct usb_interface_descriptor *iface, int imax
                 , int type, int dir)
{
    struct usb_endpoint_descriptor *epdesc = (void*)&iface[1];
    for (;;) {
        if ((void*)epdesc >= (void*)iface + imax
            || epdesc->bDescriptorType == USB_DT_INTERFACE) {
            return NULL;
        }
        if (epdesc->bDescriptorType == USB_DT_ENDPOINT
            && (epdesc->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == dir
            && (epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == type)
            return epdesc;
        epdesc = (void*)epdesc + epdesc->bLength;
    }
}

// Send a message to the default control pipe of a device.
int
send_default_control(struct usb_pipe *pipe, const struct usb_ctrlrequest *req
                     , void *data)
{
    return send_control(pipe, req->bRequestType & USB_DIR_IN
                        , req, sizeof(*req), data, req->wLength);
}

// Get the first 8 bytes of the device descriptor.
static int
get_device_info8(struct usb_pipe *pipe, struct usb_device_descriptor *dinfo)
{
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
    req.bRequest = USB_REQ_GET_DESCRIPTOR;
    req.wValue = USB_DT_DEVICE<<8;
    req.wIndex = 0;
    req.wLength = 8;
    return send_default_control(pipe, &req, dinfo);
}

static struct usb_config_descriptor *
get_device_config(struct usb_pipe *pipe)
{
    struct usb_config_descriptor cfg;

    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
    req.bRequest = USB_REQ_GET_DESCRIPTOR;
    req.wValue = USB_DT_CONFIG<<8;
    req.wIndex = 0;
    req.wLength = sizeof(cfg);
    int ret = send_default_control(pipe, &req, &cfg);
    if (ret)
        return NULL;

    void *config = malloc_tmphigh(cfg.wTotalLength);
    if (!config)
        return NULL;
    req.wLength = cfg.wTotalLength;
    ret = send_default_control(pipe, &req, config);
    if (ret)
        return NULL;
    //hexdump(config, cfg.wTotalLength);
    return config;
}

static int
set_configuration(struct usb_pipe *pipe, u16 val)
{
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
    req.bRequest = USB_REQ_SET_CONFIGURATION;
    req.wValue = val;
    req.wIndex = 0;
    req.wLength = 0;
    return send_default_control(pipe, &req, NULL);
}


/****************************************************************
 * Initialization and enumeration
 ****************************************************************/

// Assign an address to a device in the default state on the given
// controller.
static struct usb_pipe *
usb_set_address(struct usbhub_s *hub, int port, int speed)
{
    ASSERT32FLAT();
    struct usb_s *cntl = hub->cntl;
    dprintf(3, "set_address %p\n", cntl);
    if (cntl->maxaddr >= USB_MAXADDR)
        return NULL;

    struct usb_pipe *defpipe = cntl->defaultpipe;
    if (!defpipe) {
        // Create a pipe for the default address.
        struct usb_pipe dummy;
        memset(&dummy, 0, sizeof(dummy));
        dummy.cntl = cntl;
        dummy.type = cntl->type;
        dummy.maxpacket = 8;
        dummy.path = (u64)-1;
        cntl->defaultpipe = defpipe = alloc_default_control_pipe(&dummy);
        if (!defpipe)
            return NULL;
    }
    defpipe->speed = speed;
    if (hub->pipe) {
        if (hub->pipe->speed == USB_HIGHSPEED) {
            defpipe->tt_devaddr = hub->pipe->devaddr;
            defpipe->tt_port = port;
        } else {
            defpipe->tt_devaddr = hub->pipe->tt_devaddr;
            defpipe->tt_port = hub->pipe->tt_port;
        }
    } else {
        defpipe->tt_devaddr = defpipe->tt_port = 0;
    }

    msleep(USB_TIME_RSTRCY);

    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
    req.bRequest = USB_REQ_SET_ADDRESS;
    req.wValue = cntl->maxaddr + 1;
    req.wIndex = 0;
    req.wLength = 0;
    int ret = send_default_control(defpipe, &req, NULL);
    if (ret)
        return NULL;

    msleep(USB_TIME_SETADDR_RECOVERY);

    cntl->maxaddr++;
    defpipe->devaddr = cntl->maxaddr;
    struct usb_pipe *pipe = alloc_default_control_pipe(defpipe);
    defpipe->devaddr = 0;
    if (hub->pipe)
        pipe->path = hub->pipe->path;
    pipe->path = (pipe->path << 8) | port;
    return pipe;
}

// Called for every found device - see if a driver is available for
// this device and do setup if so.
static int
configure_usb_device(struct usb_pipe *pipe)
{
    ASSERT32FLAT();
    dprintf(3, "config_usb: %p\n", pipe);

    // Set the max packet size for endpoint 0 of this device.
    struct usb_device_descriptor dinfo;
    int ret = get_device_info8(pipe, &dinfo);
    if (ret)
        return 0;
    dprintf(3, "device rev=%04x cls=%02x sub=%02x proto=%02x size=%02x\n"
            , dinfo.bcdUSB, dinfo.bDeviceClass, dinfo.bDeviceSubClass
            , dinfo.bDeviceProtocol, dinfo.bMaxPacketSize0);
    if (dinfo.bMaxPacketSize0 < 8 || dinfo.bMaxPacketSize0 > 64)
        return 0;
    pipe->maxpacket = dinfo.bMaxPacketSize0;

    // Get configuration
    struct usb_config_descriptor *config = get_device_config(pipe);
    if (!config)
        return 0;

    // Determine if a driver exists for this device - only look at the
    // first interface of the first configuration.
    struct usb_interface_descriptor *iface = (void*)(&config[1]);
    if (iface->bInterfaceClass != USB_CLASS_HID
        && iface->bInterfaceClass != USB_CLASS_MASS_STORAGE
        && iface->bInterfaceClass != USB_CLASS_HUB)
        // Not a supported device.
        goto fail;

    // Set the configuration.
    ret = set_configuration(pipe, config->bConfigurationValue);
    if (ret)
        goto fail;

    // Configure driver.
    int imax = (void*)config + config->wTotalLength - (void*)iface;
    if (iface->bInterfaceClass == USB_CLASS_HUB)
        ret = usb_hub_init(pipe);
    else if (iface->bInterfaceClass == USB_CLASS_MASS_STORAGE)
        ret = usb_msc_init(pipe, iface, imax);
    else
        ret = usb_hid_init(pipe, iface, imax);
    if (ret)
        goto fail;

    free(config);
    return 1;
fail:
    free(config);
    return 0;
}

static void
usb_init_hub_port(void *data)
{
    struct usbhub_s *hub = data;
    u32 port = hub->port; // XXX - find better way to pass port

    // Detect if device present (and possibly start reset)
    int ret = hub->op->detect(hub, port);
    if (ret)
        // No device present
        goto done;

    // Reset port and determine device speed
    mutex_lock(&hub->cntl->resetlock);
    ret = hub->op->reset(hub, port);
    if (ret < 0)
        // Reset failed
        goto resetfail;

    // Set address of port
    struct usb_pipe *pipe = usb_set_address(hub, port, ret);
    if (!pipe) {
        hub->op->disconnect(hub, port);
        goto resetfail;
    }
    mutex_unlock(&hub->cntl->resetlock);

    // Configure the device
    int count = configure_usb_device(pipe);
    free_pipe(pipe);
    if (!count)
        hub->op->disconnect(hub, port);
    hub->devcount += count;
done:
    hub->threads--;
    return;

resetfail:
    mutex_unlock(&hub->cntl->resetlock);
    goto done;
}

void
usb_enumerate(struct usbhub_s *hub)
{
    u32 portcount = hub->portcount;
    hub->threads = portcount;

    // Launch a thread for every port.
    int i;
    for (i=0; i<portcount; i++) {
        hub->port = i;
        run_thread(usb_init_hub_port, hub);
    }

    // Wait for threads to complete.
    while (hub->threads)
        yield();
}

void
usb_setup(void)
{
    ASSERT32FLAT();
    if (! CONFIG_USB)
        return;

    dprintf(3, "init usb\n");

    // Look for USB controllers
    int count = 0;
    struct pci_device *ehcipci = PCIDevices;
    struct pci_device *pci;
    foreachpci(pci) {
        if (pci->class != PCI_CLASS_SERIAL_USB)
            continue;

        if (pci->bdf >= ehcipci->bdf) {
            // Check to see if this device has an ehci controller
            int found = 0;
            ehcipci = pci;
            for (;;) {
                if (pci_classprog(ehcipci) == PCI_CLASS_SERIAL_USB_EHCI) {
                    // Found an ehci controller.
                    int ret = ehci_init(ehcipci, count++, pci);
                    if (ret)
                        // Error
                        break;
                    count += found;
                    pci = ehcipci;
                    break;
                }
                if (ehcipci->class == PCI_CLASS_SERIAL_USB)
                    found++;
                ehcipci = ehcipci->next;
                if (!ehcipci || (pci_bdf_to_busdev(ehcipci->bdf)
                                 != pci_bdf_to_busdev(pci->bdf)))
                    // No ehci controller found.
                    break;
            }
        }

        if (pci_classprog(pci) == PCI_CLASS_SERIAL_USB_UHCI)
            uhci_init(pci, count++);
        else if (pci_classprog(pci) == PCI_CLASS_SERIAL_USB_OHCI)
            ohci_init(pci, count++);
    }
}
