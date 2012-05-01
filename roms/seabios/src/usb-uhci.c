// Code for handling UHCI USB controllers.
//
// Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "util.h" // dprintf
#include "pci.h" // pci_bdf_to_bus
#include "config.h" // CONFIG_*
#include "ioport.h" // outw
#include "usb-uhci.h" // USBLEGSUP
#include "pci_regs.h" // PCI_BASE_ADDRESS_4
#include "usb.h" // struct usb_s
#include "farptr.h" // GET_FLATPTR

struct usb_uhci_s {
    struct usb_s usb;
    u16 iobase;
    struct uhci_qh *control_qh, *bulk_qh;
    struct uhci_framelist *framelist;
};


/****************************************************************
 * Root hub
 ****************************************************************/

// Check if device attached to a given port
static int
uhci_hub_detect(struct usbhub_s *hub, u32 port)
{
    struct usb_uhci_s *cntl = container_of(hub->cntl, struct usb_uhci_s, usb);
    u16 ioport = cntl->iobase + USBPORTSC1 + port * 2;

    u16 status = inw(ioport);
    if (!(status & USBPORTSC_CCS))
        // No device
        return -1;

    // XXX - if just powered up, need to wait for USB_TIME_ATTDB?

    // Begin reset on port
    outw(USBPORTSC_PR, ioport);
    msleep(USB_TIME_DRSTR);
    return 0;
}

// Reset device on port
static int
uhci_hub_reset(struct usbhub_s *hub, u32 port)
{
    struct usb_uhci_s *cntl = container_of(hub->cntl, struct usb_uhci_s, usb);
    u16 ioport = cntl->iobase + USBPORTSC1 + port * 2;

    // Finish reset on port
    outw(0, ioport);
    udelay(6); // 64 high-speed bit times
    u16 status = inw(ioport);
    if (!(status & USBPORTSC_CCS))
        // No longer connected
        return -1;
    outw(USBPORTSC_PE, ioport);
    return !!(status & USBPORTSC_LSDA);
}

// Disable port
static void
uhci_hub_disconnect(struct usbhub_s *hub, u32 port)
{
    struct usb_uhci_s *cntl = container_of(hub->cntl, struct usb_uhci_s, usb);
    u16 ioport = cntl->iobase + USBPORTSC1 + port * 2;
    outw(0, ioport);
}

static struct usbhub_op_s uhci_HubOp = {
    .detect = uhci_hub_detect,
    .reset = uhci_hub_reset,
    .disconnect = uhci_hub_disconnect,
};

// Find any devices connected to the root hub.
static int
check_uhci_ports(struct usb_uhci_s *cntl)
{
    ASSERT32FLAT();
    struct usbhub_s hub;
    memset(&hub, 0, sizeof(hub));
    hub.cntl = &cntl->usb;
    hub.portcount = 2;
    hub.op = &uhci_HubOp;
    usb_enumerate(&hub);
    return hub.devcount;
}


/****************************************************************
 * Setup
 ****************************************************************/

static void
reset_uhci(struct usb_uhci_s *cntl, u16 bdf)
{
    // XXX - don't reset if not needed.

    // Reset PIRQ and SMI
    pci_config_writew(bdf, USBLEGSUP, USBLEGSUP_RWC);

    // Reset the HC
    outw(USBCMD_HCRESET, cntl->iobase + USBCMD);
    udelay(5);

    // Disable interrupts and commands (just to be safe).
    outw(0, cntl->iobase + USBINTR);
    outw(0, cntl->iobase + USBCMD);
}

static void
configure_uhci(void *data)
{
    struct usb_uhci_s *cntl = data;

    // Allocate ram for schedule storage
    struct uhci_td *term_td = malloc_high(sizeof(*term_td));
    struct uhci_framelist *fl = memalign_high(sizeof(*fl), sizeof(*fl));
    struct uhci_qh *intr_qh = malloc_high(sizeof(*intr_qh));
    struct uhci_qh *term_qh = malloc_high(sizeof(*term_qh));
    if (!term_td || !fl || !intr_qh || !term_qh) {
        warn_noalloc();
        goto fail;
    }

    // Work around for PIIX errata
    memset(term_td, 0, sizeof(*term_td));
    term_td->link = UHCI_PTR_TERM;
    term_td->token = (uhci_explen(0) | (0x7f << TD_TOKEN_DEVADDR_SHIFT)
                      | USB_PID_IN);
    memset(term_qh, 0, sizeof(*term_qh));
    term_qh->element = (u32)term_td;
    term_qh->link = UHCI_PTR_TERM;

    // Set schedule to point to primary intr queue head
    memset(intr_qh, 0, sizeof(*intr_qh));
    intr_qh->element = UHCI_PTR_TERM;
    intr_qh->link = (u32)term_qh | UHCI_PTR_QH;
    int i;
    for (i=0; i<ARRAY_SIZE(fl->links); i++)
        fl->links[i] = (u32)intr_qh | UHCI_PTR_QH;
    cntl->framelist = fl;
    cntl->control_qh = cntl->bulk_qh = intr_qh;
    barrier();

    // Set the frame length to the default: 1 ms exactly
    outb(USBSOF_DEFAULT, cntl->iobase + USBSOF);

    // Store the frame list base address
    outl((u32)fl->links, cntl->iobase + USBFLBASEADD);

    // Set the current frame number
    outw(0, cntl->iobase + USBFRNUM);

    // Mark as configured and running with a 64-byte max packet.
    outw(USBCMD_RS | USBCMD_CF | USBCMD_MAXP, cntl->iobase + USBCMD);

    // Find devices
    int count = check_uhci_ports(cntl);
    free_pipe(cntl->usb.defaultpipe);
    if (count)
        // Success
        return;

    // No devices found - shutdown and free controller.
    outw(0, cntl->iobase + USBCMD);
fail:
    free(term_td);
    free(fl);
    free(intr_qh);
    free(term_qh);
    free(cntl);
}

void
uhci_init(struct pci_device *pci, int busid)
{
    if (! CONFIG_USB_UHCI)
        return;
    u16 bdf = pci->bdf;
    struct usb_uhci_s *cntl = malloc_tmphigh(sizeof(*cntl));
    if (!cntl) {
        warn_noalloc();
        return;
    }
    memset(cntl, 0, sizeof(*cntl));
    cntl->usb.busid = busid;
    cntl->usb.pci = pci;
    cntl->usb.type = USB_TYPE_UHCI;
    cntl->iobase = (pci_config_readl(bdf, PCI_BASE_ADDRESS_4)
                    & PCI_BASE_ADDRESS_IO_MASK);

    dprintf(1, "UHCI init on dev %02x:%02x.%x (io=%x)\n"
            , pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf)
            , pci_bdf_to_fn(bdf), cntl->iobase);

    pci_config_maskw(bdf, PCI_COMMAND, 0, PCI_COMMAND_MASTER);

    reset_uhci(cntl, bdf);

    run_thread(configure_uhci, cntl);
}


/****************************************************************
 * End point communication
 ****************************************************************/

static int
wait_qh(struct usb_uhci_s *cntl, struct uhci_qh *qh)
{
    // XXX - 500ms just a guess
    u64 end = calc_future_tsc(500);
    for (;;) {
        if (qh->element & UHCI_PTR_TERM)
            return 0;
        if (check_tsc(end)) {
            warn_timeout();
            struct uhci_td *td = (void*)(qh->element & ~UHCI_PTR_BITS);
            dprintf(1, "Timeout on wait_qh %p (td=%p s=%x c=%x/%x)\n"
                    , qh, td, td->status
                    , inw(cntl->iobase + USBCMD)
                    , inw(cntl->iobase + USBSTS));
            return -1;
        }
        yield();
    }
}

// Wait for next USB frame to start - for ensuring safe memory release.
static void
uhci_waittick(u16 iobase)
{
    barrier();
    u16 startframe = inw(iobase + USBFRNUM);
    u64 end = calc_future_tsc(1000 * 5);
    for (;;) {
        if (inw(iobase + USBFRNUM) != startframe)
            break;
        if (check_tsc(end)) {
            warn_timeout();
            return;
        }
        yield();
    }
}

struct uhci_pipe {
    struct uhci_qh qh;
    struct uhci_td *next_td;
    struct usb_pipe pipe;
    u16 iobase;
    u8 toggle;
};

void
uhci_free_pipe(struct usb_pipe *p)
{
    if (! CONFIG_USB_UHCI)
        return;
    dprintf(7, "uhci_free_pipe %p\n", p);
    struct uhci_pipe *pipe = container_of(p, struct uhci_pipe, pipe);
    struct usb_uhci_s *cntl = container_of(
        pipe->pipe.cntl, struct usb_uhci_s, usb);

    struct uhci_qh *pos = (void*)(cntl->framelist->links[0] & ~UHCI_PTR_BITS);
    for (;;) {
        u32 link = pos->link;
        if (link == UHCI_PTR_TERM) {
            // Not found?!  Exit without freeing.
            warn_internalerror();
            return;
        }
        struct uhci_qh *next = (void*)(link & ~UHCI_PTR_BITS);
        if (next == &pipe->qh) {
            pos->link = next->link;
            if (cntl->control_qh == next)
                cntl->control_qh = pos;
            if (cntl->bulk_qh == next)
                cntl->bulk_qh = pos;
            uhci_waittick(cntl->iobase);
            free(pipe);
            return;
        }
        pos = next;
    }
}

struct usb_pipe *
uhci_alloc_control_pipe(struct usb_pipe *dummy)
{
    if (! CONFIG_USB_UHCI)
        return NULL;
    struct usb_uhci_s *cntl = container_of(
        dummy->cntl, struct usb_uhci_s, usb);
    dprintf(7, "uhci_alloc_control_pipe %p\n", &cntl->usb);

    // Allocate a queue head.
    struct uhci_pipe *pipe = malloc_tmphigh(sizeof(*pipe));
    if (!pipe) {
        warn_noalloc();
        return NULL;
    }
    memset(pipe, 0, sizeof(*pipe));
    memcpy(&pipe->pipe, dummy, sizeof(pipe->pipe));
    pipe->qh.element = UHCI_PTR_TERM;
    pipe->iobase = cntl->iobase;

    // Add queue head to controller list.
    struct uhci_qh *control_qh = cntl->control_qh;
    pipe->qh.link = control_qh->link;
    barrier();
    control_qh->link = (u32)&pipe->qh | UHCI_PTR_QH;
    if (cntl->bulk_qh == control_qh)
        cntl->bulk_qh = &pipe->qh;
    return &pipe->pipe;
}

int
uhci_control(struct usb_pipe *p, int dir, const void *cmd, int cmdsize
             , void *data, int datasize)
{
    ASSERT32FLAT();
    if (! CONFIG_USB_UHCI)
        return -1;
    dprintf(5, "uhci_control %p\n", p);
    struct uhci_pipe *pipe = container_of(p, struct uhci_pipe, pipe);
    struct usb_uhci_s *cntl = container_of(
        pipe->pipe.cntl, struct usb_uhci_s, usb);

    int maxpacket = pipe->pipe.maxpacket;
    int lowspeed = pipe->pipe.speed;
    int devaddr = pipe->pipe.devaddr | (pipe->pipe.ep << 7);

    // Setup transfer descriptors
    int count = 2 + DIV_ROUND_UP(datasize, maxpacket);
    struct uhci_td *tds = malloc_tmphigh(sizeof(*tds) * count);
    if (!tds) {
        warn_noalloc();
        return -1;
    }

    tds[0].link = (u32)&tds[1] | UHCI_PTR_DEPTH;
    tds[0].status = (uhci_maxerr(3) | (lowspeed ? TD_CTRL_LS : 0)
                     | TD_CTRL_ACTIVE);
    tds[0].token = (uhci_explen(cmdsize) | (devaddr << TD_TOKEN_DEVADDR_SHIFT)
                    | USB_PID_SETUP);
    tds[0].buffer = (void*)cmd;
    int toggle = TD_TOKEN_TOGGLE;
    int i;
    for (i=1; i<count-1; i++) {
        tds[i].link = (u32)&tds[i+1] | UHCI_PTR_DEPTH;
        tds[i].status = (uhci_maxerr(3) | (lowspeed ? TD_CTRL_LS : 0)
                         | TD_CTRL_ACTIVE);
        int len = (i == count-2 ? (datasize - (i-1)*maxpacket) : maxpacket);
        tds[i].token = (uhci_explen(len) | toggle
                        | (devaddr << TD_TOKEN_DEVADDR_SHIFT)
                        | (dir ? USB_PID_IN : USB_PID_OUT));
        tds[i].buffer = data + (i-1) * maxpacket;
        toggle ^= TD_TOKEN_TOGGLE;
    }
    tds[i].link = UHCI_PTR_TERM;
    tds[i].status = (uhci_maxerr(0) | (lowspeed ? TD_CTRL_LS : 0)
                     | TD_CTRL_ACTIVE);
    tds[i].token = (uhci_explen(0) | TD_TOKEN_TOGGLE
                    | (devaddr << TD_TOKEN_DEVADDR_SHIFT)
                    | (dir ? USB_PID_OUT : USB_PID_IN));
    tds[i].buffer = 0;

    // Transfer data
    barrier();
    pipe->qh.element = (u32)&tds[0];
    int ret = wait_qh(cntl, &pipe->qh);
    if (ret) {
        pipe->qh.element = UHCI_PTR_TERM;
        uhci_waittick(pipe->iobase);
    }
    free(tds);
    return ret;
}

struct usb_pipe *
uhci_alloc_bulk_pipe(struct usb_pipe *dummy)
{
    if (! CONFIG_USB_UHCI)
        return NULL;
    struct usb_uhci_s *cntl = container_of(
        dummy->cntl, struct usb_uhci_s, usb);
    dprintf(7, "uhci_alloc_bulk_pipe %p\n", &cntl->usb);

    // Allocate a queue head.
    struct uhci_pipe *pipe = malloc_low(sizeof(*pipe));
    if (!pipe) {
        warn_noalloc();
        return NULL;
    }
    memset(pipe, 0, sizeof(*pipe));
    memcpy(&pipe->pipe, dummy, sizeof(pipe->pipe));
    pipe->qh.element = UHCI_PTR_TERM;
    pipe->iobase = cntl->iobase;

    // Add queue head to controller list.
    struct uhci_qh *bulk_qh = cntl->bulk_qh;
    pipe->qh.link = bulk_qh->link;
    barrier();
    bulk_qh->link = (u32)&pipe->qh | UHCI_PTR_QH;

    return &pipe->pipe;
}

static int
wait_td(struct uhci_td *td)
{
    u64 end = calc_future_tsc(5000); // XXX - lookup real time.
    u32 status;
    for (;;) {
        status = td->status;
        if (!(status & TD_CTRL_ACTIVE))
            break;
        if (check_tsc(end)) {
            warn_timeout();
            return -1;
        }
        yield();
    }
    if (status & TD_CTRL_ANY_ERROR) {
        dprintf(1, "wait_td error - status=%x\n", status);
        return -2;
    }
    return 0;
}

#define STACKTDS 4
#define TDALIGN 16

int
uhci_send_bulk(struct usb_pipe *p, int dir, void *data, int datasize)
{
    if (! CONFIG_USB_UHCI)
        return -1;
    struct uhci_pipe *pipe = container_of(p, struct uhci_pipe, pipe);
    dprintf(7, "uhci_send_bulk qh=%p dir=%d data=%p size=%d\n"
            , &pipe->qh, dir, data, datasize);
    int maxpacket = GET_FLATPTR(pipe->pipe.maxpacket);
    int lowspeed = GET_FLATPTR(pipe->pipe.speed);
    int devaddr = (GET_FLATPTR(pipe->pipe.devaddr)
                   | (GET_FLATPTR(pipe->pipe.ep) << 7));
    int toggle = GET_FLATPTR(pipe->toggle) ? TD_TOKEN_TOGGLE : 0;

    // Allocate 4 tds on stack (16byte aligned)
    u8 tdsbuf[sizeof(struct uhci_td) * STACKTDS + TDALIGN - 1];
    struct uhci_td *tds = (void*)ALIGN((u32)tdsbuf, TDALIGN);
    memset(tds, 0, sizeof(*tds) * STACKTDS);

    // Enable tds
    barrier();
    SET_FLATPTR(pipe->qh.element, (u32)MAKE_FLATPTR(GET_SEG(SS), tds));

    int tdpos = 0;
    while (datasize) {
        struct uhci_td *td = &tds[tdpos++ % STACKTDS];
        int ret = wait_td(td);
        if (ret)
            goto fail;

        int transfer = datasize;
        if (transfer > maxpacket)
            transfer = maxpacket;
        struct uhci_td *nexttd_fl = MAKE_FLATPTR(GET_SEG(SS)
                                                 , &tds[tdpos % STACKTDS]);
        td->link = (transfer==datasize ? UHCI_PTR_TERM : (u32)nexttd_fl);
        td->token = (uhci_explen(transfer) | toggle
                     | (devaddr << TD_TOKEN_DEVADDR_SHIFT)
                     | (dir ? USB_PID_IN : USB_PID_OUT));
        td->buffer = data;
        barrier();
        td->status = (uhci_maxerr(3) | (lowspeed ? TD_CTRL_LS : 0)
                      | TD_CTRL_ACTIVE);
        toggle ^= TD_TOKEN_TOGGLE;

        data += transfer;
        datasize -= transfer;
    }
    int i;
    for (i=0; i<STACKTDS; i++) {
        struct uhci_td *td = &tds[tdpos++ % STACKTDS];
        int ret = wait_td(td);
        if (ret)
            goto fail;
    }

    SET_FLATPTR(pipe->toggle, !!toggle);
    return 0;
fail:
    dprintf(1, "uhci_send_bulk failed\n");
    SET_FLATPTR(pipe->qh.element, UHCI_PTR_TERM);
    uhci_waittick(GET_FLATPTR(pipe->iobase));
    return -1;
}

struct usb_pipe *
uhci_alloc_intr_pipe(struct usb_pipe *dummy, int frameexp)
{
    if (! CONFIG_USB_UHCI)
        return NULL;
    struct usb_uhci_s *cntl = container_of(
        dummy->cntl, struct usb_uhci_s, usb);
    dprintf(7, "uhci_alloc_intr_pipe %p %d\n", &cntl->usb, frameexp);

    if (frameexp > 10)
        frameexp = 10;
    int maxpacket = dummy->maxpacket;
    int lowspeed = dummy->speed;
    int devaddr = dummy->devaddr | (dummy->ep << 7);
    // Determine number of entries needed for 2 timer ticks.
    int ms = 1<<frameexp;
    int count = DIV_ROUND_UP(PIT_TICK_INTERVAL * 1000 * 2, PIT_TICK_RATE * ms);
    count = ALIGN(count, 2);
    struct uhci_pipe *pipe = malloc_low(sizeof(*pipe));
    struct uhci_td *tds = malloc_low(sizeof(*tds) * count);
    void *data = malloc_low(maxpacket * count);
    if (!pipe || !tds || !data) {
        warn_noalloc();
        goto fail;
    }
    memset(pipe, 0, sizeof(*pipe));
    memcpy(&pipe->pipe, dummy, sizeof(pipe->pipe));
    pipe->qh.element = (u32)tds;
    pipe->next_td = &tds[0];
    pipe->iobase = cntl->iobase;

    int toggle = 0;
    int i;
    for (i=0; i<count; i++) {
        tds[i].link = (i==count-1 ? (u32)&tds[0] : (u32)&tds[i+1]);
        tds[i].status = (uhci_maxerr(3) | (lowspeed ? TD_CTRL_LS : 0)
                         | TD_CTRL_ACTIVE);
        tds[i].token = (uhci_explen(maxpacket) | toggle
                        | (devaddr << TD_TOKEN_DEVADDR_SHIFT)
                        | USB_PID_IN);
        tds[i].buffer = data + maxpacket * i;
        toggle ^= TD_TOKEN_TOGGLE;
    }

    // Add to interrupt schedule.
    struct uhci_framelist *fl = cntl->framelist;
    if (frameexp == 0) {
        // Add to existing interrupt entry.
        struct uhci_qh *intr_qh = (void*)(fl->links[0] & ~UHCI_PTR_BITS);
        pipe->qh.link = intr_qh->link;
        barrier();
        intr_qh->link = (u32)&pipe->qh | UHCI_PTR_QH;
        if (cntl->control_qh == intr_qh)
            cntl->control_qh = &pipe->qh;
        if (cntl->bulk_qh == intr_qh)
            cntl->bulk_qh = &pipe->qh;
    } else {
        int startpos = 1<<(frameexp-1);
        pipe->qh.link = fl->links[startpos];
        barrier();
        for (i=startpos; i<ARRAY_SIZE(fl->links); i+=ms)
            fl->links[i] = (u32)&pipe->qh | UHCI_PTR_QH;
    }

    return &pipe->pipe;
fail:
    free(pipe);
    free(tds);
    free(data);
    return NULL;
}

int
uhci_poll_intr(struct usb_pipe *p, void *data)
{
    ASSERT16();
    if (! CONFIG_USB_UHCI)
        return -1;

    struct uhci_pipe *pipe = container_of(p, struct uhci_pipe, pipe);
    struct uhci_td *td = GET_FLATPTR(pipe->next_td);
    u32 status = GET_FLATPTR(td->status);
    u32 token = GET_FLATPTR(td->token);
    if (status & TD_CTRL_ACTIVE)
        // No intrs found.
        return -1;
    // XXX - check for errors.

    // Copy data.
    void *tddata = GET_FLATPTR(td->buffer);
    memcpy_far(GET_SEG(SS), data
               , FLATPTR_TO_SEG(tddata), (void*)FLATPTR_TO_OFFSET(tddata)
               , uhci_expected_length(token));

    // Reenable this td.
    struct uhci_td *next = (void*)(GET_FLATPTR(td->link) & ~UHCI_PTR_BITS);
    SET_FLATPTR(pipe->next_td, next);
    barrier();
    SET_FLATPTR(td->status, (uhci_maxerr(0) | (status & TD_CTRL_LS)
                             | TD_CTRL_ACTIVE));

    return 0;
}
