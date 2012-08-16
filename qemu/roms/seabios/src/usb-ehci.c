// Code for handling EHCI USB controllers.
//
// Copyright (C) 2010  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "util.h" // dprintf
#include "pci.h" // pci_bdf_to_bus
#include "config.h" // CONFIG_*
#include "ioport.h" // outw
#include "usb-ehci.h" // struct ehci_qh
#include "pci_ids.h" // PCI_CLASS_SERIAL_USB_UHCI
#include "pci_regs.h" // PCI_BASE_ADDRESS_0
#include "usb.h" // struct usb_s
#include "farptr.h" // GET_FLATPTR
#include "usb-uhci.h" // init_uhci
#include "usb-ohci.h" // init_ohci

struct usb_ehci_s {
    struct usb_s usb;
    struct ehci_caps *caps;
    struct ehci_regs *regs;
    struct ehci_qh *async_qh;
    struct pci_device *companion[8];
    int checkports;
    int legacycount;
};


/****************************************************************
 * Root hub
 ****************************************************************/

#define EHCI_TIME_POSTPOWER 20
#define EHCI_TIME_POSTRESET 2

// Check if need companion controllers for full/low speed devices
static void
ehci_note_port(struct usb_ehci_s *cntl)
{
    if (--cntl->checkports)
        // Ports still being detected.
        return;
    if (! cntl->legacycount)
        // No full/low speed devices found.
        return;
    // Start companion controllers.
    int i;
    for (i=0; i<ARRAY_SIZE(cntl->companion); i++) {
        struct pci_device *pci = cntl->companion[i];
        if (!pci)
            break;

        // ohci/uhci_init call pci_config_XXX - don't run from irq handler.
        wait_preempt();

        if (pci_classprog(pci) == PCI_CLASS_SERIAL_USB_UHCI)
            uhci_init(pci, cntl->usb.busid + i);
        else if (pci_classprog(pci) == PCI_CLASS_SERIAL_USB_OHCI)
            ohci_init(pci, cntl->usb.busid + i);
    }
}

// Check if device attached to port
static int
ehci_hub_detect(struct usbhub_s *hub, u32 port)
{
    struct usb_ehci_s *cntl = container_of(hub->cntl, struct usb_ehci_s, usb);
    u32 *portreg = &cntl->regs->portsc[port];
    u32 portsc = readl(portreg);

    // Power up port.
    if (!(portsc & PORT_POWER)) {
        portsc |= PORT_POWER;
        writel(portreg, portsc);
        msleep(EHCI_TIME_POSTPOWER);
    } else {
        msleep(1); // XXX - time for connect to be detected.
    }
    portsc = readl(portreg);

    if (!(portsc & PORT_CONNECT))
        // No device present
        goto doneearly;

    if ((portsc & PORT_LINESTATUS_MASK) == PORT_LINESTATUS_KSTATE) {
        // low speed device
        cntl->legacycount++;
        writel(portreg, portsc | PORT_OWNER);
        goto doneearly;
    }

    // XXX - if just powered up, need to wait for USB_TIME_ATTDB?

    // Begin reset on port
    portsc = (portsc & ~PORT_PE) | PORT_RESET;
    writel(portreg, portsc);
    msleep(USB_TIME_DRSTR);
    return 0;

doneearly:
    ehci_note_port(cntl);
    return -1;
}

// Reset device on port
static int
ehci_hub_reset(struct usbhub_s *hub, u32 port)
{
    struct usb_ehci_s *cntl = container_of(hub->cntl, struct usb_ehci_s, usb);
    u32 *portreg = &cntl->regs->portsc[port];
    u32 portsc = readl(portreg);

    // Finish reset on port
    portsc &= ~PORT_RESET;
    writel(portreg, portsc);
    msleep(EHCI_TIME_POSTRESET);

    int rv = -1;
    portsc = readl(portreg);
    if (!(portsc & PORT_CONNECT))
        // No longer connected
        goto resetfail;
    if (!(portsc & PORT_PE)) {
        // full speed device
        cntl->legacycount++;
        writel(portreg, portsc | PORT_OWNER);
        goto resetfail;
    }

    rv = USB_HIGHSPEED;
resetfail:
    ehci_note_port(cntl);
    return rv;
}

// Disable port
static void
ehci_hub_disconnect(struct usbhub_s *hub, u32 port)
{
    struct usb_ehci_s *cntl = container_of(hub->cntl, struct usb_ehci_s, usb);
    u32 *portreg = &cntl->regs->portsc[port];
    u32 portsc = readl(portreg);
    writel(portreg, portsc & ~PORT_PE);
}

static struct usbhub_op_s ehci_HubOp = {
    .detect = ehci_hub_detect,
    .reset = ehci_hub_reset,
    .disconnect = ehci_hub_disconnect,
};

// Find any devices connected to the root hub.
static int
check_ehci_ports(struct usb_ehci_s *cntl)
{
    ASSERT32FLAT();
    struct usbhub_s hub;
    memset(&hub, 0, sizeof(hub));
    hub.cntl = &cntl->usb;
    hub.portcount = cntl->checkports;
    hub.op = &ehci_HubOp;
    usb_enumerate(&hub);
    return hub.devcount;
}


/****************************************************************
 * Setup
 ****************************************************************/

static void
configure_ehci(void *data)
{
    struct usb_ehci_s *cntl = data;

    // Allocate ram for schedule storage
    struct ehci_framelist *fl = memalign_high(sizeof(*fl), sizeof(*fl));
    struct ehci_qh *intr_qh = memalign_high(EHCI_QH_ALIGN, sizeof(*intr_qh));
    struct ehci_qh *async_qh = memalign_high(EHCI_QH_ALIGN, sizeof(*async_qh));
    if (!fl || !intr_qh || !async_qh) {
        warn_noalloc();
        goto fail;
    }

    // XXX - check for halted?

    // Reset the HC
    u32 cmd = readl(&cntl->regs->usbcmd);
    writel(&cntl->regs->usbcmd, (cmd & ~(CMD_ASE | CMD_PSE)) | CMD_HCRESET);
    u64 end = calc_future_tsc(250);
    for (;;) {
        cmd = readl(&cntl->regs->usbcmd);
        if (!(cmd & CMD_HCRESET))
            break;
        if (check_tsc(end)) {
            warn_timeout();
            goto fail;
        }
        yield();
    }

    // Disable interrupts (just to be safe).
    writel(&cntl->regs->usbintr, 0);

    // Set schedule to point to primary intr queue head
    memset(intr_qh, 0, sizeof(*intr_qh));
    intr_qh->next = EHCI_PTR_TERM;
    intr_qh->info2 = (0x01 << QH_SMASK_SHIFT);
    intr_qh->token = QTD_STS_HALT;
    intr_qh->qtd_next = intr_qh->alt_next = EHCI_PTR_TERM;
    int i;
    for (i=0; i<ARRAY_SIZE(fl->links); i++)
        fl->links[i] = (u32)intr_qh | EHCI_PTR_QH;
    writel(&cntl->regs->periodiclistbase, (u32)fl);

    // Set async list to point to primary async queue head
    memset(async_qh, 0, sizeof(*async_qh));
    async_qh->next = (u32)async_qh | EHCI_PTR_QH;
    async_qh->info1 = QH_HEAD;
    async_qh->token = QTD_STS_HALT;
    async_qh->qtd_next = async_qh->alt_next = EHCI_PTR_TERM;
    cntl->async_qh = async_qh;
    writel(&cntl->regs->asynclistbase, (u32)async_qh);

    // Enable queues
    writel(&cntl->regs->usbcmd, cmd | CMD_ASE | CMD_PSE | CMD_RUN);

    // Set default of high speed for root hub.
    writel(&cntl->regs->configflag, 1);
    cntl->checkports = readl(&cntl->caps->hcsparams) & HCS_N_PORTS_MASK;

    // Find devices
    int count = check_ehci_ports(cntl);
    free_pipe(cntl->usb.defaultpipe);
    if (count)
        // Success
        return;

    // No devices found - shutdown and free controller.
    writel(&cntl->regs->usbcmd, cmd & ~CMD_RUN);
    msleep(4);  // 2ms to stop reading memory - XXX
fail:
    free(fl);
    free(intr_qh);
    free(async_qh);
    free(cntl);
}

int
ehci_init(struct pci_device *pci, int busid, struct pci_device *comppci)
{
    if (! CONFIG_USB_EHCI)
        return -1;

    u16 bdf = pci->bdf;
    u32 baseaddr = pci_config_readl(bdf, PCI_BASE_ADDRESS_0);
    struct ehci_caps *caps = (void*)(baseaddr & PCI_BASE_ADDRESS_MEM_MASK);
    u32 hcc_params = readl(&caps->hccparams);
    if (hcc_params & HCC_64BIT_ADDR) {
        dprintf(1, "No support for 64bit EHCI\n");
        return -1;
    }

    struct usb_ehci_s *cntl = malloc_tmphigh(sizeof(*cntl));
    if (!cntl) {
        warn_noalloc();
        return -1;
    }
    memset(cntl, 0, sizeof(*cntl));
    cntl->usb.busid = busid;
    cntl->usb.pci = pci;
    cntl->usb.type = USB_TYPE_EHCI;
    cntl->caps = caps;
    cntl->regs = (void*)caps + readb(&caps->caplength);

    dprintf(1, "EHCI init on dev %02x:%02x.%x (regs=%p)\n"
            , pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf)
            , pci_bdf_to_fn(bdf), cntl->regs);

    pci_config_maskw(bdf, PCI_COMMAND, 0, PCI_COMMAND_MASTER);

    // XXX - check for and disable SMM control?

    // Find companion controllers.
    int count = 0;
    for (;;) {
        if (!comppci || comppci == pci)
            break;
        if (pci_classprog(comppci) == PCI_CLASS_SERIAL_USB_UHCI)
            cntl->companion[count++] = comppci;
        else if (pci_classprog(comppci) == PCI_CLASS_SERIAL_USB_OHCI)
            cntl->companion[count++] = comppci;
        comppci = comppci->next;
    }

    run_thread(configure_ehci, cntl);
    return 0;
}


/****************************************************************
 * End point communication
 ****************************************************************/

static int
ehci_wait_qh(struct usb_ehci_s *cntl, struct ehci_qh *qh)
{
    // XXX - 500ms just a guess
    u64 end = calc_future_tsc(500);
    for (;;) {
        if (qh->qtd_next & EHCI_PTR_TERM)
            // XXX - confirm
            return 0;
        if (check_tsc(end)) {
            warn_timeout();
            return -1;
        }
        yield();
    }
}

// Wait for next USB async frame to start - for ensuring safe memory release.
static void
ehci_waittick(struct usb_ehci_s *cntl)
{
    if (MODE16) {
        msleep(10);
        return;
    }
    // Wait for access to "doorbell"
    barrier();
    u32 cmd, sts;
    u64 end = calc_future_tsc(100);
    for (;;) {
        sts = readl(&cntl->regs->usbsts);
        if (!(sts & STS_IAA)) {
            cmd = readl(&cntl->regs->usbcmd);
            if (!(cmd & CMD_IAAD))
                break;
        }
        if (check_tsc(end)) {
            warn_timeout();
            return;
        }
        yield();
    }
    // Ring "doorbell"
    writel(&cntl->regs->usbcmd, cmd | CMD_IAAD);
    // Wait for completion
    for (;;) {
        sts = readl(&cntl->regs->usbsts);
        if (sts & STS_IAA)
            break;
        if (check_tsc(end)) {
            warn_timeout();
            return;
        }
        yield();
    }
    // Ack completion
    writel(&cntl->regs->usbsts, STS_IAA);
}

struct ehci_pipe {
    struct ehci_qh qh;
    struct ehci_qtd *next_td, *tds;
    void *data;
    struct usb_pipe pipe;
};

void
ehci_free_pipe(struct usb_pipe *p)
{
    if (! CONFIG_USB_EHCI)
        return;
    dprintf(7, "ehci_free_pipe %p\n", p);
    struct ehci_pipe *pipe = container_of(p, struct ehci_pipe, pipe);
    struct usb_ehci_s *cntl = container_of(
        pipe->pipe.cntl, struct usb_ehci_s, usb);

    struct ehci_qh *start = cntl->async_qh;
    struct ehci_qh *pos = start;
    for (;;) {
        struct ehci_qh *next = (void*)(pos->next & ~EHCI_PTR_BITS);
        if (next == start) {
            // Not found?!  Exit without freeing.
            warn_internalerror();
            return;
        }
        if (next == &pipe->qh) {
            pos->next = next->next;
            ehci_waittick(cntl);
            free(pipe);
            return;
        }
        pos = next;
    }
}

struct usb_pipe *
ehci_alloc_control_pipe(struct usb_pipe *dummy)
{
    if (! CONFIG_USB_EHCI)
        return NULL;
    struct usb_ehci_s *cntl = container_of(
        dummy->cntl, struct usb_ehci_s, usb);
    dprintf(7, "ehci_alloc_control_pipe %p\n", &cntl->usb);

    // Allocate a queue head.
    struct ehci_pipe *pipe = memalign_tmphigh(EHCI_QH_ALIGN, sizeof(*pipe));
    if (!pipe) {
        warn_noalloc();
        return NULL;
    }
    memset(pipe, 0, sizeof(*pipe));
    memcpy(&pipe->pipe, dummy, sizeof(pipe->pipe));
    pipe->qh.qtd_next = pipe->qh.alt_next = EHCI_PTR_TERM;
    pipe->qh.token = QTD_STS_HALT;

    // Add queue head to controller list.
    struct ehci_qh *async_qh = cntl->async_qh;
    pipe->qh.next = async_qh->next;
    barrier();
    async_qh->next = (u32)&pipe->qh | EHCI_PTR_QH;
    return &pipe->pipe;
}

static int
fillTDbuffer(struct ehci_qtd *td, u16 maxpacket, const void *buf, int bytes)
{
    u32 dest = (u32)buf;
    u32 *pos = td->buf;
    while (bytes) {
        if (pos >= &td->buf[ARRAY_SIZE(td->buf)])
            // More data than can transfer in a single qtd - only use
            // full packets to prevent a babble error.
            return ALIGN_DOWN(dest - (u32)buf, maxpacket);
        u32 count = bytes;
        u32 max = 0x1000 - (dest & 0xfff);
        if (count > max)
            count = max;
        *pos = dest;
        bytes -= count;
        dest += count;
        pos++;
    }
    return dest - (u32)buf;
}

int
ehci_control(struct usb_pipe *p, int dir, const void *cmd, int cmdsize
             , void *data, int datasize)
{
    ASSERT32FLAT();
    if (! CONFIG_USB_EHCI)
        return -1;
    dprintf(5, "ehci_control %p\n", p);
    if (datasize > 4*4096 || cmdsize > 4*4096) {
        // XXX - should support larger sizes.
        warn_noalloc();
        return -1;
    }
    struct ehci_pipe *pipe = container_of(p, struct ehci_pipe, pipe);
    struct usb_ehci_s *cntl = container_of(
        pipe->pipe.cntl, struct usb_ehci_s, usb);

    u16 maxpacket = pipe->pipe.maxpacket;
    int speed = pipe->pipe.speed;

    // Setup fields in qh
    pipe->qh.info1 = (
        (1 << QH_MULT_SHIFT) | (speed != USB_HIGHSPEED ? QH_CONTROL : 0)
        | (maxpacket << QH_MAXPACKET_SHIFT)
        | QH_TOGGLECONTROL
        | (speed << QH_SPEED_SHIFT)
        | (pipe->pipe.ep << QH_EP_SHIFT)
        | (pipe->pipe.devaddr << QH_DEVADDR_SHIFT));
    pipe->qh.info2 = ((1 << QH_MULT_SHIFT)
                      | (pipe->pipe.tt_port << QH_HUBPORT_SHIFT)
                      | (pipe->pipe.tt_devaddr << QH_HUBADDR_SHIFT));

    // Setup transfer descriptors
    struct ehci_qtd *tds = memalign_tmphigh(EHCI_QTD_ALIGN, sizeof(*tds) * 3);
    if (!tds) {
        warn_noalloc();
        return -1;
    }
    memset(tds, 0, sizeof(*tds) * 3);
    struct ehci_qtd *td = tds;

    td->qtd_next = (u32)&td[1];
    td->alt_next = EHCI_PTR_TERM;
    td->token = (ehci_explen(cmdsize) | QTD_STS_ACTIVE
                 | QTD_PID_SETUP | ehci_maxerr(3));
    fillTDbuffer(td, maxpacket, cmd, cmdsize);
    td++;

    if (datasize) {
        td->qtd_next = (u32)&td[1];
        td->alt_next = EHCI_PTR_TERM;
        td->token = (QTD_TOGGLE | ehci_explen(datasize) | QTD_STS_ACTIVE
                     | (dir ? QTD_PID_IN : QTD_PID_OUT) | ehci_maxerr(3));
        fillTDbuffer(td, maxpacket, data, datasize);
        td++;
    }

    td->qtd_next = EHCI_PTR_TERM;
    td->alt_next = EHCI_PTR_TERM;
    td->token = (QTD_TOGGLE | QTD_STS_ACTIVE
                 | (dir ? QTD_PID_OUT : QTD_PID_IN) | ehci_maxerr(3));

    // Transfer data
    barrier();
    pipe->qh.qtd_next = (u32)tds;
    barrier();
    pipe->qh.token = 0;
    int ret = ehci_wait_qh(cntl, &pipe->qh);
    pipe->qh.token = QTD_STS_HALT;
    if (ret) {
        pipe->qh.qtd_next = pipe->qh.alt_next = EHCI_PTR_TERM;
        // XXX - halt qh?
        ehci_waittick(cntl);
    }
    free(tds);
    return ret;
}

struct usb_pipe *
ehci_alloc_bulk_pipe(struct usb_pipe *dummy)
{
    // XXX - this func is same as alloc_control except for malloc_low
    if (! CONFIG_USB_EHCI)
        return NULL;
    struct usb_ehci_s *cntl = container_of(
        dummy->cntl, struct usb_ehci_s, usb);
    dprintf(7, "ehci_alloc_bulk_pipe %p\n", &cntl->usb);

    // Allocate a queue head.
    struct ehci_pipe *pipe = memalign_low(EHCI_QH_ALIGN, sizeof(*pipe));
    if (!pipe) {
        warn_noalloc();
        return NULL;
    }
    memset(pipe, 0, sizeof(*pipe));
    memcpy(&pipe->pipe, dummy, sizeof(pipe->pipe));
    pipe->qh.qtd_next = pipe->qh.alt_next = EHCI_PTR_TERM;
    pipe->qh.token = QTD_STS_HALT;

    // Add queue head to controller list.
    struct ehci_qh *async_qh = cntl->async_qh;
    pipe->qh.next = async_qh->next;
    barrier();
    async_qh->next = (u32)&pipe->qh | EHCI_PTR_QH;
    return &pipe->pipe;
}

static int
ehci_wait_td(struct ehci_qtd *td)
{
    u64 end = calc_future_tsc(5000); // XXX - lookup real time.
    u32 status;
    for (;;) {
        status = td->token;
        if (!(status & QTD_STS_ACTIVE))
            break;
        if (check_tsc(end)) {
            warn_timeout();
            return -1;
        }
        yield();
    }
    if (status & QTD_STS_HALT) {
        dprintf(1, "ehci_wait_td error - status=%x\n", status);
        return -2;
    }
    return 0;
}

#define STACKQTDS 4

int
ehci_send_bulk(struct usb_pipe *p, int dir, void *data, int datasize)
{
    if (! CONFIG_USB_EHCI)
        return -1;
    struct ehci_pipe *pipe = container_of(p, struct ehci_pipe, pipe);
    dprintf(7, "ehci_send_bulk qh=%p dir=%d data=%p size=%d\n"
            , &pipe->qh, dir, data, datasize);

    // Allocate 4 tds on stack (16byte aligned)
    u8 tdsbuf[sizeof(struct ehci_qtd) * STACKQTDS + EHCI_QTD_ALIGN - 1];
    struct ehci_qtd *tds = (void*)ALIGN((u32)tdsbuf, EHCI_QTD_ALIGN);
    memset(tds, 0, sizeof(*tds) * STACKQTDS);

    // Setup fields in qh
    u16 maxpacket = GET_FLATPTR(pipe->pipe.maxpacket);
    SET_FLATPTR(pipe->qh.info1
                , ((1 << QH_MULT_SHIFT)
                   | (maxpacket << QH_MAXPACKET_SHIFT)
                   | (GET_FLATPTR(pipe->pipe.speed) << QH_SPEED_SHIFT)
                   | (GET_FLATPTR(pipe->pipe.ep) << QH_EP_SHIFT)
                   | (GET_FLATPTR(pipe->pipe.devaddr) << QH_DEVADDR_SHIFT)));
    SET_FLATPTR(pipe->qh.info2
                , ((1 << QH_MULT_SHIFT)
                   | (GET_FLATPTR(pipe->pipe.tt_port) << QH_HUBPORT_SHIFT)
                   | (GET_FLATPTR(pipe->pipe.tt_devaddr) << QH_HUBADDR_SHIFT)));
    barrier();
    SET_FLATPTR(pipe->qh.qtd_next, (u32)MAKE_FLATPTR(GET_SEG(SS), tds));
    barrier();
    SET_FLATPTR(pipe->qh.token, GET_FLATPTR(pipe->qh.token) & QTD_TOGGLE);

    int tdpos = 0;
    while (datasize) {
        struct ehci_qtd *td = &tds[tdpos++ % STACKQTDS];
        int ret = ehci_wait_td(td);
        if (ret)
            goto fail;

        struct ehci_qtd *nexttd_fl = MAKE_FLATPTR(GET_SEG(SS)
                                                 , &tds[tdpos % STACKQTDS]);

        int transfer = fillTDbuffer(td, maxpacket, data, datasize);
        td->qtd_next = (transfer==datasize ? EHCI_PTR_TERM : (u32)nexttd_fl);
        td->alt_next = EHCI_PTR_TERM;
        barrier();
        td->token = (ehci_explen(transfer) | QTD_STS_ACTIVE
                     | (dir ? QTD_PID_IN : QTD_PID_OUT) | ehci_maxerr(3));

        data += transfer;
        datasize -= transfer;
    }
    int i;
    for (i=0; i<STACKQTDS; i++) {
        struct ehci_qtd *td = &tds[tdpos++ % STACKQTDS];
        int ret = ehci_wait_td(td);
        if (ret)
            goto fail;
    }

    return 0;
fail:
    dprintf(1, "ehci_send_bulk failed\n");
    SET_FLATPTR(pipe->qh.qtd_next, EHCI_PTR_TERM);
    SET_FLATPTR(pipe->qh.alt_next, EHCI_PTR_TERM);
    // XXX - halt qh?
    struct usb_ehci_s *cntl = container_of(
        GET_FLATPTR(pipe->pipe.cntl), struct usb_ehci_s, usb);
    ehci_waittick(cntl);
    return -1;
}

struct usb_pipe *
ehci_alloc_intr_pipe(struct usb_pipe *dummy, int frameexp)
{
    if (! CONFIG_USB_EHCI)
        return NULL;
    struct usb_ehci_s *cntl = container_of(
        dummy->cntl, struct usb_ehci_s, usb);
    dprintf(7, "ehci_alloc_intr_pipe %p %d\n", &cntl->usb, frameexp);

    if (frameexp > 10)
        frameexp = 10;
    int maxpacket = dummy->maxpacket;
    // Determine number of entries needed for 2 timer ticks.
    int ms = 1<<frameexp;
    int count = DIV_ROUND_UP(PIT_TICK_INTERVAL * 1000 * 2, PIT_TICK_RATE * ms);
    struct ehci_pipe *pipe = memalign_low(EHCI_QH_ALIGN, sizeof(*pipe));
    struct ehci_qtd *tds = memalign_low(EHCI_QTD_ALIGN, sizeof(*tds) * count);
    void *data = malloc_low(maxpacket * count);
    if (!pipe || !tds || !data) {
        warn_noalloc();
        goto fail;
    }
    memset(pipe, 0, sizeof(*pipe));
    memcpy(&pipe->pipe, dummy, sizeof(pipe->pipe));
    pipe->next_td = pipe->tds = tds;
    pipe->data = data;

    pipe->qh.info1 = (
        (1 << QH_MULT_SHIFT)
        | (maxpacket << QH_MAXPACKET_SHIFT)
        | (pipe->pipe.speed << QH_SPEED_SHIFT)
        | (pipe->pipe.ep << QH_EP_SHIFT)
        | (pipe->pipe.devaddr << QH_DEVADDR_SHIFT));
    pipe->qh.info2 = ((1 << QH_MULT_SHIFT)
                      | (pipe->pipe.tt_port << QH_HUBPORT_SHIFT)
                      | (pipe->pipe.tt_devaddr << QH_HUBADDR_SHIFT)
                      | (0x01 << QH_SMASK_SHIFT)
                      | (0x1c << QH_CMASK_SHIFT));
    pipe->qh.qtd_next = (u32)tds;

    int i;
    for (i=0; i<count; i++) {
        struct ehci_qtd *td = &tds[i];
        td->qtd_next = (i==count-1 ? (u32)tds : (u32)&td[1]);
        td->alt_next = EHCI_PTR_TERM;
        td->token = (ehci_explen(maxpacket) | QTD_STS_ACTIVE
                     | QTD_PID_IN | ehci_maxerr(3));
        td->buf[0] = (u32)data + maxpacket * i;
    }

    // Add to interrupt schedule.
    struct ehci_framelist *fl = (void*)readl(&cntl->regs->periodiclistbase);
    if (frameexp == 0) {
        // Add to existing interrupt entry.
        struct ehci_qh *intr_qh = (void*)(fl->links[0] & ~EHCI_PTR_BITS);
        pipe->qh.next = intr_qh->next;
        barrier();
        intr_qh->next = (u32)&pipe->qh | EHCI_PTR_QH;
    } else {
        int startpos = 1<<(frameexp-1);
        pipe->qh.next = fl->links[startpos];
        barrier();
        for (i=startpos; i<ARRAY_SIZE(fl->links); i+=ms)
            fl->links[i] = (u32)&pipe->qh | EHCI_PTR_QH;
    }

    return &pipe->pipe;
fail:
    free(pipe);
    free(tds);
    free(data);
    return NULL;
}

int
ehci_poll_intr(struct usb_pipe *p, void *data)
{
    ASSERT16();
    if (! CONFIG_USB_EHCI)
        return -1;
    struct ehci_pipe *pipe = container_of(p, struct ehci_pipe, pipe);
    struct ehci_qtd *td = GET_FLATPTR(pipe->next_td);
    u32 token = GET_FLATPTR(td->token);
    if (token & QTD_STS_ACTIVE)
        // No intrs found.
        return -1;
    // XXX - check for errors.

    // Copy data.
    int maxpacket = GET_FLATPTR(pipe->pipe.maxpacket);
    int pos = td - GET_FLATPTR(pipe->tds);
    void *tddata = GET_FLATPTR(pipe->data) + maxpacket * pos;
    memcpy_far(GET_SEG(SS), data
               , FLATPTR_TO_SEG(tddata), (void*)FLATPTR_TO_OFFSET(tddata)
               , maxpacket);

    // Reenable this td.
    struct ehci_qtd *next = (void*)(GET_FLATPTR(td->qtd_next) & ~EHCI_PTR_BITS);
    SET_FLATPTR(pipe->next_td, next);
    SET_FLATPTR(td->buf[0], (u32)tddata);
    barrier();
    SET_FLATPTR(td->token, (ehci_explen(maxpacket) | QTD_STS_ACTIVE
                            | QTD_PID_IN | ehci_maxerr(3)));

    return 0;
}
