/*
 * QEMU PowerPC pSeries Logical Partition (aka sPAPR) hardware System Emulator
 *
 * PAPR Virtualized Interrupt System, aka ICS/ICP aka xics
 *
 * Copyright (c) 2010,2011 David Gibson, IBM Corporation.
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
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/hw.h"
#include "trace.h"
#include "qemu/timer.h"
#include "hw/ppc/xics.h"
#include "qemu/error-report.h"
#include "qapi/visitor.h"
#include "monitor/monitor.h"
#include "hw/intc/intc.h"

int xics_get_cpu_index_by_dt_id(int cpu_dt_id)
{
    PowerPCCPU *cpu = ppc_get_vcpu_by_dt_id(cpu_dt_id);

    if (cpu) {
        return cpu->parent_obj.cpu_index;
    }

    return -1;
}

void xics_cpu_destroy(XICSFabric *xi, PowerPCCPU *cpu)
{
    CPUState *cs = CPU(cpu);
    ICPState *icp = xics_icp_get(xi, cs->cpu_index);

    assert(icp);
    assert(cs == icp->cs);

    icp->output = NULL;
    icp->cs = NULL;
}

void xics_cpu_setup(XICSFabric *xi, PowerPCCPU *cpu)
{
    CPUState *cs = CPU(cpu);
    CPUPPCState *env = &cpu->env;
    ICPState *icp = xics_icp_get(xi, cs->cpu_index);
    ICPStateClass *icpc;

    assert(icp);

    icp->cs = cs;

    icpc = ICP_GET_CLASS(icp);
    if (icpc->cpu_setup) {
        icpc->cpu_setup(icp, cpu);
    }

    switch (PPC_INPUT(env)) {
    case PPC_FLAGS_INPUT_POWER7:
        icp->output = env->irq_inputs[POWER7_INPUT_INT];
        break;

    case PPC_FLAGS_INPUT_970:
        icp->output = env->irq_inputs[PPC970_INPUT_INT];
        break;

    default:
        error_report("XICS interrupt controller does not support this CPU "
                     "bus model");
        abort();
    }
}

void icp_pic_print_info(ICPState *icp, Monitor *mon)
{
    int cpu_index = icp->cs ? icp->cs->cpu_index : -1;

    if (!icp->output) {
        return;
    }
    monitor_printf(mon, "CPU %d XIRR=%08x (%p) PP=%02x MFRR=%02x\n",
                   cpu_index, icp->xirr, icp->xirr_owner,
                   icp->pending_priority, icp->mfrr);
}

void ics_pic_print_info(ICSState *ics, Monitor *mon)
{
    uint32_t i;

    monitor_printf(mon, "ICS %4x..%4x %p\n",
                   ics->offset, ics->offset + ics->nr_irqs - 1, ics);

    if (!ics->irqs) {
        return;
    }

    for (i = 0; i < ics->nr_irqs; i++) {
        ICSIRQState *irq = ics->irqs + i;

        if (!(irq->flags & XICS_FLAGS_IRQ_MASK)) {
            continue;
        }
        monitor_printf(mon, "  %4x %s %02x %02x\n",
                       ics->offset + i,
                       (irq->flags & XICS_FLAGS_IRQ_LSI) ?
                       "LSI" : "MSI",
                       irq->priority, irq->status);
    }
}

/*
 * ICP: Presentation layer
 */

#define XISR_MASK  0x00ffffff
#define CPPR_MASK  0xff000000

#define XISR(icp)   (((icp)->xirr) & XISR_MASK)
#define CPPR(icp)   (((icp)->xirr) >> 24)

static void ics_reject(ICSState *ics, uint32_t nr)
{
    ICSStateClass *k = ICS_BASE_GET_CLASS(ics);

    if (k->reject) {
        k->reject(ics, nr);
    }
}

void ics_resend(ICSState *ics)
{
    ICSStateClass *k = ICS_BASE_GET_CLASS(ics);

    if (k->resend) {
        k->resend(ics);
    }
}

static void ics_eoi(ICSState *ics, int nr)
{
    ICSStateClass *k = ICS_BASE_GET_CLASS(ics);

    if (k->eoi) {
        k->eoi(ics, nr);
    }
}

static void icp_check_ipi(ICPState *icp)
{
    if (XISR(icp) && (icp->pending_priority <= icp->mfrr)) {
        return;
    }

    trace_xics_icp_check_ipi(icp->cs->cpu_index, icp->mfrr);

    if (XISR(icp) && icp->xirr_owner) {
        ics_reject(icp->xirr_owner, XISR(icp));
    }

    icp->xirr = (icp->xirr & ~XISR_MASK) | XICS_IPI;
    icp->pending_priority = icp->mfrr;
    icp->xirr_owner = NULL;
    qemu_irq_raise(icp->output);
}

void icp_resend(ICPState *icp)
{
    XICSFabric *xi = icp->xics;
    XICSFabricClass *xic = XICS_FABRIC_GET_CLASS(xi);

    if (icp->mfrr < CPPR(icp)) {
        icp_check_ipi(icp);
    }

    xic->ics_resend(xi);
}

void icp_set_cppr(ICPState *icp, uint8_t cppr)
{
    uint8_t old_cppr;
    uint32_t old_xisr;

    old_cppr = CPPR(icp);
    icp->xirr = (icp->xirr & ~CPPR_MASK) | (cppr << 24);

    if (cppr < old_cppr) {
        if (XISR(icp) && (cppr <= icp->pending_priority)) {
            old_xisr = XISR(icp);
            icp->xirr &= ~XISR_MASK; /* Clear XISR */
            icp->pending_priority = 0xff;
            qemu_irq_lower(icp->output);
            if (icp->xirr_owner) {
                ics_reject(icp->xirr_owner, old_xisr);
                icp->xirr_owner = NULL;
            }
        }
    } else {
        if (!XISR(icp)) {
            icp_resend(icp);
        }
    }
}

void icp_set_mfrr(ICPState *icp, uint8_t mfrr)
{
    icp->mfrr = mfrr;
    if (mfrr < CPPR(icp)) {
        icp_check_ipi(icp);
    }
}

uint32_t icp_accept(ICPState *icp)
{
    uint32_t xirr = icp->xirr;

    qemu_irq_lower(icp->output);
    icp->xirr = icp->pending_priority << 24;
    icp->pending_priority = 0xff;
    icp->xirr_owner = NULL;

    trace_xics_icp_accept(xirr, icp->xirr);

    return xirr;
}

uint32_t icp_ipoll(ICPState *icp, uint32_t *mfrr)
{
    if (mfrr) {
        *mfrr = icp->mfrr;
    }
    return icp->xirr;
}

void icp_eoi(ICPState *icp, uint32_t xirr)
{
    XICSFabric *xi = icp->xics;
    XICSFabricClass *xic = XICS_FABRIC_GET_CLASS(xi);
    ICSState *ics;
    uint32_t irq;

    /* Send EOI -> ICS */
    icp->xirr = (icp->xirr & ~CPPR_MASK) | (xirr & CPPR_MASK);
    trace_xics_icp_eoi(icp->cs->cpu_index, xirr, icp->xirr);
    irq = xirr & XISR_MASK;

    ics = xic->ics_get(xi, irq);
    if (ics) {
        ics_eoi(ics, irq);
    }
    if (!XISR(icp)) {
        icp_resend(icp);
    }
}

static void icp_irq(ICSState *ics, int server, int nr, uint8_t priority)
{
    ICPState *icp = xics_icp_get(ics->xics, server);

    trace_xics_icp_irq(server, nr, priority);

    if ((priority >= CPPR(icp))
        || (XISR(icp) && (icp->pending_priority <= priority))) {
        ics_reject(ics, nr);
    } else {
        if (XISR(icp) && icp->xirr_owner) {
            ics_reject(icp->xirr_owner, XISR(icp));
            icp->xirr_owner = NULL;
        }
        icp->xirr = (icp->xirr & ~XISR_MASK) | (nr & XISR_MASK);
        icp->xirr_owner = ics;
        icp->pending_priority = priority;
        trace_xics_icp_raise(icp->xirr, icp->pending_priority);
        qemu_irq_raise(icp->output);
    }
}

static void icp_dispatch_pre_save(void *opaque)
{
    ICPState *icp = opaque;
    ICPStateClass *info = ICP_GET_CLASS(icp);

    if (info->pre_save) {
        info->pre_save(icp);
    }
}

static int icp_dispatch_post_load(void *opaque, int version_id)
{
    ICPState *icp = opaque;
    ICPStateClass *info = ICP_GET_CLASS(icp);

    if (info->post_load) {
        return info->post_load(icp, version_id);
    }

    return 0;
}

static const VMStateDescription vmstate_icp_server = {
    .name = "icp/server",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = icp_dispatch_pre_save,
    .post_load = icp_dispatch_post_load,
    .fields = (VMStateField[]) {
        /* Sanity check */
        VMSTATE_UINT32(xirr, ICPState),
        VMSTATE_UINT8(pending_priority, ICPState),
        VMSTATE_UINT8(mfrr, ICPState),
        VMSTATE_END_OF_LIST()
    },
};

static void icp_reset(void *dev)
{
    ICPState *icp = ICP(dev);

    icp->xirr = 0;
    icp->pending_priority = 0xff;
    icp->mfrr = 0xff;

    /* Make all outputs are deasserted */
    qemu_set_irq(icp->output, 0);
}

static void icp_realize(DeviceState *dev, Error **errp)
{
    ICPState *icp = ICP(dev);
    Object *obj;
    Error *err = NULL;

    obj = object_property_get_link(OBJECT(dev), "xics", &err);
    if (!obj) {
        error_setg(errp, "%s: required link 'xics' not found: %s",
                   __func__, error_get_pretty(err));
        return;
    }

    icp->xics = XICS_FABRIC(obj);

    qemu_register_reset(icp_reset, dev);
}


static void icp_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->vmsd = &vmstate_icp_server;
    dc->realize = icp_realize;
}

static const TypeInfo icp_info = {
    .name = TYPE_ICP,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(ICPState),
    .class_init = icp_class_init,
    .class_size = sizeof(ICPStateClass),
};

/*
 * ICS: Source layer
 */
static void ics_simple_resend_msi(ICSState *ics, int srcno)
{
    ICSIRQState *irq = ics->irqs + srcno;

    /* FIXME: filter by server#? */
    if (irq->status & XICS_STATUS_REJECTED) {
        irq->status &= ~XICS_STATUS_REJECTED;
        if (irq->priority != 0xff) {
            icp_irq(ics, irq->server, srcno + ics->offset, irq->priority);
        }
    }
}

static void ics_simple_resend_lsi(ICSState *ics, int srcno)
{
    ICSIRQState *irq = ics->irqs + srcno;

    if ((irq->priority != 0xff)
        && (irq->status & XICS_STATUS_ASSERTED)
        && !(irq->status & XICS_STATUS_SENT)) {
        irq->status |= XICS_STATUS_SENT;
        icp_irq(ics, irq->server, srcno + ics->offset, irq->priority);
    }
}

static void ics_simple_set_irq_msi(ICSState *ics, int srcno, int val)
{
    ICSIRQState *irq = ics->irqs + srcno;

    trace_xics_ics_simple_set_irq_msi(srcno, srcno + ics->offset);

    if (val) {
        if (irq->priority == 0xff) {
            irq->status |= XICS_STATUS_MASKED_PENDING;
            trace_xics_masked_pending();
        } else  {
            icp_irq(ics, irq->server, srcno + ics->offset, irq->priority);
        }
    }
}

static void ics_simple_set_irq_lsi(ICSState *ics, int srcno, int val)
{
    ICSIRQState *irq = ics->irqs + srcno;

    trace_xics_ics_simple_set_irq_lsi(srcno, srcno + ics->offset);
    if (val) {
        irq->status |= XICS_STATUS_ASSERTED;
    } else {
        irq->status &= ~XICS_STATUS_ASSERTED;
    }
    ics_simple_resend_lsi(ics, srcno);
}

static void ics_simple_set_irq(void *opaque, int srcno, int val)
{
    ICSState *ics = (ICSState *)opaque;

    if (ics->irqs[srcno].flags & XICS_FLAGS_IRQ_LSI) {
        ics_simple_set_irq_lsi(ics, srcno, val);
    } else {
        ics_simple_set_irq_msi(ics, srcno, val);
    }
}

static void ics_simple_write_xive_msi(ICSState *ics, int srcno)
{
    ICSIRQState *irq = ics->irqs + srcno;

    if (!(irq->status & XICS_STATUS_MASKED_PENDING)
        || (irq->priority == 0xff)) {
        return;
    }

    irq->status &= ~XICS_STATUS_MASKED_PENDING;
    icp_irq(ics, irq->server, srcno + ics->offset, irq->priority);
}

static void ics_simple_write_xive_lsi(ICSState *ics, int srcno)
{
    ics_simple_resend_lsi(ics, srcno);
}

void ics_simple_write_xive(ICSState *ics, int srcno, int server,
                           uint8_t priority, uint8_t saved_priority)
{
    ICSIRQState *irq = ics->irqs + srcno;

    irq->server = server;
    irq->priority = priority;
    irq->saved_priority = saved_priority;

    trace_xics_ics_simple_write_xive(ics->offset + srcno, srcno, server,
                                     priority);

    if (ics->irqs[srcno].flags & XICS_FLAGS_IRQ_LSI) {
        ics_simple_write_xive_lsi(ics, srcno);
    } else {
        ics_simple_write_xive_msi(ics, srcno);
    }
}

static void ics_simple_reject(ICSState *ics, uint32_t nr)
{
    ICSIRQState *irq = ics->irqs + nr - ics->offset;

    trace_xics_ics_simple_reject(nr, nr - ics->offset);
    if (irq->flags & XICS_FLAGS_IRQ_MSI) {
        irq->status |= XICS_STATUS_REJECTED;
    } else if (irq->flags & XICS_FLAGS_IRQ_LSI) {
        irq->status &= ~XICS_STATUS_SENT;
    }
}

static void ics_simple_resend(ICSState *ics)
{
    int i;

    for (i = 0; i < ics->nr_irqs; i++) {
        /* FIXME: filter by server#? */
        if (ics->irqs[i].flags & XICS_FLAGS_IRQ_LSI) {
            ics_simple_resend_lsi(ics, i);
        } else {
            ics_simple_resend_msi(ics, i);
        }
    }
}

static void ics_simple_eoi(ICSState *ics, uint32_t nr)
{
    int srcno = nr - ics->offset;
    ICSIRQState *irq = ics->irqs + srcno;

    trace_xics_ics_simple_eoi(nr);

    if (ics->irqs[srcno].flags & XICS_FLAGS_IRQ_LSI) {
        irq->status &= ~XICS_STATUS_SENT;
    }
}

static void ics_simple_reset(void *dev)
{
    ICSState *ics = ICS_SIMPLE(dev);
    int i;
    uint8_t flags[ics->nr_irqs];

    for (i = 0; i < ics->nr_irqs; i++) {
        flags[i] = ics->irqs[i].flags;
    }

    memset(ics->irqs, 0, sizeof(ICSIRQState) * ics->nr_irqs);

    for (i = 0; i < ics->nr_irqs; i++) {
        ics->irqs[i].priority = 0xff;
        ics->irqs[i].saved_priority = 0xff;
        ics->irqs[i].flags = flags[i];
    }
}

static void ics_simple_dispatch_pre_save(void *opaque)
{
    ICSState *ics = opaque;
    ICSStateClass *info = ICS_BASE_GET_CLASS(ics);

    if (info->pre_save) {
        info->pre_save(ics);
    }
}

static int ics_simple_dispatch_post_load(void *opaque, int version_id)
{
    ICSState *ics = opaque;
    ICSStateClass *info = ICS_BASE_GET_CLASS(ics);

    if (info->post_load) {
        return info->post_load(ics, version_id);
    }

    return 0;
}

static const VMStateDescription vmstate_ics_simple_irq = {
    .name = "ics/irq",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(server, ICSIRQState),
        VMSTATE_UINT8(priority, ICSIRQState),
        VMSTATE_UINT8(saved_priority, ICSIRQState),
        VMSTATE_UINT8(status, ICSIRQState),
        VMSTATE_UINT8(flags, ICSIRQState),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_ics_simple = {
    .name = "ics",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = ics_simple_dispatch_pre_save,
    .post_load = ics_simple_dispatch_post_load,
    .fields = (VMStateField[]) {
        /* Sanity check */
        VMSTATE_UINT32_EQUAL(nr_irqs, ICSState),

        VMSTATE_STRUCT_VARRAY_POINTER_UINT32(irqs, ICSState, nr_irqs,
                                             vmstate_ics_simple_irq,
                                             ICSIRQState),
        VMSTATE_END_OF_LIST()
    },
};

static void ics_simple_initfn(Object *obj)
{
    ICSState *ics = ICS_SIMPLE(obj);

    ics->offset = XICS_IRQ_BASE;
}

static void ics_simple_realize(DeviceState *dev, Error **errp)
{
    ICSState *ics = ICS_SIMPLE(dev);

    if (!ics->nr_irqs) {
        error_setg(errp, "Number of interrupts needs to be greater 0");
        return;
    }
    ics->irqs = g_malloc0(ics->nr_irqs * sizeof(ICSIRQState));
    ics->qirqs = qemu_allocate_irqs(ics_simple_set_irq, ics, ics->nr_irqs);

    qemu_register_reset(ics_simple_reset, dev);
}

static Property ics_simple_properties[] = {
    DEFINE_PROP_UINT32("nr-irqs", ICSState, nr_irqs, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void ics_simple_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ICSStateClass *isc = ICS_BASE_CLASS(klass);

    isc->realize = ics_simple_realize;
    dc->props = ics_simple_properties;
    dc->vmsd = &vmstate_ics_simple;
    isc->reject = ics_simple_reject;
    isc->resend = ics_simple_resend;
    isc->eoi = ics_simple_eoi;
}

static const TypeInfo ics_simple_info = {
    .name = TYPE_ICS_SIMPLE,
    .parent = TYPE_ICS_BASE,
    .instance_size = sizeof(ICSState),
    .class_init = ics_simple_class_init,
    .class_size = sizeof(ICSStateClass),
    .instance_init = ics_simple_initfn,
};

static void ics_base_realize(DeviceState *dev, Error **errp)
{
    ICSStateClass *icsc = ICS_BASE_GET_CLASS(dev);
    ICSState *ics = ICS_BASE(dev);
    Object *obj;
    Error *err = NULL;

    obj = object_property_get_link(OBJECT(dev), "xics", &err);
    if (!obj) {
        error_setg(errp, "%s: required link 'xics' not found: %s",
                   __func__, error_get_pretty(err));
        return;
    }
    ics->xics = XICS_FABRIC(obj);


    if (icsc->realize) {
        icsc->realize(dev, errp);
    }
}

static void ics_base_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = ics_base_realize;
}

static const TypeInfo ics_base_info = {
    .name = TYPE_ICS_BASE,
    .parent = TYPE_DEVICE,
    .abstract = true,
    .instance_size = sizeof(ICSState),
    .class_init = ics_base_class_init,
    .class_size = sizeof(ICSStateClass),
};

static const TypeInfo xics_fabric_info = {
    .name = TYPE_XICS_FABRIC,
    .parent = TYPE_INTERFACE,
    .class_size = sizeof(XICSFabricClass),
};

/*
 * Exported functions
 */
qemu_irq xics_get_qirq(XICSFabric *xi, int irq)
{
    XICSFabricClass *xic = XICS_FABRIC_GET_CLASS(xi);
    ICSState *ics = xic->ics_get(xi, irq);

    if (ics) {
        return ics->qirqs[irq - ics->offset];
    }

    return NULL;
}

ICPState *xics_icp_get(XICSFabric *xi, int server)
{
    XICSFabricClass *xic = XICS_FABRIC_GET_CLASS(xi);

    return xic->icp_get(xi, server);
}

void ics_set_irq_type(ICSState *ics, int srcno, bool lsi)
{
    assert(!(ics->irqs[srcno].flags & XICS_FLAGS_IRQ_MASK));

    ics->irqs[srcno].flags |=
        lsi ? XICS_FLAGS_IRQ_LSI : XICS_FLAGS_IRQ_MSI;
}

static void xics_register_types(void)
{
    type_register_static(&ics_simple_info);
    type_register_static(&ics_base_info);
    type_register_static(&icp_info);
    type_register_static(&xics_fabric_info);
}

type_init(xics_register_types)
