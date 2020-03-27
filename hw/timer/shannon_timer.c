/*
 * Implementation of timer for Samsungs Shannon baseband.
 * This may not be accurate, as it is the result of reverse engineering.
 * Implementation is loosely based on arm_timer.c
 */


#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qemu/timer.h"
#include "qemu-common.h"
#include "hw/qdev.h"
#include "hw/ptimer.h"
#include "qemu/main-loop.h"
#include "qemu/log.h"

#include "hw/avatar/configurable_machine.h"
#include "hw/cpu/a9mpcore.h"

#define SH_TIMER_DEBUG_GATE 0

#define DPRINTF(fmt, ...) do {                                          \
        if (SH_TIMER_DEBUG_GATE) {                                           \
            fprintf(stderr, "%s: " fmt, __func__, ## __VA_ARGS__);      \
            fflush(stderr);                                             \
        }                                                               \
    } while (0)

#define TYPE_SHANNON_TIMER "shannon_timer"
#define SHANNON_TIMER(obj) \
    OBJECT_CHECK(shannon_timer_state, (obj), TYPE_SHANNON_TIMER)


#define STIMER_CTRL_ENABLE            (1 << 0)
#define STIMER_CTRL_PERIODIC          (1 << 1)

typedef struct {
    SysBusDevice parent_obj;
    ptimer_state *timer;
    uint32_t control;
    uint32_t limit;
    uint32_t freq;
    uint32_t int_level;
    uint32_t irq_num;
    MemoryRegion iomem;
    qemu_irq irq;
} shannon_timer_state;



static void shannon_timer_set_irq(void *opaque, int irq, int level)
{
    shannon_timer_state *s = (shannon_timer_state *)opaque;

    DPRINTF("Raising IRQ");
    qemu_set_irq(s->irq, s->int_level);
}


static void shannon_timer_update(shannon_timer_state *s)
{
    A9MPPrivState *gic = (A9MPPrivState *) configurable_get_peripheral("gic");
    /* Update interrupts.  */
    DPRINTF("SetIRQLevel %d: %d\n", s->irq_num, s->int_level);
    configurable_a9mp_inject_irq(gic, s->irq_num-32, s->int_level);
}




static uint64_t shannon_timer_read(void *opaque, hwaddr offset,
                             uint32_t value)
{
    shannon_timer_state *s = (shannon_timer_state *)opaque;
    uint64_t ret;

    switch (offset) {
    case 0x00: /* TimerLoad */
        ret = s->limit;
        break;
    case 0x04: /* TimerControl */
        ret = s->control;
        break;
    case 0x34: /* TimerValue */
        ret = ptimer_get_count(s->timer);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Bad offset %x\n", __func__, (int)offset);
        ret = 0;
    }
    DPRINTF("Read at 0x%lx (%d): %lx\n", offset, s->irq_num, ret);
    return ret;
}

static void shannon_timer_write(void *opaque, hwaddr offset,
                                 uint64_t value, unsigned size)
{
    shannon_timer_state *s = (shannon_timer_state *)opaque;
    DPRINTF("Write at 0x%lx: 0x%lx (%d)\n", offset, value, s->irq_num);
    int freq;

    
    switch (offset) {
    case 0x00: /* TimerLoad */
        s->limit = value;
        ptimer_set_limit(s->timer, s->limit, 1);
        break;
    case 0x04: /* TimerControl */
        if (s->control & STIMER_CTRL_ENABLE) {
            /* Pause the timer if it is running.  This may cause some
               inaccuracy dure to rounding, but avoids a whole lot of other
               messyness.  */
            ptimer_stop(s->timer);
        }
        s->control = value;
        freq = s->freq;

        ptimer_set_limit(s->timer, s->limit, 1);
        ptimer_set_freq(s->timer, freq);

        if (s->control & STIMER_CTRL_ENABLE) {
            /* Restart the timer if still enabled.  */
            ptimer_run(s->timer, (s->control & STIMER_CTRL_PERIODIC) == 0);
        }
        break;
    case 0x10:
        shannon_timer_update(s); //disable irq if necessary
        break;
    case 0x14: /* TIM_IRQ_LEVEL */
        s->int_level = value;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Bad offset %x\n", __func__, (int)offset);
    }
}

static void shannon_timer_tick(void *opaque)
{
    shannon_timer_state *s = (shannon_timer_state *)opaque;
    s->int_level = 1;
    shannon_timer_update(s);
}

static const VMStateDescription vmstate_shannon_timer = {
    .name = TYPE_SHANNON_TIMER,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(control, shannon_timer_state),
        VMSTATE_UINT32(limit, shannon_timer_state),
        VMSTATE_UINT32(freq, shannon_timer_state),
        VMSTATE_UINT32(int_level, shannon_timer_state),
        VMSTATE_UINT32(irq_num, shannon_timer_state),
        VMSTATE_PTIMER(timer, shannon_timer_state),
        VMSTATE_END_OF_LIST()
    }
};

static const MemoryRegionOps shannon_timer_ops = {
    .read = shannon_timer_read,
    .write = shannon_timer_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void shannon_timer_init(Object *obj)
{
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    shannon_timer_state *s = SHANNON_TIMER(obj);
    QEMUBH *bh;

    s->control = 0xffffffff;
    s->limit = 0;
    s->int_level = 0;

    bh = qemu_bh_new(shannon_timer_tick, s);
    s->timer = ptimer_init(bh, PTIMER_POLICY_DEFAULT);

    memory_region_init_io(&s->iomem, OBJECT(s), &shannon_timer_ops, s,
            TYPE_SHANNON_TIMER, 0xf0);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
    s->irq = qemu_allocate_irq(shannon_timer_set_irq, s, s->irq_num);
}


static Property shannon_timer_properties[] = {
    DEFINE_PROP_UINT32("irq_num", shannon_timer_state, irq_num, 35),
    DEFINE_PROP_UINT32("freq", shannon_timer_state, freq, 1000000ll),
    DEFINE_PROP_END_OF_LIST(),
};

static void shannon_timer_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *k = DEVICE_CLASS(klass);

    k->props = shannon_timer_properties;
    k->vmsd = &vmstate_shannon_timer;
}

static const TypeInfo shannon_timer_info = {
    .name = TYPE_SHANNON_TIMER,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_init = shannon_timer_init,
    .instance_size = sizeof(shannon_timer_state),
    .class_init =  shannon_timer_class_init,
};

static void shannon_timer_register_types(void)
{
    type_register_static(&shannon_timer_info);
}

type_init(shannon_timer_register_types)
