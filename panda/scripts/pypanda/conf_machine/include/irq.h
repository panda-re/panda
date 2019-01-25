typedef struct IRQState *qemu_irq;

typedef void (*qemu_irq_handler)(void *opaque, int n, int level);

void qemu_set_irq(qemu_irq irq, int level);

static inline void qemu_irq_raise(qemu_irq irq)
{
    qemu_set_irq(irq, 1);
}

static inline void qemu_irq_lower(qemu_irq irq)
{
    qemu_set_irq(irq, 0);
}

static inline void qemu_irq_pulse(qemu_irq irq)
{
    qemu_set_irq(irq, 1);
    qemu_set_irq(irq, 0);
}




qemu_irq *qemu_allocate_irqs(qemu_irq_handler handler, void *opaque, int n);





qemu_irq qemu_allocate_irq(qemu_irq_handler handler, void *opaque, int n);




qemu_irq *qemu_extend_irqs(qemu_irq *old, int n_old, qemu_irq_handler handler,
                                void *opaque, int n);

void qemu_free_irqs(qemu_irq *s, int n);
void qemu_free_irq(qemu_irq irq);


qemu_irq qemu_irq_invert(qemu_irq irq);


qemu_irq qemu_irq_split(qemu_irq irq1, qemu_irq irq2);




qemu_irq *qemu_irq_proxy(qemu_irq **target, int n);



void qemu_irq_intercept_in(qemu_irq *gpio_in, qemu_irq_handler handler, int n);
