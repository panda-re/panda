/** @brief Magic code to use in cpuid hypercall. */
#define HC_MAGIC 0x10adc0d3

typedef enum {
    HC_NOOP = 0,
    HC_START,               /* start new action */
    HC_STOP,                /* stop action */
    HC_READ,                /* read buffer from hypervisor */
    HC_WRITE,               /* write buffer TO hypervisor*/
    HC_ERROR,               /* report error to hypervisor*/
    HC_CONDITIONAL_OP,      /* ask the hypervisor if op should be completed*/
    HC_NEXT_STATE_MACHINE,  /* ask the hypervisor manager to move to the next
                            state machine*/
} hc_cmd;

