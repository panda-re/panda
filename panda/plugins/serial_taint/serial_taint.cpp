/* PANDABEGINCOMMENT
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "taint2/taint2.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

#include "taint2/taint2_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
}

uint32_t input_label;
bool positional_labels;
uint32_t pos_current_label = 0;

int serial_receive(CPUState *cpu, uint64_t _fifo_addr, uint8_t value)
{
    target_ptr_t fifo_addr = (target_ptr_t)_fifo_addr;
    fprintf(stderr, "Applying taint labels to incoming serial port data.\n");
    fprintf(stderr, "  Address in IO Shadow = 0x" TARGET_PTR_FMT "\n", fifo_addr);
    fprintf(stderr, "  Value = 0x%X\n", value);

    taint2_enable_taint();
    uint32_t label = input_label;
    if (positional_labels) {
        label = pos_current_label++;
    }
    fprintf(stderr, "  Label = 0x%X\n", label);
    taint2_label_io(fifo_addr, label);

    return 0;
}

int serial_read(CPUState *cpu, uint64_t fifo_addr, uint32_t port_addr,
                uint8_t value)
{
    if (!taint2_enabled()) {
        // Taint hasn't yet been enabled, no need to copy taint between EAX
        // and IO buffer.
        return 0;
    }

#ifdef TARGET_I386
    // Copy taint from the IO shadow into the EAX register.
    taint2_labelset_io_iter(fifo_addr,
                            [](uint32_t elt, void *unused) {
                                taint2_label_reg_additive(R_EAX, 0, elt);
                                return 0;
                            },
                            NULL);
#endif
    return 0;
}

int serial_write(CPUState *cpu, uint64_t fifo_addr, uint32_t port_addr,
                 uint8_t value)
{
    if (!taint2_enabled()) {
        // During a write, if taint hasn't been enabled we don't need to do
        // anything.
        return 0;
    }

#ifdef TARGET_I386
    // During a write, propagate taint from the register shadow at EAX to IO
    // shadow.
    taint2_labelset_reg_iter(R_EAX, 0,
                             [](uint32_t label, void *p_fifo_addr) {
                                 taint2_label_io(*(uint64_t *)p_fifo_addr,
                                                 label);
                                 return 0;
                             },
                             &fifo_addr);
#endif

    return 0;
}

int serial_send(CPUState *cpu, uint64_t fifo_addr, uint8_t value)
{
    if (!taint2_enabled()) {
        // During a send, if taint hasn't been enabled we don't need to do
        // anything.
        return 0;
    }

    // If the panda log is enabled, we report taint there. Otherwise, just print
    // out a message when a tainted transmit occurs.
    if (pandalog) {
        Panda__SerialTx *tx = (Panda__SerialTx *)malloc(sizeof(*tx));
        *tx = PANDA__SERIAL_TX__INIT;
        tx->value = value;
        tx->n_labels = taint2_query_io(fifo_addr);
        tx->labels = (uint32_t *)malloc(sizeof(*tx->labels) * tx->n_labels);
        taint2_query_set_io(fifo_addr, tx->labels);
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.serial_tx = tx;
        pandalog_write_entry(&ple);
        free(tx->labels);
        free(tx);
    } else if (taint2_query_io(fifo_addr) > 0) {
        fprintf(stderr, "Tainted Serial TX (value=0x%X)\n", value);
    }
    return 0;
}

bool init_plugin(void *self)
{
    // Setup Taint 2
    panda_require("taint2");
    assert(init_taint2_api());

    // Parse plugin arguments.
    panda_arg_list *args = panda_get_args("serial_taint");
    input_label = panda_parse_uint32_opt(
        args, "input_label", 0xC0FFEE42,
        "the label to apply to incoming serial port data");
    positional_labels = panda_parse_bool_opt(args, "positional_labels",
                                             "enables positional labels");
    bool taint_input = !panda_parse_bool_opt(
        args, "disable_taint_input", "disable tainting of serial input");
    bool report_tainted_sends = !panda_parse_bool_opt(
        args, "disable_taint_reports", "disable reporting of tainted sends");

    panda_cb pcb;

    // Only need to register read and receive callbacks if we're tainting
    // incoming data.
    if (taint_input) {
        pcb.replay_serial_receive = serial_receive;
        panda_register_callback(self, PANDA_CB_REPLAY_SERIAL_RECEIVE, pcb);

        pcb.replay_serial_read = serial_read;
        panda_register_callback(self, PANDA_CB_REPLAY_SERIAL_READ, pcb);
    }

    // Only need to register write and send callbacks if we're reporting tainted
    // serial port output.
    if (report_tainted_sends) {
        pcb.replay_serial_write = serial_write;
        panda_register_callback(self, PANDA_CB_REPLAY_SERIAL_WRITE, pcb);

        pcb.replay_serial_send = serial_send;
        panda_register_callback(self, PANDA_CB_REPLAY_SERIAL_SEND, pcb);
    }

    return true;
}

void uninit_plugin(void *self) { }
