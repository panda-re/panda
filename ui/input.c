#include "qemu/osdep.h"
#include "hw/qdev.h"
#include "sysemu/sysemu.h"
#include "qapi-types.h"
#include "qemu/error-report.h"
#include "qmp-commands.h"
#include "trace.h"
#include "ui/input.h"
#include "ui/console.h"
#include "sysemu/replay.h"

struct QemuInputHandlerState {
    DeviceState       *dev;
    QemuInputHandler  *handler;
    int               id;
    int               events;
    QemuConsole       *con;
    QTAILQ_ENTRY(QemuInputHandlerState) node;
};

typedef struct QemuInputEventQueue QemuInputEventQueue;
struct QemuInputEventQueue {
    enum {
        QEMU_INPUT_QUEUE_DELAY = 1,
        QEMU_INPUT_QUEUE_EVENT,
        QEMU_INPUT_QUEUE_SYNC,
    } type;
    QEMUTimer *timer;
    uint32_t delay_ms;
    QemuConsole *src;
    InputEvent *evt;
    QTAILQ_ENTRY(QemuInputEventQueue) node;
};

static QTAILQ_HEAD(, QemuInputHandlerState) handlers =
    QTAILQ_HEAD_INITIALIZER(handlers);
static NotifierList mouse_mode_notifiers =
    NOTIFIER_LIST_INITIALIZER(mouse_mode_notifiers);

static QTAILQ_HEAD(QemuInputEventQueueHead, QemuInputEventQueue) kbd_queue =
    QTAILQ_HEAD_INITIALIZER(kbd_queue);
static QEMUTimer *kbd_timer;
static uint32_t kbd_default_delay_ms = 10;
static uint32_t queue_count;
static uint32_t queue_limit = 1024;

QemuInputHandlerState *qemu_input_handler_register(DeviceState *dev,
                                                   QemuInputHandler *handler)
{
    QemuInputHandlerState *s = g_new0(QemuInputHandlerState, 1);
    static int id = 1;

    s->dev = dev;
    s->handler = handler;
    s->id = id++;
    QTAILQ_INSERT_TAIL(&handlers, s, node);

    qemu_input_check_mode_change();
    return s;
}

void qemu_input_handler_activate(QemuInputHandlerState *s)
{
    QTAILQ_REMOVE(&handlers, s, node);
    QTAILQ_INSERT_HEAD(&handlers, s, node);
    qemu_input_check_mode_change();
}

void qemu_input_handler_deactivate(QemuInputHandlerState *s)
{
    QTAILQ_REMOVE(&handlers, s, node);
    QTAILQ_INSERT_TAIL(&handlers, s, node);
    qemu_input_check_mode_change();
}

void qemu_input_handler_unregister(QemuInputHandlerState *s)
{
    QTAILQ_REMOVE(&handlers, s, node);
    g_free(s);
    qemu_input_check_mode_change();
}

void qemu_input_handler_bind(QemuInputHandlerState *s,
                             const char *device_id, int head,
                             Error **errp)
{
    QemuConsole *con;
    Error *err = NULL;

    con = qemu_console_lookup_by_device_name(device_id, head, &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    s->con = con;
}

static QemuInputHandlerState*
qemu_input_find_handler(uint32_t mask, QemuConsole *con)
{
    QemuInputHandlerState *s;

    QTAILQ_FOREACH(s, &handlers, node) {
        if (s->con == NULL || s->con != con) {
            continue;
        }
        if (mask & s->handler->mask) {
            return s;
        }
    }

    QTAILQ_FOREACH(s, &handlers, node) {
        if (s->con != NULL) {
            continue;
        }
        if (mask & s->handler->mask) {
            return s;
        }
    }
    return NULL;
}

void qmp_input_send_event(bool has_device, const char *device,
                          bool has_head, int64_t head,
                          InputEventList *events, Error **errp)
{
    InputEventList *e;
    QemuConsole *con;
    Error *err = NULL;

    con = NULL;
    if (has_device) {
        if (!has_head) {
            head = 0;
        }
        con = qemu_console_lookup_by_device_name(device, head, &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }
    }

    if (!runstate_is_running() && !runstate_check(RUN_STATE_SUSPENDED)) {
        error_setg(errp, "VM not running");
        return;
    }

    for (e = events; e != NULL; e = e->next) {
        InputEvent *event = e->value;

        if (!qemu_input_find_handler(1 << event->type, con)) {
            error_setg(errp, "Input handler not found for "
                             "event type %s",
                            InputEventKind_lookup[event->type]);
            return;
        }
    }

    for (e = events; e != NULL; e = e->next) {
        InputEvent *event = e->value;

        qemu_input_event_send(con, event);
    }

    qemu_input_event_sync();
}

static void qemu_input_transform_abs_rotate(InputEvent *evt)
{
    InputMoveEvent *move = evt->u.abs.data;
    switch (graphic_rotate) {
    case 90:
        if (move->axis == INPUT_AXIS_X) {
            move->axis = INPUT_AXIS_Y;
        } else if (move->axis == INPUT_AXIS_Y) {
            move->axis = INPUT_AXIS_X;
            move->value = INPUT_EVENT_ABS_SIZE - 1 - move->value;
        }
        break;
    case 180:
        move->value = INPUT_EVENT_ABS_SIZE - 1 - move->value;
        break;
    case 270:
        if (move->axis == INPUT_AXIS_X) {
            move->axis = INPUT_AXIS_Y;
            move->value = INPUT_EVENT_ABS_SIZE - 1 - move->value;
        } else if (move->axis == INPUT_AXIS_Y) {
            move->axis = INPUT_AXIS_X;
        }
        break;
    }
}

static void qemu_input_event_trace(QemuConsole *src, InputEvent *evt)
{
    const char *name;
    int qcode, idx = -1;
    InputKeyEvent *key;
    InputBtnEvent *btn;
    InputMoveEvent *move;

    if (src) {
        idx = qemu_console_get_index(src);
    }
    switch (evt->type) {
    case INPUT_EVENT_KIND_KEY:
        key = evt->u.key.data;
        switch (key->key->type) {
        case KEY_VALUE_KIND_NUMBER:
            qcode = qemu_input_key_number_to_qcode(key->key->u.number.data);
            name = QKeyCode_lookup[qcode];
            trace_input_event_key_number(idx, key->key->u.number.data,
                                         name, key->down);
            break;
        case KEY_VALUE_KIND_QCODE:
            name = QKeyCode_lookup[key->key->u.qcode.data];
            trace_input_event_key_qcode(idx, name, key->down);
            break;
        case KEY_VALUE_KIND__MAX:
            /* keep gcc happy */
            break;
        }
        break;
    case INPUT_EVENT_KIND_BTN:
        btn = evt->u.btn.data;
        name = InputButton_lookup[btn->button];
        trace_input_event_btn(idx, name, btn->down);
        break;
    case INPUT_EVENT_KIND_REL:
        move = evt->u.rel.data;
        name = InputAxis_lookup[move->axis];
        trace_input_event_rel(idx, name, move->value);
        break;
    case INPUT_EVENT_KIND_ABS:
        move = evt->u.abs.data;
        name = InputAxis_lookup[move->axis];
        trace_input_event_abs(idx, name, move->value);
        break;
    case INPUT_EVENT_KIND__MAX:
        /* keep gcc happy */
        break;
    }
}

static void qemu_input_queue_process(void *opaque)
{
    struct QemuInputEventQueueHead *queue = opaque;
    QemuInputEventQueue *item;

    g_assert(!QTAILQ_EMPTY(queue));
    item = QTAILQ_FIRST(queue);
    g_assert(item->type == QEMU_INPUT_QUEUE_DELAY);
    QTAILQ_REMOVE(queue, item, node);
    queue_count--;
    g_free(item);

    while (!QTAILQ_EMPTY(queue)) {
        item = QTAILQ_FIRST(queue);
        switch (item->type) {
        case QEMU_INPUT_QUEUE_DELAY:
            timer_mod(item->timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
                      + item->delay_ms);
            return;
        case QEMU_INPUT_QUEUE_EVENT:
            qemu_input_event_send(item->src, item->evt);
            qapi_free_InputEvent(item->evt);
            break;
        case QEMU_INPUT_QUEUE_SYNC:
            qemu_input_event_sync();
            break;
        }
        QTAILQ_REMOVE(queue, item, node);
        queue_count--;
        g_free(item);
    }
}

static void qemu_input_queue_delay(struct QemuInputEventQueueHead *queue,
                                   QEMUTimer *timer, uint32_t delay_ms)
{
    QemuInputEventQueue *item = g_new0(QemuInputEventQueue, 1);
    bool start_timer = QTAILQ_EMPTY(queue);

    item->type = QEMU_INPUT_QUEUE_DELAY;
    item->delay_ms = delay_ms;
    item->timer = timer;
    QTAILQ_INSERT_TAIL(queue, item, node);
    queue_count++;

    if (start_timer) {
        timer_mod(item->timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
                  + item->delay_ms);
    }
}

static void qemu_input_queue_event(struct QemuInputEventQueueHead *queue,
                                   QemuConsole *src, InputEvent *evt)
{
    QemuInputEventQueue *item = g_new0(QemuInputEventQueue, 1);

    item->type = QEMU_INPUT_QUEUE_EVENT;
    item->src = src;
    item->evt = evt;
    QTAILQ_INSERT_TAIL(queue, item, node);
    queue_count++;
}

static void qemu_input_queue_sync(struct QemuInputEventQueueHead *queue)
{
    QemuInputEventQueue *item = g_new0(QemuInputEventQueue, 1);

    item->type = QEMU_INPUT_QUEUE_SYNC;
    QTAILQ_INSERT_TAIL(queue, item, node);
    queue_count++;
}

void qemu_input_event_send_impl(QemuConsole *src, InputEvent *evt)
{
    QemuInputHandlerState *s;

    qemu_input_event_trace(src, evt);

    /* pre processing */
    if (graphic_rotate && (evt->type == INPUT_EVENT_KIND_ABS)) {
            qemu_input_transform_abs_rotate(evt);
    }

    /* send event */
    s = qemu_input_find_handler(1 << evt->type, src);
    if (!s) {
        return;
    }
    s->handler->event(s->dev, src, evt);
    s->events++;
}

void qemu_input_event_send(QemuConsole *src, InputEvent *evt)
{
    if (!runstate_is_running() && !runstate_check(RUN_STATE_SUSPENDED)) {
        return;
    }

    replay_input_event(src, evt);
}

void qemu_input_event_sync_impl(void)
{
    QemuInputHandlerState *s;

    trace_input_event_sync();

    QTAILQ_FOREACH(s, &handlers, node) {
        if (!s->events) {
            continue;
        }
        if (s->handler->sync) {
            s->handler->sync(s->dev);
        }
        s->events = 0;
    }
}

void qemu_input_event_sync(void)
{
    if (!runstate_is_running() && !runstate_check(RUN_STATE_SUSPENDED)) {
        return;
    }

    replay_input_sync_event();
}

InputEvent *qemu_input_event_new_key(KeyValue *key, bool down)
{
    InputEvent *evt = g_new0(InputEvent, 1);
    evt->u.key.data = g_new0(InputKeyEvent, 1);
    evt->type = INPUT_EVENT_KIND_KEY;
    evt->u.key.data->key = key;
    evt->u.key.data->down = down;
    return evt;
}

void qemu_input_event_send_key(QemuConsole *src, KeyValue *key, bool down)
{
    InputEvent *evt;
    evt = qemu_input_event_new_key(key, down);
    if (QTAILQ_EMPTY(&kbd_queue)) {
        qemu_input_event_send(src, evt);
        qemu_input_event_sync();
        qapi_free_InputEvent(evt);
    } else if (queue_count < queue_limit) {
        qemu_input_queue_event(&kbd_queue, src, evt);
        qemu_input_queue_sync(&kbd_queue);
    }
}

void qemu_input_event_send_key_number(QemuConsole *src, int num, bool down)
{
    KeyValue *key = g_new0(KeyValue, 1);
    key->type = KEY_VALUE_KIND_NUMBER;
    key->u.number.data = num;
    qemu_input_event_send_key(src, key, down);
}

void qemu_input_event_send_key_qcode(QemuConsole *src, QKeyCode q, bool down)
{
    KeyValue *key = g_new0(KeyValue, 1);
    key->type = KEY_VALUE_KIND_QCODE;
    key->u.qcode.data = q;
    qemu_input_event_send_key(src, key, down);
}

void qemu_input_event_send_key_delay(uint32_t delay_ms)
{
    if (!kbd_timer) {
        kbd_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, qemu_input_queue_process,
                                 &kbd_queue);
    }
    if (queue_count < queue_limit) {
        qemu_input_queue_delay(&kbd_queue, kbd_timer,
                               delay_ms ? delay_ms : kbd_default_delay_ms);
    }
}

InputEvent *qemu_input_event_new_btn(InputButton btn, bool down)
{
    InputEvent *evt = g_new0(InputEvent, 1);
    evt->u.btn.data = g_new0(InputBtnEvent, 1);
    evt->type = INPUT_EVENT_KIND_BTN;
    evt->u.btn.data->button = btn;
    evt->u.btn.data->down = down;
    return evt;
}

void qemu_input_queue_btn(QemuConsole *src, InputButton btn, bool down)
{
    InputEvent *evt;
    evt = qemu_input_event_new_btn(btn, down);
    qemu_input_event_send(src, evt);
    qapi_free_InputEvent(evt);
}

void qemu_input_update_buttons(QemuConsole *src, uint32_t *button_map,
                               uint32_t button_old, uint32_t button_new)
{
    InputButton btn;
    uint32_t mask;

    for (btn = 0; btn < INPUT_BUTTON__MAX; btn++) {
        mask = button_map[btn];
        if ((button_old & mask) == (button_new & mask)) {
            continue;
        }
        qemu_input_queue_btn(src, btn, button_new & mask);
    }
}

bool qemu_input_is_absolute(void)
{
    QemuInputHandlerState *s;

    s = qemu_input_find_handler(INPUT_EVENT_MASK_REL | INPUT_EVENT_MASK_ABS,
                                NULL);
    return (s != NULL) && (s->handler->mask & INPUT_EVENT_MASK_ABS);
}

int qemu_input_scale_axis(int value, int size_in, int size_out)
{
    if (size_in < 2) {
        return size_out / 2;
    }
    return (int64_t)value * (size_out - 1) / (size_in - 1);
}

InputEvent *qemu_input_event_new_move(InputEventKind kind,
                                      InputAxis axis, int value)
{
    InputEvent *evt = g_new0(InputEvent, 1);
    InputMoveEvent *move = g_new0(InputMoveEvent, 1);

    evt->type = kind;
    evt->u.rel.data = move; /* evt->u.rel is the same as evt->u.abs */
    move->axis = axis;
    move->value = value;
    return evt;
}

void qemu_input_queue_rel(QemuConsole *src, InputAxis axis, int value)
{
    InputEvent *evt;
    evt = qemu_input_event_new_move(INPUT_EVENT_KIND_REL, axis, value);
    qemu_input_event_send(src, evt);
    qapi_free_InputEvent(evt);
}

void qemu_input_queue_abs(QemuConsole *src, InputAxis axis, int value, int size)
{
    InputEvent *evt;
    int scaled = qemu_input_scale_axis(value, size, INPUT_EVENT_ABS_SIZE);
    evt = qemu_input_event_new_move(INPUT_EVENT_KIND_ABS, axis, scaled);
    qemu_input_event_send(src, evt);
    qapi_free_InputEvent(evt);
}

void qemu_input_check_mode_change(void)
{
    static int current_is_absolute;
    int is_absolute;

    is_absolute = qemu_input_is_absolute();

    if (is_absolute != current_is_absolute) {
        trace_input_mouse_mode(is_absolute);
        notifier_list_notify(&mouse_mode_notifiers, NULL);
    }

    current_is_absolute = is_absolute;
}

void qemu_add_mouse_mode_change_notifier(Notifier *notify)
{
    notifier_list_add(&mouse_mode_notifiers, notify);
}

void qemu_remove_mouse_mode_change_notifier(Notifier *notify)
{
    notifier_remove(notify);
}

MouseInfoList *qmp_query_mice(Error **errp)
{
    MouseInfoList *mice_list = NULL;
    MouseInfoList *info;
    QemuInputHandlerState *s;
    bool current = true;

    QTAILQ_FOREACH(s, &handlers, node) {
        if (!(s->handler->mask &
              (INPUT_EVENT_MASK_REL | INPUT_EVENT_MASK_ABS))) {
            continue;
        }

        info = g_new0(MouseInfoList, 1);
        info->value = g_new0(MouseInfo, 1);
        info->value->index = s->id;
        info->value->name = g_strdup(s->handler->name);
        info->value->absolute = s->handler->mask & INPUT_EVENT_MASK_ABS;
        info->value->current = current;

        current = false;
        info->next = mice_list;
        mice_list = info;
    }

    return mice_list;
}

void hmp_mouse_set(Monitor *mon, const QDict *qdict)
{
    QemuInputHandlerState *s;
    int index = qdict_get_int(qdict, "index");
    int found = 0;

    QTAILQ_FOREACH(s, &handlers, node) {
        if (s->id != index) {
            continue;
        }
        if (!(s->handler->mask & (INPUT_EVENT_MASK_REL |
                                  INPUT_EVENT_MASK_ABS))) {
            error_report("Input device '%s' is not a mouse", s->handler->name);
            return;
        }
        found = 1;
        qemu_input_handler_activate(s);
        break;
    }

    if (!found) {
        error_report("Mouse at index '%d' not found", index);
    }

    qemu_input_check_mode_change();
}
