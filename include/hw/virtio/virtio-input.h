#ifndef QEMU_VIRTIO_INPUT_H
#define QEMU_VIRTIO_INPUT_H

#include "ui/input.h"

/* ----------------------------------------------------------------- */
/* virtio input protocol                                             */

#include "standard-headers/linux/virtio_ids.h"
#include "standard-headers/linux/virtio_input.h"

typedef struct virtio_input_absinfo virtio_input_absinfo;
typedef struct virtio_input_config virtio_input_config;
typedef struct virtio_input_event virtio_input_event;

/* ----------------------------------------------------------------- */
/* qemu internals                                                    */

#define TYPE_VIRTIO_INPUT "virtio-input-device"
#define VIRTIO_INPUT(obj) \
        OBJECT_CHECK(VirtIOInput, (obj), TYPE_VIRTIO_INPUT)
#define VIRTIO_INPUT_GET_PARENT_CLASS(obj) \
        OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_INPUT)
#define VIRTIO_INPUT_GET_CLASS(obj) \
        OBJECT_GET_CLASS(VirtIOInputClass, obj, TYPE_VIRTIO_INPUT)
#define VIRTIO_INPUT_CLASS(klass) \
        OBJECT_CLASS_CHECK(VirtIOInputClass, klass, TYPE_VIRTIO_INPUT)

#define TYPE_VIRTIO_INPUT_HID "virtio-input-hid-device"
#define TYPE_VIRTIO_KEYBOARD  "virtio-keyboard-device"
#define TYPE_VIRTIO_MOUSE     "virtio-mouse-device"
#define TYPE_VIRTIO_TABLET    "virtio-tablet-device"

#define VIRTIO_INPUT_HID(obj) \
        OBJECT_CHECK(VirtIOInputHID, (obj), TYPE_VIRTIO_INPUT_HID)
#define VIRTIO_INPUT_HID_GET_PARENT_CLASS(obj) \
        OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_INPUT_HID)

#define TYPE_VIRTIO_INPUT_HOST   "virtio-input-host-device"
#define VIRTIO_INPUT_HOST(obj) \
        OBJECT_CHECK(VirtIOInputHost, (obj), TYPE_VIRTIO_INPUT_HOST)
#define VIRTIO_INPUT_HOST_GET_PARENT_CLASS(obj) \
        OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_INPUT_HOST)

typedef struct VirtIOInput VirtIOInput;
typedef struct VirtIOInputClass VirtIOInputClass;
typedef struct VirtIOInputConfig VirtIOInputConfig;
typedef struct VirtIOInputHID VirtIOInputHID;
typedef struct VirtIOInputHost VirtIOInputHost;

struct VirtIOInputConfig {
    virtio_input_config               config;
    QTAILQ_ENTRY(VirtIOInputConfig)   node;
};

struct VirtIOInput {
    VirtIODevice                      parent_obj;
    uint8_t                           cfg_select;
    uint8_t                           cfg_subsel;
    uint32_t                          cfg_size;
    QTAILQ_HEAD(, VirtIOInputConfig)  cfg_list;
    VirtQueue                         *evt, *sts;
    char                              *serial;

    struct {
        virtio_input_event event;
        VirtQueueElement *elem;
    }                                 *queue;
    uint32_t                          qindex, qsize;

    bool                              active;
};

struct VirtIOInputClass {
    /*< private >*/
    VirtioDeviceClass parent;
    /*< public >*/

    DeviceRealize realize;
    DeviceUnrealize unrealize;
    void (*change_active)(VirtIOInput *vinput);
    void (*handle_status)(VirtIOInput *vinput, virtio_input_event *event);
};

struct VirtIOInputHID {
    VirtIOInput                       parent_obj;
    char                              *display;
    uint32_t                          head;
    QemuInputHandler                  *handler;
    QemuInputHandlerState             *hs;
    int                               ledstate;
};

struct VirtIOInputHost {
    VirtIOInput                       parent_obj;
    char                              *evdev;
    int                               fd;
};

void virtio_input_send(VirtIOInput *vinput, virtio_input_event *event);
void virtio_input_init_config(VirtIOInput *vinput,
                              virtio_input_config *config);
virtio_input_config *virtio_input_find_config(VirtIOInput *vinput,
                                              uint8_t select,
                                              uint8_t subsel);
void virtio_input_add_config(VirtIOInput *vinput,
                             virtio_input_config *config);
void virtio_input_idstr_config(VirtIOInput *vinput,
                               uint8_t select, const char *string);

#endif /* QEMU_VIRTIO_INPUT_H */
