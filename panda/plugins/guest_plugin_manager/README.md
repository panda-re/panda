# Guest Plugin Manager

The guest plugin manager is a PANDA plugin which handles loading guest agent plugins 
into the guest, managing communication channels between the guest and the host. 
Typical usage involves writing a host PANDA plugin which calls the plugin manager in
order to load the executable, then loading that PANDA plugin as normal (from either the
PANDA command line or from pypanda).

Currently the guest plugin manager only supports Linux guests via the `linjector` plugin
however support for other guest OS' would be possible in the presence of other backends.
The responsibility of `linjector` is, as the name would imply, inject a single binary
into the guest as a new process. The guest plugin manager uses this capability in order
to load the "Guest Daemon", an executable running the guest responsible for handling
the spawning of future guest processes and is responsible for communicating with the
guest_plugin_manager directly.

## APIs and Callbacks

---

Name: **add_guest_plugin**

Signature:

```c
typedef ChannelId (*add_guest_plugin)(GuestPlugin);
```

Description: Adds a guest plugin to be loaded, returns a channel ID representing the
main channel of the to-be-loaded plugin. Writes to this channel ID before plugin
load will be queued and will thus be available when the plugin begins reading.

---

Name: **channel_write**

Signature:

```c
typedef void (*channel_write)(ChannelId, const u8*, size_t);
```

Description: Writes bytes from a buffer to the given channel ID, queuing them up for 
the next guest plugin read. The buffer is copied into a new allocation before being 
added to the queue, so the act of writing has no strict lifetime requirements.

---

Name: **get_channel_from_name**

Signature:

```c
typedef ChannelId (*get_channel_from_name)(const char*);
```

Description:

Given the name of a plugin or channel, return the associated channel, panicking
if a channel of the given name cannot be found. Channel name should be passed
as a null-terminated string.

The provided string has no lifetime requirements, but must be a non-null pointer
to a valid C string.

---

## Types

```c
// A globally unique identifier for a given channel
typedef uint32_t ChannelId;

// ChannelId - the unique identifier for the channel the message came from
// const unsigned char* - a pointer to the data being sent from the guest
// size_t - the length of the data buffer in bytes
typedef void (*ChannelCB)(ChannelId, const unsigned char*, size_t);

// A plugin to be passed to guest_plugin_manager to be registered
typedef struct guest_plugin {
    // A unique name for the given plugin, provided as a non-null C string
    const char* plugin_name;

    // An optional path to load the guest agent binary. If null, a lookup will be
    // performed to find the binary from the given name. If non-null must be a valid
    // C string.
    const char* guest_binary_path;

    // A callback for when this guest plugin sends a message to the host
    ChannelCB msg_recieve_cb;
} GuestPlugin;
```
