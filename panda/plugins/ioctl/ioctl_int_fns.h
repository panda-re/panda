//#ifndef __IOCTL_INT_FNS_H__
//#define __IOCTL_INT_FNS_H__

extern "C" {

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

    // Callback functions must be of this type
    // They always fire on ioctl return, not entry
    typedef void (*ioctl_hook_t)(CPUState*, ioctl_t*);

    void force_success(const char* path);
    void add_ioctl_hook_by_path(const char* path, ioctl_hook_t hook);
    void add_all_ioctls_hook(ioctl_hook_t hook);

    void decode_ioctl_cmd(ioctl_cmd_t* cmd, uint32_t val);
    uint32_t encode_ioctl_cmd(ioctl_cmd_t* cmd);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

}

//#endif // __IOCTL_INT_FNS_H__