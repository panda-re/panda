extern "C" {

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

    // Block a signal for all processes
    void block_sig(int32_t sig);

    // Block a signal only for a named process
    void block_sig_by_proc(int32_t sig, char* proc_name);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

}
