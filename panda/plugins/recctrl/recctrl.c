/*!
 * @file recctrl.c
 * @brief Recording controller plugin for PANDA.
 *
 * @author Manolis Stamatogiannakis manolis.stamatogiannakis@vu.nl
 *
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <glib.h>
#include "panda/plugin.h"
#include "panda/rr/rr_api.h"
#include "recctrl.h"

bool init_plugin(void *);
void uninit_plugin(void *);
bool start_stop_recording(CPUState *cpu);
gboolean timeout_cb(gpointer data);

static bool dry = false; /** dry-run mode flag */
static rr_control_t rr_control_dry = {.mode = RR_OFF, .next = RR_NOCHANGE}; /** dry-run state */
static bool session_rec = false; /** session recoding mode flag */
static uint32_t nsessions = 0;   /** number of active sessions */
static uint32_t nrec_max = 0;    /** maximum number of session recordings to produce */
static uint32_t nrec = 0;        /** number of recodings produced so far */
static uint32_t timeout = 0;     /** maximum numbers of seconds for a recording */
static uint32_t timeout_id = 0;  /** id for the last recording timeout callback */

/**
 * @brief Reads a printable string from the guest up to \p maxlen bytes long.
 * The length includes the terminating \0 byte. Returns a dynamically allocated
 * copy of the string.
 */
static inline char *read_guest_string(CPUState *cpu, target_ptr_t addr, uint32_t maxlen) {
    uint8_t *buf = g_malloc0(maxlen*sizeof(char));
    uint32_t i = 0;
    if (panda_virtual_memory_read(cpu, addr, buf, maxlen) > 0) {
        LOG_ERROR("could not read string from " TARGET_PTR_FMT, addr);
        goto error;
    }
    while (i < maxlen && g_ascii_isprint(buf[i])) { i++; }
    if (i < maxlen && buf[i] == '\0') {
        return (char *)buf;
    } else {
        LOG_ERROR("malformed string read from " TARGET_PTR_FMT, addr);
        goto error;
    }
error:
    g_free(buf);
    return NULL;
}

/**
 * @brief Callback for unconditionally toggling panda PANDA recording.
 * Returns a status code whether the toggle was successful.
 */
static recctrl_ret_t record_toggler(CPUState *cpu, rr_control_t *rrcp, target_ptr_t rnamep) {
    recctrl_ret_t ret = RECCTRL_RET_ERROR;

    switch (rrcp->mode) {
	case RR_OFF: {
        LOG_INFO("start of recording requested");
        char *guest_string = read_guest_string(cpu, rnamep, RECCTRL_RNAME_MAX);
        char *rname = guest_string;
        if (rname != NULL) {
            if (nrec_max != 1) {
                rname = g_strdup_printf("%s_%03u", guest_string, nrec);
                g_free(guest_string);
            }
            if (!dry) {
                panda_record_begin(rname, NULL);
                g_free(rname);
            } else {
                rrcp->mode = RR_RECORD;
                rrcp->name = rname;
            }
            ret = RECCTRL_RET_START;
        } else {
            LOG_ERROR("start of recording aborted (couldn't get recording name)");
        }
	} break;

	case RR_RECORD: {
        LOG_INFO("end of recording requested");
        if (!dry) {
            panda_record_end();
        } else {
            rrcp->mode = RR_OFF;
            g_free(rrcp->name);
            rrcp->name = NULL;
        }
        ret = RECCTRL_RET_STOP;
	} break;

	case RR_REPLAY: {
        LOG_WARNING("ignoring record request during replay");
        ret = RECCTRL_RET_NOOP;
	} break;

	default: {
        LOG_ERROR("unknown rr mode=%d", rrcp->mode);
        ret = RECCTRL_RET_NOOP;
        assert(false && "unknown rr mode");
    } break;
    }

    return ret;
}

/**
 * @brief Callback for starting/stopping PANDA recording using a hypercall
 * from the guest VM. Returns true when the proper hypercall magic is set.
 * Registers are set with the appropriate return code for the user program.
 */
bool start_stop_recording(CPUState *cpu) {
    target_ulong magic = 0;
    target_ptr_t rnamep = (uintptr_t)NULL;
    recctrl_action_t action = RECCTRL_ACT_TOGGLE;
    recctrl_ret_t hypercall_ret = RECCTRL_RET_NOOP;
    target_ulong *hypercall_retp = NULL;

    rr_control_t *rrcp = dry ? &rr_control_dry : &rr_control;
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;

#if defined(TARGET_I386)
    magic = env->regs[R_EAX];
    action = env->regs[R_EBX];
    rnamep = env->regs[R_ECX];
    hypercall_retp = &env->regs[R_EAX];
#elif defined(TARGET_ARM)
    magic = env->regs[0];
    action = env->regs[1];
    rnamep = env->regs[2];
    hypercall_retp = &env->regs[0];
#else
    assert(false && "recctrl does not support this platform");
    assert(env);
    assert(hypercall_retp);
#endif

    if (magic != RECCTRL_MAGIC)
        return false;

    bool do_toggle = false;
    if (!session_rec) {
        /* manual mode - always toggle */
        if (action != RECCTRL_ACT_TOGGLE) {
            LOG_WARNING("ignoring unexpected action %d in manual mode", action);
        } else {
            do_toggle = true;
        }
    } else {
        /* session recorder mode - toggle based on nsessions */
        if (action == RECCTRL_ACT_SESSION_OPEN) {
            if (nsessions == 0) {
                do_toggle = true;
            }
            nsessions += 1;
        } else if (action == RECCTRL_ACT_SESSION_CLOSE) {
            if (nsessions == 1) {
                do_toggle = true;
            }
            if (nsessions == 0) {
                LOG_WARNING("session ended after the recording");
            } else {
                nsessions -= 1;
            }
        } else {
            LOG_WARNING("ignoring unexpected action %d in session recorder mode", action);
        }
    }

    if (do_toggle) {
        hypercall_ret = record_toggler(cpu, rrcp, rnamep);
        if (hypercall_ret == RECCTRL_RET_START && timeout > 0) {
            assert(timeout_id == 0 && "a timeout callback is still pending!");
            timeout_id = g_timeout_add_seconds(timeout, timeout_cb, NULL);
        } else if (hypercall_ret == RECCTRL_RET_STOP) {
            nrec++;
            if (timeout_id != 0) {
                g_source_remove(timeout_id);
                timeout_id = 0;
            }
        }
    } else {
        LOG_INFO("%u active sessions", nsessions);
    }

    /* maximum number of recordings reached */
    if (nrec_max > 0 && nrec >= nrec_max) {
        LOG_INFO("quitting after %d traces", nrec);
        panda_vm_quit();
    }

    /* set hypercall return value and return to callbacks helper */
    *hypercall_retp = (target_ulong)hypercall_ret;
    return true;
}


/**
 * @brief Glib callback for stopping PANDA recording after a number of seconds.
 */
gboolean timeout_cb(gpointer data) {
    rr_control_t *rrcp = dry ? &rr_control_dry : &rr_control;
    recctrl_ret_t hypercall_ret = RECCTRL_RET_NOOP;

    if (rrcp->mode == RR_RECORD) {
        /*  when turning off recording only rrcp variable is required */
        hypercall_ret = record_toggler(NULL, rrcp, (uintptr_t)NULL);
        if (hypercall_ret == RECCTRL_RET_STOP) {
            nrec++;
            nsessions = 0;
            timeout_id = 0;
            LOG_INFO("Recording %d timed out after %dsec.", nrec, timeout);
        } else {
            assert(false && "recording didn't stop?");
        }

        /* maximum number of recordings reached */
        if (nrec_max > 0 && nrec >= nrec_max) {
            LOG_INFO("quitting after %d traces", nrec);
            panda_vm_quit();
        }
    } else {
        /* timeout should have been unregistered */
        assert(false && "unexpected timeout");
    }

    /* timeout only runs once */
    return false;
}

bool init_plugin(void *self) {
    panda_cb pcb;
    pcb.guest_hypercall = start_stop_recording;
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);

    panda_arg_list *args = panda_get_args(PLUGIN_NAME);
    if (args != NULL) {
        dry = panda_parse_bool_opt(args, "dry", "dry-run mode");
        session_rec = panda_parse_bool_opt(args, "session_rec", "session recording mode");
        nrec_max = panda_parse_uint32_opt(args, "nrec", 0, "number of recodings to produce");
        timeout = panda_parse_uint32_opt(args, "timeout", 0, "recording timeout in sec");
    }

    LOG_INFO("mode=%s, nrec=%d, timeout=%d, dry-mode=%s",
            (session_rec ? "sessions" : "manual"), nrec_max,
            timeout, (dry ? "yes" : "no"));

    return true;
}

void uninit_plugin(void *self) {
    LOG_INFO("produced %d traces", nrec);
}

/* vim:set tabstop=4 softtabstop=4 expandtab: */
