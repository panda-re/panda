/*!
 * @file osi_pse_linux.h
 * @brief Helpers for the linux implementation for process-level events.
 *
 * @author Manolis Stamatogiannakis manolis.stamatogiannakis@vu.nl
 *
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <tuple>
#include <vector>

extern "C" {
PPP_CB_EXTERN(on_process_start)
PPP_CB_EXTERN(on_process_end)
}

/**
 * @brief Linux Process FSM class. Wraps the state of the FSM we use to
 * track the lifetime of processes.
 */
class LPFSM {
   public:
    /** @brief Enumeration of available FSM states. */
    enum State : uint8_t { INIT, RUN, EXE, CLN, VFP, VFC, KILL, END, KERN };
    static const uint8_t kNumStates;

    State state; /**< Current FSM state. */

    /** @brief Default constructor. */
    LPFSM() = default;

    /** @brief Constructor from initial state. */
    constexpr LPFSM(State s) : state(s), state_sav_(s) {}

    /** @brief Destructor. Deallocates internal transition string. */
    ~LPFSM() {
        if (transition_cstr_ != nullptr) {
            delete transition_cstr_;
        }
    }

    /** @brief Equality operator */
    bool operator==(LPFSM fsm) const { return state == fsm.state; }

    /** @brief Inequality operator */
    bool operator!=(LPFSM fsm) const { return state != fsm.state; }

    /**
     * @brief Saves the FSM state to a backup variable.
     * This is used to control the output of transition_c_str().
     **/
    inline void save_state() { state_sav_ = state; }

    /**
     * @brief Saves the FSM state to a backup variable.
     * This is used to control the output of transition_c_str().
     **/
    inline bool state_changed() { return state_sav_ != state; }

    /** @brief Returns a C string representation for the specified FSM state. */
    static const char *state_str(State s) { return kStateCString_[s]; }

    /** @brief Returns a C string representation of the current FSM state. */
    inline const char *c_str() const { return kStateCString_[state]; }

    /**
     * @brief Returns a C string representing the transition from the last
     * saved FSM state to the current FSM state. Intermediate transitions
     * are not captured.
     */
    inline const char *transition_c_str() {
        if (transition_cstr_ == nullptr) {
            transition_cstr_ = new char[kMaxTransitionString_];
        }
        if (state == state_sav_) {
            strncpy(transition_cstr_, kStateCString_[(uint8_t)state],
                    kMaxTransitionString_);
        } else {
            snprintf(transition_cstr_, kMaxTransitionString_,
                     kTransitionStringFormat_,
                     kStateCString_[(uint8_t)state_sav_],
                     kStateCString_[(uint8_t)state]);
        }
        return transition_cstr_;
    }

   private:
    State state_sav_;                 /**< Saved FSM state. */
    char *transition_cstr_ = nullptr; /**< Buffer used for transition strings */

    static const char *kStateCString_[];
    static const uint8_t kMaxStateString_;
    static const char *kTransitionStringFormat_;
    static const uint8_t kMaxTransitionString_;
};
/** @brief Number of LPFSM states. */
const uint8_t LPFSM::kNumStates = (uint8_t)LPFSM::State::KERN + 1;
/** @brief String representation of the LPFSM states. */
const char *LPFSM::kStateCString_[] = {"INIT", "RUN",  "EXE",  "CLN", "VFP",
                                       "VFC",  "KILL", "END", "KERN"};
/** @brief Maximum length for a string representation of an LPFSM state. */
const uint8_t LPFSM::kMaxStateString_ = 4;
/** @brief Format used for stringifying LPFSM state transitions. */
const char *LPFSM::kTransitionStringFormat_ = "%s -> %s";
/** @brief Maximum length for a state transition string. */
const uint8_t LPFSM::kMaxTransitionString_ =
    strlen(LPFSM::kTransitionStringFormat_) + 2 * LPFSM::kMaxStateString_;


/** @brief Encapsulates the current state of a process. */
typedef struct process_info_struct {
    OsiProcHandle handle; /**< Handle of the process. */
    target_pid_t pid;     /**< Process id. */
    target_pid_t ppid;    /**< Parent process id. */
    LPFSM fsm;            /**< Current FSM state for the process. */
    struct process_info_struct *vforkp; /**< Pointer to vfork parent. */
    struct process_info_struct *vforkc; /**< Pointer to vform child. */
    bool ran_cb_start_; /**< status of on_process_start callback */
    bool ran_cb_end_;   /**< status of on_process_end callback */

    /** @brief Default constructor. Manual initialization should follow.  */
    process_info_struct() = default;

    /** @brief Construct and initialize from handle. */
    process_info_struct(CPUState *cpu, OsiProcHandle *h) {
       reset(cpu, h->taskd, h->asid, true);
    }

    /** @brief Construct and initialize from  \p taskd and \p asid. */
    process_info_struct(CPUState *cpu, target_ptr_t taskd, target_ptr_t asid) {
       reset(cpu, taskd, asid, true);
    }

    /**
     * @brief Wrapper for running the start callback for the process.
     * Makes sure that the callback is run only once.
     */
    inline void run_cb_start(CPUState *cpu) {
        if (ran_cb_start_) {
            // make this a soft error - for now at least
            LOG_WARNING("Callback on_process_start has already run for "
                        PH_FMT ".", PH_ARGS(handle));
        } else {
            ran_cb_start_ = true;
            PPP_RUN_CB(on_process_start, cpu, &handle)
        }
    }

    /**
     * @brief Wrapper for running the end callback for the process.
     * Makes sure that the callback is run only once.
     */
    inline void run_cb_end(CPUState *cpu) {
        if (!ran_cb_start_) {
           LOG_ERROR("Callback on_process_start hasn't run for "
                     PH_FMT ".", PH_ARGS(handle));
           assert(false && "on_process_end without on_process_start");
        }

        if (ran_cb_end_) {
            LOG_ERROR("Callback on_process_end has already run for "
                      PH_FMT ".", PH_ARGS(handle));
            assert(false && "duplicate on_process_end");
        } else {
            ran_cb_end_ = true;
            PPP_RUN_CB(on_process_end, cpu, &handle)
        }
    }

    /** @brief Resets the process information using the provided handle. */
    inline void reset(CPUState *cpu, OsiProcHandle *h, bool force=false) {
        reset(cpu, h->taskd, h->asid, force);
    }

    /**
     * and \p asid. By default the process is required to have an fsm state
     * of LPFSM::State::END. This helps to avoid having to do this check
     * at the call location. The \p force argument allows the caller to
     * skip the check in cases where this is desired.
     */
    inline void reset(CPUState *cpu, target_ptr_t taskd, target_ptr_t asid, bool force=false) {
        if (!force && fsm.state != LPFSM::State::END) {
           LOG_ERROR("Reset process has not ended. "
                     "If this expected, use force=true when resetting.");
           vdump(cpu);
           assert(false && "reset process has not ended");
        }
        handle.taskd = taskd;
        handle.asid = asid;
        pid = get_process_pid(cpu, &handle);
        ppid = get_process_ppid(cpu, &handle);
        fsm.state = ((handle.asid != ASID0) ? LPFSM::State::INIT : LPFSM::State::KERN);
        vforkp = nullptr;
        vforkc = nullptr;
        ran_cb_start_ = false;
        ran_cb_end_ = false;
        vdump(cpu);
    }

    /** @brief Dumps default verbose information for \p p. */
    inline void vdump(CPUState *cpu) const {
#if PANDA_LOG_LEVEL >= PANDA_LOG_DEBUG
       vdump(cpu, fsm.c_str());
#endif
    }

    /** @brief Dumps verbose information for \p p (alternative). */
    inline void vdump_transition(CPUState *cpu) {
#if PANDA_LOG_LEVEL >= PANDA_LOG_DEBUG
       vdump(cpu, fsm.transition_c_str());
#endif
    }

    /**
     * @brief Dumps verbose information for \p p. This includes introspection
     * information such as the process name. For this, a \p cpu argument needs
     * to be supplied.
     */
    inline void vdump(CPUState *cpu, const char *sff) const {
#if PANDA_LOG_LEVEL >= PANDA_LOG_DEBUG
        OsiProc *osip = get_process(cpu, &handle);
        assert(osip != nullptr);

        // Warn when live and stored state don't match.
        // END and EXE are ignored because not matching is expected.
        if (fsm.state != LPFSM::State::END &&
            fsm.state != LPFSM::State::EXE &&
            (handle.asid != osip->asid || handle.taskd != osip->taskd)) {
            LOG_WARNING("Live and stored process info don't match:");
            LOG_WARNING("\t  live " TARGET_PTR_FMT " " TARGET_PTR_FMT,
                        osip->asid, osip->taskd);
            LOG_WARNING("\tstored " TARGET_PTR_FMT " " TARGET_PTR_FMT,
                        handle.asid, handle.taskd);
        }

        char *prf = g_strdup_printf(TARGET_PID_FMT ":" TARGET_PID_FMT,
                                    osip->pid, osip->ppid);
        dump(prf, osip->name, sff);
        g_free(prf);
        free_osiproc(osip);
#endif
    }

    /**
     * @brief Dumps process information for \p p, supplemented
     * with the supplied, prefix (\p prf), details (\p det),
     * and suffix (\p sff).
     */
    inline void dump(const char *prf, const char *det, const char *sff) const {
#if PANDA_LOG_LEVEL >= PANDA_LOG_DEBUG
        prf = (prf == nullptr) ? "    " : prf;
        det = (det == nullptr) ? "" : det;
        sff = (sff == nullptr) ? "" : sff;
        LOG_DEBUG("%9s\t%-20s\t" PH_FMT "\t%s", prf, det, PH_ARGS(handle), sff);
#endif
    }
} process_info_t;


/** @brief Maps task descriptor addresses to process_info_t stucts. */
typedef std::map<target_ptr_t, process_info_t> process_map_t;
/** @brief Maps asids to task descriptor addresses. */
typedef std::map<target_ptr_t, target_ptr_t> asid_task_map_t;
/**
 * @brief Information about a retrieved process_info_t.
 * Returned by get_current_process_info().
 */
typedef std::tuple<OsiProcHandle*, process_info_t&, bool> process_info_added_t;


/**
 * @brief Linux Process tracking class.
 */
class LPTracker {
   public:
    process_map_t ps;
    asid_task_map_t asids;

    /** @brief Initializes process list at start of replay. */
    inline int initialize(CPUState *cpu) {
        if (initialized_) { return -1; }
        uint32_t nadded = 0;
        GArray *handles = get_process_handles(cpu);
        assert(handles != nullptr && handles->len > 0);
        for (uint32_t i = 0; i < handles->len; i++) {
            OsiProcHandle *h = &g_array_index(handles, OsiProcHandle, i);

            // add process info
            auto emplaced_p = ps.emplace(std::piecewise_construct,
                                         std::forward_as_tuple(h->taskd),
                                         std::forward_as_tuple(cpu, h));
            process_info_t &UNUSED(p) = emplaced_p.first->second;
            assert(emplaced_p.second);

            // add asid to taskd mapping
            if (h->asid != ASID0) {
                auto emplaced_a2t = asids.emplace(h->asid, h->taskd);
                assert(emplaced_a2t.second);
            }

            nadded++;
        }
        g_array_free(handles, true);
        initialized_ = true;
        return nadded;
    }

    /** @brief Inline for dumping the process map of the instance. */
    inline void psdump(CPUState *cpu) {
#if PANDA_LOG_LEVEL >= PANDA_LOG_DEBUG
        LOG_DEBUG("--- %s - start -------------------------------------------", __func__);
        for(auto &ps_it : ps) {
           process_info_t &p = ps_it.second;
           p.vdump(cpu);
        }
        LOG_DEBUG("--- %s - end ---------------------------------------------", __func__);
        LOG_DEBUG("");
#endif
    }

    /**
     * @brief Adds an asid to taskd mapping.
     * Asserts that the mapping doesn't exist.
     */
    inline void AddASIDMapping(target_ptr_t asid, target_ptr_t taskd) {
        auto emplaced_a2t = asids.emplace(asid, taskd);
        if (emplaced_a2t.second) {
            LOG_DEBUG("\tadded a2t mapping: "
                      TARGET_PTR_FMT "->" TARGET_PTR_FMT, asid, taskd);
        } else {
            LOG_ERROR("\tadded a2t mapping: "
                      TARGET_PTR_FMT "->" TARGET_PTR_FMT, asid, taskd);
            LOG_ERROR("\texisting a2t mapping: "
                      TARGET_PTR_FMT "->" TARGET_PTR_FMT,
                      emplaced_a2t.first->first, emplaced_a2t.first->second);
            assert(false && "failed to add a2t mapping");
        }
    }

    /**
     * @brief Updates an asid to taskd mapping.
     * Asserts that the mapping already exists.
     */
    inline void UpdateASIDMapping(target_ptr_t asid, target_ptr_t new_taskd) {
        auto a2t_it = asids.find(asid);
        if (a2t_it == asids.end()) {
           LOG_ERROR("\tno a2t mapping to update for " TARGET_PTR_FMT, asid);
           assert(false && "no a2t mapping to update");
        } else if (a2t_it->second == new_taskd) {
           LOG_ERROR("\tupdating a2t mapping to the same value:"
                     TARGET_PTR_FMT "->" TARGET_PTR_FMT, asid, new_taskd);
           assert(false && "no a2t mapping to update");
        } else {
            a2t_it->second = new_taskd;
        }
    }

    /**
     * @brief Returns stored information about the current process.
     * A new information entry will be created, if needed.
     */
    inline process_info_added_t procinfo_current(CPUState *cpu) {
        OsiProcHandle *h = get_current_process_handle(cpu);

        auto ps_it = ps.lower_bound(h->taskd);
        bool found = (ps_it != ps.end() && ps_it->first == h->taskd);
        if (!found) {
            // This is the cold path.
            // Usually when kernel creates kworker processes.
            ps_it = ps.emplace_hint(ps_it, std::piecewise_construct,
                                    std::forward_as_tuple(h->taskd),
                                    std::forward_as_tuple(cpu, h));
            process_info_t &p = ps_it->second;
            auto emplaced_a2t = asids.emplace(h->asid, h->taskd);
            assert(emplaced_a2t.second);
            p.vdump(cpu);
            return std::forward_as_tuple(h, p, found);
        } else {
            // This is the hot path.
            // Normally, we have created process information ahead of time.
            process_info_t &p = ps_it->second;
            p.vdump(cpu);

            // sanity checks - can be disabled when we're more confident
            // ??? are those repicated in vdump? ???
            if (p.handle.asid != h->asid) {
                auto pidh = get_process_pid(cpu, h);
                auto pidp = get_process_pid(cpu, &p.handle);
                assert(pidh == pidp);
            }
            assert(p.handle.taskd == h->taskd);

            return std::forward_as_tuple(h, p, found);
        }
        assert(false && "reached unexpected control flow state");
    }

    /**
     * @brief Returns stored information about the specified process.
     * Asserts that the information already exists.
     */
    inline process_info_t &procinfo_by_taskd(target_ptr_t taskd) {
       auto ps_it = ps.find(taskd);
       assert(ps_it != ps.end());
       return ps_it->second;
    }

    /**
     * @brief Returns stored information about the specified process.
     * Asserts that the information already exists.
     */
    inline process_info_t &procinfo_by_pid(target_pid_t pid) {
        for(auto &ps_it : ps) {
            process_info_t &p = ps_it.second;
            if (p.pid == pid) return p;
        }

        // g++ is smart enough to not require a return after this
        LOG_ERROR("Failed to find process with pid " TARGET_PID_FMT, pid);
        assert(false && "failed to find process by pid");
    }

    /**
     * @brief Returns the information about the process with the
     * specified asid. A full scan of the current process list is
     * performed for this.
     * The process information map \p ps and the asid to taskd map
     * \p asids are also updated.
     *
     * @note Currently we retrieve the full process list and scan for
     * the specified asid. This can be simplified by adding to osi
     * an api call that retrieves one handle by asid.
     *
     * @note This method is currently only used for debug purposes.
     */
    inline process_info_t *AddNewByASID(CPUState *cpu, target_ptr_t asid) {
        GArray *handles = get_process_handles(cpu);
        assert(handles != nullptr && handles->len > 0);
        LOG_DEBUG("scanning %d processes for new process with asid="
                  TARGET_PTR_FMT, handles->len, asid);
        for (uint32_t i = 0; i < handles->len; i++) {
            OsiProcHandle *h = &g_array_index(handles, OsiProcHandle, i);
            // kernel process
            if (h->asid == ASID0) { continue; }

            // asid not matching
            if (h->asid != asid) { continue; }

            // asid matching - get or create process_info_t entry
            auto ps_it = ps.lower_bound(h->taskd);
            bool found = (ps_it != ps.end() && ps_it->first == h->taskd);
            if (!found) {
                LOG_DEBUG("CREATED");
                ps_it = ps.emplace_hint(ps_it, std::piecewise_construct,
                                        std::forward_as_tuple(h->taskd),
                                        std::forward_as_tuple(cpu, h));
                process_info_t &p = ps_it->second;
                auto emplaced_a2t = asids.emplace(h->asid, h->taskd);
                assert(emplaced_a2t.second);
                g_array_free(handles, true);
                return &p;
            } else {
                LOG_DEBUG("RECYCLED");
                process_info_t &p = ps_it->second;
                p.reset(cpu, h);
                auto emplaced_a2t = asids.emplace(h->asid, h->taskd);
                assert(emplaced_a2t.second);
                g_array_free(handles, true);
                return &p;
            }
            assert(false && "reached unexpected control flow state");
        }
        LOG_WARNING("no new process with asid=" TARGET_PTR_FMT, asid);
        g_array_free(handles, true);
        return nullptr;
    }

    inline process_info_t *AddNewByPPID(CPUState *cpu, target_pid_t ppid) {
        GArray *handles = get_process_handles(cpu);
        assert(handles != nullptr && handles->len > 0);
        LOG_DEBUG("scanning %d processes for new process with ppid="
                  TARGET_PID_FMT, handles->len, ppid);
        for (uint32_t i = 0; i < handles->len; i++) {
            OsiProcHandle *h = &g_array_index(handles, OsiProcHandle, i);
            // kernel process
            if (h->asid == ASID0) { continue; }

            // ppid not matching
            target_pid_t hppid = get_process_ppid(cpu, h);
            if (hppid != ppid) { continue; }

            // ppid matching - get or create process_info_t entry
            auto ps_it = ps.lower_bound(h->taskd);
            bool found = (ps_it != ps.end() && ps_it->first == h->taskd);
            if (!found) {
                ps_it = ps.emplace_hint(ps_it, std::piecewise_construct,
                                        std::forward_as_tuple(h->taskd),
                                        std::forward_as_tuple(cpu, h));
                process_info_t &p = ps_it->second;
                p = ps_it->second;
                auto emplaced_a2t = asids.emplace(h->asid, h->taskd);
                assert(emplaced_a2t.second);
                g_array_free(handles, true);
                return &p;
            } else if (ps_it->second.fsm.state == LPFSM::State::END) {
                // reset ended process
                process_info_t &p = ps_it->second;
                p.reset(cpu, h);
                auto emplaced_a2t = asids.emplace(h->asid, h->taskd);
                assert(emplaced_a2t.second);
                g_array_free(handles, true);
                return &p;
            } else if (ps_it->second.fsm.state == LPFSM::State::KERN) {
                // reset (presumably) ended kernel process
                process_info_t &p = ps_it->second;
                p.reset(cpu, h, true);
                auto emplaced_a2t = asids.emplace(h->asid, h->taskd);
                assert(emplaced_a2t.second);
                g_array_free(handles, true);
                return &p;
            } else if (ps_it->second.fsm.state == LPFSM::State::INIT) {
                // created by recent clone() by the same parent - ignore
                continue;
            } else if (ps_it->second.fsm.state == LPFSM::State::RUN) {
                // running process with the same parent - ignore
                continue;
            }
            assert(false && "reached unexpected control flow state");
        }
        LOG_WARNING("no new process with ppid=" TARGET_PID_FMT, ppid);
        g_array_free(handles, true);
        return nullptr;
    }

    /**
     * @brief Checks if the state maintained by the class is in sync with the
     * live state. Returns the number of inconsistencies found.
     */
    int check(CPUState *cpu) {
#if PANDA_LOG_LEVEL >= PANDA_LOG_DEBUG
        process_map_t stale = ps;
        std::vector<uint32_t> missing;
        std::vector<uint32_t> inconsistent;
        uint32_t nerrors = 0;

        GArray *handles = get_process_handles(cpu);
        for (uint32_t i = 0; i < handles->len; i++) {
            OsiProcHandle *h = &g_array_index(handles, OsiProcHandle, i);
            auto stale_it = stale.find(h->taskd);
            if (stale_it == stale.end()) {
               missing.push_back(i);
            } else {
                process_info_t &p = stale_it->second;
                if (p.handle.asid != h->asid || p.handle.taskd != h->taskd) {
                    inconsistent.push_back(i);
                }
                stale.erase(stale_it);
            }
        }
#if 0
        if (stale.size() > 0) {
            nerrors += stale.size();
            for(auto &stale_it : stale) {
                process_info_t &p = stale_it.second;
                // +++
            }
        }
        if (missing.size() > 0) {
            nerrors += missing.size();
            for(uint32_t i : missing) {
                OsiProcHandle *h = &g_array_index(handles, OsiProcHandle, i);
                // +++
            }
        }
        if (inconsistent.size() > 0) {
            nerrors += inconsistent.size();
            for(uint32_t i : inconsistent) {
                OsiProcHandle *h = &g_array_index(handles, OsiProcHandle, i);
                process_info_t &p = ps[h->taskd];
                // +++
            }
        }
#endif
        g_array_free(handles, true);
        return nerrors;
#else
        LOG_WARNING("Consistency checking skipped for this log level.");
        return 0;
#endif
    }

   private:
    bool initialized_ = false;
};

/* vim:set tabstop=4 softtabstop=4 expandtab: */
