#include "osi_proc_events.h"

extern "C" {
#include <osi_int_fns.h>
}

#include <glib.h>
#include <string.h>
#include <algorithm>
#include <iterator>
#include <set>
#include <map>

/*! @brief The global process state. */
ProcState pstate;

/*! @brief Constructor. */
ProcState::ProcState(void) {
	this->pid_set = new PidSet();
	this->proc_map = new ProcMap();
	return;
}

/*! @brief Destructor. */
ProcState::~ProcState(void) {
	if (this->pid_set != NULL) delete this->pid_set;
	if (this->proc_map != NULL) delete this->proc_map;

	// This destructor is called at the end of the replay.
	// Calling free_osiprocs() may cause a segfault at that point.
	// Use the generic inline.
	free_osiprocs_g(this->ps);
}

/*! @brief Gets a subset of the processes in `ProcMap`. */
OsiProcs *ProcState::OsiProcsSubset(ProcMap *m, PidSet *s) {
	int notfound = 0;
	OsiProcs *ps = (OsiProcs *)g_malloc0(sizeof(OsiProcs));

	ps->proc = g_new0(OsiProc, s->size());
	for (auto it=s->begin(); it!=s->end(); ++it) {
		auto p_it = m->find(*it);
		if (unlikely(p_it == m->end())) {
			notfound++;
			continue;
		}
		copy_osiproc_g(p_it->second, &ps->proc[ps->num]);
		ps->num++;
	}

	if (unlikely(notfound > 0)) LOG_WARN("PEVT: Process mapt didn't include %d processes of the requested subset.", notfound);

	if (ps->num == 0) goto error;

	return ps;

error:
	free_osiprocs(ps);
	return NULL;
}

/*! @brief Updates the ProcState with the new process set.
 * If `in` and `out` are not NULL, the new and finished processes
 * will be returned through them.
 *
 * @note For efficiency (i.e. to avoid an additional copy),
 * the passed `ps` becomes part of the ProcState.
 * Therefore, it must not be freed by the caller.
 */
void ProcState::update(OsiProcs *ps, OsiProcs **in, OsiProcs **out){
	PidSet *pid_set_new = new PidSet();
	ProcMap *proc_map_new = new ProcMap();

	// copy data to c++ containers
#ifdef PROC_EVENTS_DBG
	printf("*+**********\n");
#endif
	for (unsigned int i=0; i<ps->num; i++) {
		OsiProc *p = &ps->proc[i];
		target_ulong asid = p->asid;

		// Address Space identifier for all kernel tasks is 0.
		// This is because they have no mm struct associated with them.
		// Skip them.
		if (asid == 0) continue;

#ifdef PROC_EVENTS_DBG
		printf("*\t%-10s\t" TARGET_FMT_lu "\t" TARGET_FMT_lu "\t" TARGET_FMT_lx "\n", p->name, p->pid, p->ppid, p->asid);
#endif

		pid_set_new->insert(asid);
		auto ret = proc_map_new->insert(std::make_pair(asid, p));

		// ret type is pair<iterator, bool>
		if (!ret.second && (asid != 0)) {
			LOG_INFO("DUP " TARGET_FMT_lu " %s/%s", asid, ((*(ret.first)).second->name), p->name);
		}
	}
#ifdef PROC_EVENTS_DBG
	printf("*+**********\n");
#endif

	// extract OsiProcs
	if (likely(in != NULL && out != NULL)) {
		// free old data
		if (*in != NULL) free_osiprocs(*in);
		if (*out != NULL) free_osiprocs(*out);

		// find the pids of incoming/outgoing process
		PidSet pid_in, pid_out;
		std::set_difference(
			pid_set_new->begin(), pid_set_new->end(),
			this->pid_set->begin(), this->pid_set->end(),
			std::inserter(pid_in, pid_in.begin())
		);
		std::set_difference(
			this->pid_set->begin(), this->pid_set->end(),
			pid_set_new->begin(), pid_set_new->end(),
			std::inserter(pid_out, pid_out.begin())
		);

		*in = ProcState::OsiProcsSubset(proc_map_new, &pid_in);
		*out = ProcState::OsiProcsSubset(this->proc_map, &pid_out);
	}

	// update ProcState
	delete this->pid_set;
	delete this->proc_map;
	free_osiprocs(this->ps);
	this->pid_set = pid_set_new;
	this->proc_map = proc_map_new;
	this->ps = ps;

	return;
}

/*!
 * @brief C wrapper for updating the global process state.
 */
void procstate_update(OsiProcs *ps, OsiProcs **in, OsiProcs **out) {
	pstate.update(ps, in, out);
}

