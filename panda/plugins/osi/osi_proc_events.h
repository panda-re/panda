#pragma once
#include "panda/plugin.h"
#include "osi_types.h"

/*!
 * @brief Branch prediction hint macros.
 */
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

/*!
 * @brief Debug macros.
 */
#define LOG_ERROR(fmt, args...) fprintf(stderr, "ERROR(%s:%s): " fmt "\n", __FILE__, __func__, ## args)
#define LOG_WARN(fmt, args...) fprintf(stderr, "WARN(%s:%s): " fmt "\n", __FILE__, __func__, ## args)
#define LOG_INFO(fmt, args...) fprintf(stderr, "INFO(%s:%s): " fmt "\n", __FILE__, __func__, ## args)
#define PRINT_CONTAINER(c, fmt, args...) do{\
	int _l = 0;\
	LOG_INFO("------- " #c " start -------");\
	for (auto it=(c)->begin(); it!=(c)->end(); ++it){\
		char _d = _l ? ' ' : '\t';\
		fprintf(stderr, "%c" fmt, _d, ## args);\
		_l = (_l + 1) % 10;\
		if (!_l) fprintf(stderr, "\n");\
	}\
	if (_l) fprintf(stderr, "\n");\
	LOG_INFO("-------- " #c " end --------\n");\
} while(0)

#ifdef __cplusplus
#include <set>
#include <unordered_map>
typedef std::set<target_ulong> PidSet;
typedef std::unordered_map<target_ulong, OsiProc *> ProcMap;

class ProcState {
	public:
		ProcState();
		~ProcState();
		void update(OsiProcs *ps, OsiProcs **in, OsiProcs **out);

	private:
		PidSet *pid_set = NULL;		/**< pids from previous run */
		ProcMap *proc_map = NULL;	/**< pid to OsiProc* map */
		OsiProcs *ps = NULL;		/**< the actual OsiProc structs pointed to by proc_map are contained here */
		static OsiProcs *OsiProcsSubset(ProcMap *, PidSet *);
		static OsiProc *OsiProcCopy(OsiProc *from, OsiProc *to);
};
#else
typedef struct ProcState ProcState;
#endif



#ifdef __cplusplus
extern "C" {
#endif

extern ProcState pstate;

/*!
 * @brief C wrapper for updating the global process state.
 */
void procstate_update(OsiProcs *ps, OsiProcs **in, OsiProcs **out);

#ifdef __cplusplus
}
#endif

