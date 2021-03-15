#include "panda/rr/rr_api.h"
#include "panda/rr/rr_types.h"

bool rr_in_replay(void) { return rr_control.mode == RR_REPLAY; }
bool rr_in_record(void) { return rr_control.mode == RR_RECORD; }
bool rr_replay_requested(void) { return rr_control.next == RR_REPLAY; }
bool rr_record_requested(void) { return rr_control.next == RR_RECORD; }
bool rr_off(void) { return rr_control.mode == RR_OFF; }
bool rr_on(void) { return !rr_off(); }
