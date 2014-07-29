

#ifndef __STRINGSEARCH_H_
#define __STRINGSEARCH_H_


#define MAX_STRINGS 16
#define MAX_STRLEN  256


// the type for the ppp callback fn that can be passed to string search to be called
// whenever a string match is observed
typedef void (* on_ssm_t)(CPUState *env, target_ulong pc, target_ulong addr,
			  uint8_t *matched_string, uint32_t matched_string_lenght, 
			  bool is_write);


#endif
