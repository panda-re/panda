Plugin: sample
===========

Summary
-------

Arguments
---------



Dependencies
------------

sample/sample_ext.h:static inline bool init_sample_api(void);static inline bool init_sample_api(void){

APIs and Callbacks
------------------




typedef void CPUState;

#include "sample_int_fns.h"


#ifndef __SAMPLE_INT_FNS_H__
#define __SAMPLE_INT_FNS_H__

int sample_function(CPUState *env);

int other_sample_function(CPUState *env, int foo);

#endif // __SAMPLE_INT_FNS_H__

Example
-------

