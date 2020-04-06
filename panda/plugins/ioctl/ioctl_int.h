/*
 * Per the below:
 * https://github.com/panda-re/panda/blob/c16aa91354596241a21f9b9f5897ed279e7a6155/panda/plugins/hooks/hooks_int.h#L1
 *
 * pycparser doesn't like certain function pointers, so we enable the pypanda API but NOT the C plugin-to-plugin API
 */

/*
typedef void CPUState;
typedef void uint32_t;

typedef void ioctl_cmd_t;
typedef void ioctl_t;

#include "ioctl_int_fns.h"
*/