#ifndef __PANDA_OS_H__
#define __PANDA_OS_H__

// this stuff is defined / used in common.c

// NOTE: Pls read README before editing!

// this stuff is used by the new qemu cmd-line arg '-os os_name'
typedef enum OSFamilyEnum { OS_UNKNOWN, OS_WINDOWS, OS_LINUX } PandaOsFamily;

// these are set in panda/src/common.c via call to panda_set_os_name(os_name)
extern char *panda_os_name;           // the full name of the os, as provided by the user
extern char *panda_os_family;         // parsed os family
extern char *panda_os_variant;        // parsed os variant
extern uint32_t panda_os_bits;        // parsed os bits
extern PandaOsFamily panda_os_familyno; // numeric identifier for family


#endif
