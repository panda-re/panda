#ifndef HW_AVATAR_CONFIGURABLE_MACHINE_H
#define HW_AVATAR_CONFIGURABLE_MACHINE_H

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// from panda_api.c

QObject * configurable_get_peripheral(char * name);
void configurable_a9mp_inject_irq(void *opaque, int irq, int level);


// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
#endif
