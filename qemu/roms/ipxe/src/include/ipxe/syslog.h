#ifndef _IPXE_SYSLOG_H
#define _IPXE_SYSLOG_H

/** @file
 *
 * Syslog protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

/** Syslog server port */
#define SYSLOG_PORT 514

/** Syslog line buffer size
 *
 * This is a policy decision
 */
#define SYSLOG_BUFSIZE 128

/** Syslog facility
 *
 * This is a policy decision
 */
#define SYSLOG_FACILITY 0 /* kernel */

/** Syslog severity
 *
 * This is a policy decision
 */
#define SYSLOG_SEVERITY 6 /* informational */

/** Syslog priority */
#define SYSLOG_PRIORITY( facility, severity ) ( 8 * (facility) + (severity) )

#endif /* _IPXE_SYSLOG_H */
