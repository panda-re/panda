// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

/**
 * Information about a given socket binding
 */
typedef struct SocketInfo {
  uint8_t ip[4];
  uint64_t pid;
  uint16_t port;
  bool server;
} SocketInfo;

/**
 * Request that a table of sockets be printed once guest execution resumes
 */
void print_socket_info(void);

/**
 * Provide a callback for receiving a socket list that will get called once the guest
 * resumes execution
 */
void on_get_socket_list(void (*callback)(const struct SocketInfo*, uintptr_t));

/**
 * Forward a socket from the guest, returning true if no issue is hit. Returns `false` if
 * the IP address fails to parse. A null IP address is treated as 0.0.0.0
 *
 * Guest must resume execution for an unspecified amount of time before TCP traffic
 * will actually be processed.
 */
bool forward_socket(const char *ip, uint16_t guest_port, uint16_t host_port);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
