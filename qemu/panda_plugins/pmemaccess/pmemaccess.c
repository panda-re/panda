// Branden Clark
// Tests the pmemacces patch

// Includes
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "panda_plugin.h"
#include "memory-access.h"

// Definitions
#define PLUGIN_NAME "pmemaccess"
#define PLUGIN_ARG_KEY "path"

typedef enum {
  REQ_QUIT,
  REQ_READ,
  REQ_WRITE
} req_type_t;

struct request{
  uint8_t type;      // 0 quit, 1 read, 2 write, ... rest reserved
  uint64_t address;  // address to read from OR write to
  uint64_t length;   // number of bytes to read OR write
};

// Prototypes
bool init_plugin(void *self);
bool uninit_plugin(void *self);

void *test_mem_access(void *arg);

// Globals
char *socket_path = NULL;
pthread_t tid;

void *test_mem_access(void *arg)
{
  struct sockaddr_un saddr;
  struct request req;
  int sock = -1;
  int retry = 0;
  int num_bytes = 0;
  char *buf = NULL;

  // Wait for VM to boot a little
  sleep(20);

  // Setup socket
  saddr.sun_family = AF_UNIX;
  strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path)-1);
  saddr.sun_path[strlen(saddr.sun_path)] = '\0';

  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock == -1) {
    printf("PMemAccess: socket failed\n");
    perror("socket");
    return NULL;
  }

  // Connect to socket
  while (retry < 10) {
    printf("Connecting to %s\n", saddr.sun_path);
    if (connect(sock, (struct sockaddr *)&saddr, strlen(saddr.sun_path)+sizeof(saddr.sun_family)) == -1) { 
      printf("PMemAccess: connect failed\n");
      perror("connect");
      retry++;
    } else {
      printf("Success!!!\n");
      break;
    }
    sleep(1);
  }
  if (retry == 10)
    return NULL;

  /*** Run some tests ***/
  buf = (char *)calloc(8+1, sizeof(char));

  // 4 byte read
  req.type = REQ_READ;
  req.length = 4;
  req.address = 0xe540;
  num_bytes = write(sock, &req, sizeof(struct request));
  if (num_bytes != sizeof(struct request))
        goto read_fail;
  num_bytes = read(sock, buf, 4+1);
  if (buf[4] == 1 && num_bytes != sizeof(struct request))
    printf("STATUS: Read 4 success!\n");
  else {
    read_fail:
    printf("STATUS: Read 4 failure!\n");
    goto error_exit;
  }
  printf("Read: %x\n", ((int *)buf)[0]);
  // 4 byte write + read to verify
  sleep(10);
  req.type = REQ_WRITE;
  req.address = 0xe540;
  req.length = 4;
  num_bytes = write(sock, &req, sizeof(struct request));
  if (num_bytes != sizeof(struct request))
    goto write_fail;
  strncpy(buf, "AAAA", req.length);
  num_bytes = write(sock, buf, req.length);
  if (num_bytes != req.length)
      goto write_fail;
  memset(buf, 0, 5);
  num_bytes = read(sock, buf, 1);
  if (buf[0] == 1 && num_bytes == 1)
    printf("STATUS: Write 4 success!\n");
  else {
    write_fail:
    printf("STATUS: Write 4 failure!\n");
    goto error_exit;
  }
  // Verify data was written by reading it back
  req.type = REQ_READ;
  req.length = 4;
  req.address = 0xe540;
  memset(buf, 0, 5);
  num_bytes = write(sock, &req, sizeof(struct request));
  if (num_bytes != sizeof(struct request))
      goto verify_fail;
  num_bytes = read(sock, buf, req.length+1);
  printf("Verifying: %x\n", *(int *)buf);
  if (buf[4] == 1 && buf[0] == 'A' && num_bytes == req.length+1)
    printf("STATUS: Write 4 verified!\n");
  else {
    verify_fail:
    printf("STATUS: Write 4 verification failure!\n");
    goto error_exit;
  }

  free(buf);
error_exit:
  return NULL;
}

bool init_plugin(void *self)
{
  int i = 0;

  // Find the path argument
  panda_arg_list *pargs = panda_get_args(PLUGIN_NAME);
  for (i = 0; i < pargs->nargs; i++) {
    if(!strcmp(PLUGIN_ARG_KEY, pargs->list[i].key))
      break;
  }
  if (i == pargs->nargs) {
    printf("path argument not found\n");
    return false;
  }

  // Start the memory access socket
  memory_access_start(pargs->list[i].value);

  // Make a local copy for ourselves
  socket_path = (char *)malloc(strlen(pargs->list[i].value)+1);
  strncpy(socket_path, pargs->list[i].value, strlen(pargs->list[i].value)+1);

  // Free PANDA's copy
  panda_free_args(pargs);

  // Spawn the test thread
  pthread_create(&tid, NULL, &test_mem_access, NULL);

  return true;
}

bool uninit_plugin(void *self)
{
  free(socket_path);
  pthread_cancel(tid);

  return true;
}
