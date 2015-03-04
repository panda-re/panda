// Branden Clark
// Tests the pmemacces patch

// Includes
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "panda_plugin.h"
#include "cpus.h"
#include "memory-access.h"

// Definitions
#define PLUGIN_NAME "pmemaccess"
#define PLUGIN_ARG_PATH_KEY "path"
#define PLUGIN_ARG_PROFILE_KEY "profile"
#define PLUGIN_ARG_COMMAND_KEY "command"
#define PLUGIN_ARG_MODE_KEY "mode"

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
int RR_before_block_exec(CPUState *env, TranslationBlock *tb);

// Globals
char *socket_path = NULL;
char *volatility_profile = NULL;
char *volatility_command = NULL;
char pmemaccess_mode = -1;
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
  sleep(10);

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

int RR_before_block_exec(CPUState *env, TranslationBlock *tb) {
  FILE *fp;
  int status;
  char tmp_buf[PATH_MAX];
  static int exec_once = 0;
  int tries = 0;
  // We only want to run volatility once
  if (exec_once)
    return 0;
  exec_once = 1;
  // Setup the volatility command
  memset(tmp_buf, 0, PATH_MAX);
  snprintf(tmp_buf, PATH_MAX, "python ~/git/volatility/vol.py -f %s --profile=%s %s",
           socket_path, volatility_profile, volatility_command);
  printf("PMemAccess: Will popen(%s)\n", tmp_buf);
  // Start volatility
  fp = popen(tmp_buf, "r");
  if (fp == NULL) {
    printf("PMemAccess: Error running volatility\n");
    return 0;
  }
  // Wait for output
  for (tries = 0; tries < 10; tries++) {
    while (fgets(tmp_buf, PATH_MAX, fp) != NULL) {
      printf("%s", tmp_buf);
      // break outer loop
      tries = 10;
    }
    sleep(1);
  }
  // Exit
  status = pclose(fp);
  if (status == -1) {
    printf("PMemAccess: pclose() error.\n");
  } else {
    printf("PMemAccess: Volatility finished.\n");
  }

  return 0;
}

bool init_plugin(void *self)
{
  int i = 0;

  // Find the plugin args and make a local copy
  panda_arg_list *pargs = panda_get_args(PLUGIN_NAME);
  for (i = 0; i < pargs->nargs; i++) {
    if(!strcmp(PLUGIN_ARG_PATH_KEY, pargs->list[i].key)) {
      socket_path = (char *)malloc(strlen(pargs->list[i].value)+1);
      strncpy(socket_path, pargs->list[i].value, strlen(pargs->list[i].value)+1);
    } else if (!strcmp(PLUGIN_ARG_PROFILE_KEY, pargs->list[i].key)) {
      volatility_profile = calloc(strlen(pargs->list[i].value)+1, sizeof(char));
      strncpy(volatility_profile, pargs->list[i].value, strlen(pargs->list[i].value)+1);
    } else if (!strcmp(PLUGIN_ARG_COMMAND_KEY, pargs->list[i].key)) {
      volatility_command = calloc(strlen(pargs->list[i].value)+1, sizeof(char));
      strncpy(volatility_command, pargs->list[i].value, strlen(pargs->list[i].value)+1);
    } else if (!strcmp(PLUGIN_ARG_MODE_KEY, pargs->list[i].key)) {
      pmemaccess_mode = atoi(pargs->list[i].value);
    }
  }
  if (socket_path == NULL) {
    printf("PMemAccess: %s argument not found\n", PLUGIN_ARG_PATH_KEY);
    return false;
  }
  if (pmemaccess_mode == -1) {
    printf("PMemAccess: %s argument not found\n", PLUGIN_ARG_MODE_KEY);
    return false;
  }
  if (pmemaccess_mode == 1 && volatility_profile == NULL) {
    printf("PMemAccess: %s argument not found\n", PLUGIN_ARG_PROFILE_KEY);
    return false;
  }
  if (pmemaccess_mode == 1 && volatility_command == NULL) {
    printf("PMemAccess: %s argument not found\n", PLUGIN_ARG_COMMAND_KEY);
    return false;
  }

  // Start the memory access socket
  memory_access_start(socket_path);

  // Free PANDA's copy
  panda_free_args(pargs);

  switch (pmemaccess_mode) {
    case 0: // Spawn the test thread
      pthread_create(&tid, NULL, &test_mem_access, NULL);
      break;
    case 1: ;// Test RR access with callback
      panda_cb pcb = {.before_block_exec = RR_before_block_exec };
      panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
      break;
    default:
      break;
  }

  return true;
}

bool uninit_plugin(void *self)
{
  free(socket_path);
  pthread_cancel(tid);

  return true;
}
