// Branden Clark
// Tests the pmemacces patch

// Includes
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "panda/plugin.h"
#include "memory-access.h"
#include <sys/select.h>

// Definitions
#define PLUGIN_NAME "pmemaccess"
#define PLUGIN_ARG_PATH_KEY "path"
#define PLUGIN_ARG_PROFILE_KEY "profile"
#define PLUGIN_ARG_COMMAND_KEY "command"
#define PLUGIN_ARG_MODE_KEY "mode"
#define PLUGIN_ARG_DUMP_FILE_KEY "dump"

/*
 * Acess guest physical memory via a domain socket.
 *
 * Copyright (C) 2011 Sandia National Laboratories
 * Author: Bryan D. Payne (bdpayne@acm.org)
 */

//#include "memory-access.h"
//#include "cpu-all.h"
// RYAN REMOVED THESE
//#include "qemu-common.h"
//#include "cpu-common.h"
//#include "config.h"

// RYAN ADDED THIS
//#include "panda/plugin.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>

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

static uint64_t
connection_read_memory (uint64_t user_paddr, void *buf, uint64_t user_len)
{
    hwaddr paddr = (hwaddr) user_paddr;
    hwaddr len = (hwaddr) user_len;
    void *guestmem = cpu_physical_memory_map(paddr, &len, 0);
    if (!guestmem){
        return 0;
    }
    memcpy(buf, guestmem, len);
    cpu_physical_memory_unmap(guestmem, len, 0, len);
    return len;
}

static uint64_t
connection_write_memory (uint64_t user_paddr, void *buf, uint64_t user_len)
{
    hwaddr paddr = (hwaddr) user_paddr;
    hwaddr len = (hwaddr) user_len;
    void *guestmem = cpu_physical_memory_map(paddr, &len, 1);
    if (!guestmem){
        return 0;
    }
    memcpy(guestmem, buf, len);
    cpu_physical_memory_unmap(guestmem, len, 0, len);

    return len;
}

static void
send_success_ack (int connection_fd)
{
    uint8_t success = 1;
    int nbytes = write(connection_fd, &success, 1);
    if (1 != nbytes){
        printf("QemuMemoryAccess: failed to send success ack\n");
    }
}

static void
send_fail_ack (int connection_fd)
{
    uint8_t fail = 0;
    int nbytes = write(connection_fd, &fail, 1);
    if (1 != nbytes){
        printf("QemuMemoryAccess: failed to send fail ack\n");
    }
}

static void
connection_handler (int connection_fd)
{
    int nbytes;
    struct request req;
    while (1){
        // client request should match the struct request format
        //printf("Reading?\n");
        /*fd_set set;
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;
        FD_ZERO(&set);
        FD_SET(connection_fd, &set);
        int rv = select(connection_fd, &set, NULL, NULL, &timeout);
        if(rv == -1 || rv == 0) {
          time_count++;
          //send_fail_ack(connection_fd);
          printf("Timed out, retrying\n");
          nbytes = write(connection_fd, "\x00", req.length + 1);
          continue;
        }*/
        
        nbytes = read(connection_fd, &req, sizeof(struct request));
        
        if (nbytes != sizeof(struct request)){
            // error
            //printf("Error reading request, read 0x%x bytes instead of 0x%lx\n", nbytes, sizeof(struct request));
            continue;
        }
        else if (req.type == 0){
            //printf("Quit requested\n");
            // request to quit, goodbye
            break;
        }
        else if (req.type == 1){
            // request to read
            char *buf = malloc(req.length + 1);
            nbytes = connection_read_memory(req.address, buf, req.length);
            //printf("Reading addr %lx\n", req.address);
            if (nbytes != req.length){
                // read failure, return failure message
                //printf("Failed to read %lx, sending 0\n", req.address);
                buf[req.length] = 0; // set last byte to 0 for failure
                nbytes = write(connection_fd, buf, req.length + 1);
            }
            else{
                // read success, return bytes
                buf[req.length] = 1; // set last byte to 1 for success
                nbytes = write(connection_fd, buf, req.length + 1);
            }
            free(buf);
        }
        else if (req.type == 2){
            // request to write
            //printf("Writing?\n");
            void *write_buf = malloc(req.length);
            nbytes = read(connection_fd, write_buf, req.length);
            if (nbytes != req.length){
                // failed reading the message to write
                send_fail_ack(connection_fd);
            }
            else{
                // do the write
                nbytes = connection_write_memory(req.address, write_buf, req.length);
                if (nbytes == req.length){
                    send_success_ack(connection_fd);
                }
                else{
                    send_fail_ack(connection_fd);
                }
            }
            free(write_buf);
        }
        else if (req.type == 3) {
          // request for ram size
          unsigned char bytes[sizeof(ram_size)];
          for(int i = sizeof(ram_size); i > 0; i--) {
            bytes[sizeof(ram_size) - i] = (ram_size) >> i * 8 & 0xff;
          }
          //printf("RAMSIZE: %lx\n", ram_size);
          //for(int b = 0; b<sizeof(ram_size); b++) {
          //  printf("%x", (int)bytes[b]);
          //}
          //printf("\n");
          nbytes = write(connection_fd, bytes, sizeof(ram_size));
          exit(-1);
        }
        else{
            // unknown command
            printf("QemuMemoryAccess: ignoring unknown command (%d)\n", req.type);
            char *buf = malloc(1);
            buf[0] = 0;
            nbytes = write(connection_fd, buf, 1);
            free(buf);
        }

    }
    printf("Closing connection\n");
    close(connection_fd);
}

static void *
connection_handler_gate (void *fd)
{
  connection_handler(*(int *)fd);
  //printf("QemuMemoryAccess: Connection done (%d)\n", *(int *)fd);
  free(fd);
  return NULL;
}

static void *
memory_access_thread (void *path)
{
    struct sockaddr_un address;
    int socket_fd, connection_fd, *tmp_fd;
    pthread_t thread;
    socklen_t address_length;

    socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0){
        printf("QemuMemoryAccess: socket failed\n");
        goto error_exit;
    }
    unlink(path);
    address.sun_family = AF_UNIX;
    address_length = sizeof(address.sun_family) + sprintf(address.sun_path, "%s", (char *) path);

    if (bind(socket_fd, (struct sockaddr *) &address, address_length) != 0){
        printf("QemuMemoryAccess: bind failed\n");
        goto error_exit;
    }
    if (listen(socket_fd, 0) != 0){
        printf("QemuMemoryAccess: listen failed\n");
        goto error_exit;
    }
    while (true) {
      connection_fd = accept(socket_fd, (struct sockaddr *) &address, &address_length);
      printf("QemuMemoryAccess: Connection accepted on %d.\n", connection_fd);
      tmp_fd = (int *) calloc(1, sizeof(int));
      *tmp_fd = connection_fd;
      pthread_create(&thread, NULL, connection_handler_gate, tmp_fd);
    }
    printf("Closing socket and unlinking path\n");
    close(socket_fd);
    unlink(path);
error_exit:
    return NULL;
}

int
memory_access_start (const char *path)
{
    pthread_t thread;
    sigset_t set, oldset;
    int ret;

    // create a copy of path that we can safely use
    char *pathcopy = malloc(strlen(path) + 1);
    memcpy(pathcopy, path, strlen(path) + 1);

    // start the thread
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, &oldset);
    ret = pthread_create(&thread, NULL, memory_access_thread, pathcopy);
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);

    return ret;
}

// Prototypes
bool init_plugin(void *self);
bool uninit_plugin(void *self);

void *test_mem_access(void *arg);
void RR_before_block_exec(CPUState *env, TranslationBlock *tb);

void *read_all(void *arg);

// Globals
char *socket_path = NULL;
char *volatility_profile = NULL;
char *volatility_command = NULL;
char pmemaccess_mode = -1;
char *dump_file = NULL;
pthread_t tid;


void *read_all(void *arg)
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
    if (connect(sock, (struct sockaddr *)&saddr, strlen(saddr.sun_path)+sizeof(saddr.sun_family)) == -1) { 
      printf("PMemAccess: connect failed\n");
      perror("connect");
      retry++;
    } else {
      break;
    }
    sleep(1);
  }
  if (retry == 10)
    return NULL;

  int block_len = 1024;
  buf = (char *)calloc(block_len+1, sizeof(char));

  int addr = 0;

  FILE *f = fopen(dump_file, "wb");
  if(f== NULL){
    printf("Error opening file\n");
    exit(1);
  }
  
  while (addr < ram_size) {
    req.type = REQ_READ;
    req.length = block_len;
    req.address = addr;
    num_bytes = write(sock, &req, sizeof(struct request));
    if (num_bytes != sizeof(struct request)){
          goto read_fail;
    }
    num_bytes = read(sock, buf, block_len+1);
    if (buf[block_len] == 1 && num_bytes != sizeof(struct request)){
      fwrite(&buf[0], 1, block_len, f);
      }
    else {
      read_fail:
      addr+= block_len;
      continue;
    }
    addr+=block_len;
  }
  return NULL;
}

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
    if (connect(sock, (struct sockaddr *)&saddr, strlen(saddr.sun_path)+sizeof(saddr.sun_family)) == -1) { 
      printf("PMemAccess: connect failed\n");
      perror("connect");
      retry++;
    } else {
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
void * _self;
panda_cb pcb2;

void RR_before_block_exec(CPUState *env, TranslationBlock *tb) {
  FILE *fp;
  int status;
  char tmp_buf[PATH_MAX];
  int tries = 0;
  // We only want to run volatility once
  panda_disable_callback(_self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb2);
  //printf("Dumping memory in callback\n");
  //read_all(NULL);
  //printf("Done\n");
  //return;
  // spin until dump_file is created
  /*while(access(dump_file, F_OK)) {
    sleep(0.1);
  }
  FILE *f = fopen(dump_file, "wb");
  
  int fsz = 0;
  while(fsz < 1000000000) {
    fseek(f, 0L, SEEK_END);
    fsz = ftell(f);
    rewind(f);
  }*/

  // Setup the volatility command
  memset(tmp_buf, 0, PATH_MAX);
  //snprintf(tmp_buf, PATH_MAX, "python3 ~/volatility/vol.py -f %s --profile=%s %s",
  //         dump_file, volatility_profile, volatility_command);
  snprintf(tmp_buf, PATH_MAX, "python3 ~/volatility/vol.py -f %s --profile=%s %s",
           socket_path, volatility_profile, volatility_command);
  printf("PMemAccess: Will popen(%s)\n", tmp_buf);
  // Start volatility
  fp = popen(tmp_buf, "r");
  if (fp == NULL) {
    printf("PMemAccess: Error running volatility\n");
    return;
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
  }

  return;
}

bool init_plugin(void *self)
{
  int i = 0;
  _self = self;
  // Find the plugin args and make a local copy
  panda_arg_list *pargs = panda_get_args(PLUGIN_NAME);
  for (i = 0; i < pargs->nargs; i++) {
    if(!strcmp(PLUGIN_ARG_PATH_KEY, pargs->list[i].key)) {
      socket_path = (char *)malloc(strlen(pargs->list[i].value)+1);
      memcpy(socket_path, pargs->list[i].value, strlen(pargs->list[i].value)+1);
    } else if (!(strcmp(PLUGIN_ARG_DUMP_FILE_KEY, pargs->list[i].key))) {
      dump_file = (char *)malloc(strlen(pargs->list[i].value)+1);
      memcpy(dump_file, pargs->list[i].value, strlen(pargs->list[i].value)+1);
    } else if (!strcmp(PLUGIN_ARG_PROFILE_KEY, pargs->list[i].key)) {
      volatility_profile = calloc(strlen(pargs->list[i].value)+1, sizeof(char));
      memcpy(volatility_profile, pargs->list[i].value, strlen(pargs->list[i].value)+1);
    } else if (!strcmp(PLUGIN_ARG_COMMAND_KEY, pargs->list[i].key)) {
      volatility_command = calloc(strlen(pargs->list[i].value)+1, sizeof(char));
      memcpy(volatility_command, pargs->list[i].value, strlen(pargs->list[i].value)+1);
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
  else {
    printf("Creating dumpfile %s\n", dump_file);
  }

  // Start the memory access socket
  memory_access_start(socket_path);

  // Free PANDA's copy
  panda_free_args(pargs);
  pcb2.before_block_exec = RR_before_block_exec;
  switch (pmemaccess_mode) {
    case 0: // Spawn the test thread
      pthread_create(&tid, NULL, &test_mem_access, NULL);
      break;
    case 1: ;// Test RR access with callback
  
      panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb2);
      break;
    case 2:
      pthread_create(&tid, NULL, &read_all, NULL);
      break;
    case 3:
      panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb2);
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