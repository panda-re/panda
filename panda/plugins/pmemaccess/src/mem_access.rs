use std::env;
use std::os::unix::net::UnixStream;

/*
struct request{
    uint8_t type;      // 0 quit, 1 read, 2 write, ... rest reserved
    uint64_t address;  // address to read from OR write to
    uint64_t length;   // number of bytes to read OR write
};
*/
#[repr(C)]
pub struct Request {
    pub req_type: u8,
    pub address: target_ptr_t,
    pub length: target_ptr_t,
}
/*
static uint64_t
connection_read_memory (uint64_t user_paddr, void *buf, uint64_t user_len)
{
    target_phys_addr_t paddr = (target_phys_addr_t) user_paddr;
    target_phys_addr_t len = (target_phys_addr_t) user_len;
    void *guestmem = cpu_physical_memory_map(paddr, &len, 0);
    if (!guestmem){
        return 0;
    }
    memcpy(buf, guestmem, len);
    cpu_physical_memory_unmap(guestmem, len, 0, len);

    return len;
}
*/
pub fn connection_read_memory(padder: target_ptr_t, len: target_ptr_t)
{
    // Maybe this works? Need to think/test it actually, though.
    target_ptr_t::read_from_guest(padder, len).ok()?
    
}
/*
static uint64_t
connection_write_memory (uint64_t user_paddr, void *buf, uint64_t user_len)
{
    target_phys_addr_t paddr = (target_phys_addr_t) user_paddr;
    target_phys_addr_t len = (target_phys_addr_t) user_len;
    void *guestmem = cpu_physical_memory_map(paddr, &len, 1);
    if (!guestmem){
        return 0;
    }
    memcpy(guestmem, buf, len);
    cpu_physical_memory_unmap(guestmem, len, 0, len);

    return len;
} */
pub fn connection_write_memory(paddr: target_ptr_t, len: target_ptr_t) { 
    target_ptr_t::write_to_guest(paddr, len).ok()?
}
/*
static void
send_success_ack (int connection_fd)
{
    uint8_t success = 1;
    int nbytes = write(connection_fd, &success, 1);
    if (1 != nbytes){
        printf("QemuMemoryAccess: failed to send success ack\n");
    }
}*/
pub fn send_success_ack(stream: UnixStream) {
    match stream.write_str("Success!").ok() {
        Some(res) => (),
        None => println!("Failed to send success"),
    };
}
/*
static void
send_fail_ack (int connection_fd)
{
    uint8_t fail = 0;
    int nbytes = write(connection_fd, &fail, 1);
    if (1 != nbytes){
        printf("QemuMemoryAccess: failed to send fail ack\n");
    }
} */
pub fn send_fail_ack(stream: UnixStream) {
    match stream.write_str("Failed...").ok() {
        Some(res) => (),
        None => println!("Failed to fail"),
    };
}
/*static void
connection_handler (int connection_fd)
{
    int nbytes;
    struct request req;

    while (1){
        // client request should match the struct request format
        nbytes = read(connection_fd, &req, sizeof(struct request));
        if (nbytes != sizeof(struct request)){
            // error
            continue;
        }
        else if (req.type == 0){
            // request to quit, goodbye
            break;
        }
        else if (req.type == 1){
            // request to read
            char *buf = malloc(req.length + 1);
            nbytes = connection_read_memory(req.address, buf, req.length);
            if (nbytes != req.length){
                // read failure, return failure message
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
        else{
            // unknown command
            printf("QemuMemoryAccess: ignoring unknown command (%d)\n", req.type);
            char *buf = malloc(1);
            buf[0] = 0;
            nbytes = write(connection_fd, buf, 1);
            free(buf);
        }
    }

    close(connection_fd);
} */
pub fn connection_handler(stream: UnixStream) {
    let mut req: Request;
    while True {
        match nbytes = stream.read(&req).ok() {
            Some(res) => {
                if res == size_of(Request){
                    match req.req_type {
                        0 => break,
                        1 => {
                            /*
                            else if (req.type == 1){
                                // request to read
                                char *buf = malloc(req.length + 1);
                                nbytes = connection_read_memory(req.address, buf, req.length);
                                if (nbytes != req.length){
                                    // read failure, return failure message
                                    buf[req.length] = 0; // set last byte to 0 for failure
                                    nbytes = write(connection_fd, buf, req.length + 1);
                                }
                                else{
                                    // read success, return bytes
                                    buf[req.length] = 1; // set last byte to 1 for success
                                    nbytes = write(connection_fd, buf, req.length + 1);
                                }
                                free(buf);
                            } */
                            let mut buf: [u8];
                            connection_read_memory(req.address, req.length);
                        },
                        2 => {
                            connection_write_memory(req.address, len)
                        },
                    }
                }
            },
            None => println!("didn't it"),
        };
    }
}
/*

static void *
connection_handler_gate (void *fd)
{
  connection_handler(*(int *)fd);
  printf("QemuMemoryAccess: Connection done (%d)\n", *(int *)fd);
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
      printf("QemuMemoryAccess: Connction accepted on %d.\n", connection_fd);
      tmp_fd = (int *) calloc(1, sizeof(int));
      *tmp_fd = connection_fd;
      pthread_create(&thread, NULL, connection_handler_gate, tmp_fd);
    }

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
*/