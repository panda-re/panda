#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
/*
 * Statically linked, have tested against libc and uClibc
 * Communicates with the KernelInfo PyPlugin to exercise kernel functions and 
 * read /proc/
 *
 * This whole thing is a brutal hack and I am not proud of it
 */

//Use the string "KERNELINFO:" to have PANDA catch recognize our output from 
//sys_write... implies you must start with a const char
#define OUTPUT(...) printf( "KERNELINFO: " __VA_ARGS__)

//Use the string "PANDA:" to communicate some information to the PANDA plugin
//that we will use to derive some information
#define PANDA(...) printf( "PANDA: " __VA_ARGS__)

//Some globals for file IO
FILE *fp;
#define BUF_LEN 1024
char buf[BUF_LEN];

//For strtok
#define DELIM " \t"

//From /proc/slabinfo, object_size is the third field
#define OBJSIZE_FIELD 3


//Totally safe function for grabbing fields from files, assuming we've started
//strtok
static inline void get_field(char *tok, const char *field,
                             const char *output_name, int no) {
    int i;
    if(!strncmp(tok, field, strlen(field))) {
        for(i=0; i<no; i++) {
            tok = strtok(NULL, DELIM);
            if(tok==NULL)
                break;
            if(i==no-1) {
                OUTPUT("%s %s\n",output_name, tok);
                break;
            }
        }
    }
}

//These should be stable across kernel versions
static inline void send_task_struct() {
    fp = fopen("/proc/self/syscall", "r");
    fgets(buf, BUF_LEN, fp);//Don't care about contents, just need to read
    fclose(fp);
}

static inline void send_mm_struct() {
    fp = fopen("/proc/self/status", "r");
    fgets(buf, BUF_LEN, fp);//Don't care about contents, just need to read
    fclose(fp);
}

//Creates a couple of child processes to find task struct offsets
//Probably fragile due to inherent race conditions and dependence on sleep for 
//ordering
static inline void find_tasks_offset() {
    pid_t pid1, pid2;

    //First, send the parent process pid
    PANDA("parent_pid: %d\n", getpid());
    send_mm_struct();
    send_task_struct();

    pid1 = fork();
    if(pid1) 
        pid2 = fork();
    if(!pid1 || !pid2) {
        sleep(5);
        //pid2 lives a little longer and sends its struct a little later
        if(!pid2)
            sleep(1);
        send_task_struct();
        sleep(5);
        exit(0);
    }
    PANDA("pids: %d %d\n", pid1, pid2);
}

int main() {
    char *line, *tok;
    size_t n;
    ssize_t nread;
    int status;

    /*BEGIN get struct sizes from /proc/slabinfo*/
    fp = fopen("/proc/slabinfo", "r");
    while(fgets(buf, BUF_LEN, fp)) {
        tok = strtok(buf, DELIM);
        get_field(tok, "task_struct", "task.size", OBJSIZE_FIELD);
        get_field(tok, "mm_struct", "mm.size", OBJSIZE_FIELD);
        get_field(tok, "vm_area_struct", "vma.size", OBJSIZE_FIELD);
    }
    fclose(fp);
    /*END get struct sizes from /proc/slabinfo*/

    /*Now find task.tasks_offset, this is probably fragile*/
    //First, send init's task struct to PANDA
    fp = fopen("/proc/1/syscall", "r");
    fgets(buf, BUF_LEN, fp);//Don't care about contents, just need to read
    fclose(fp);
        
    find_tasks_offset();
    wait(&status);    

    //Now send a file struct via dup_fd in fork()
    fork();
    sleep(1);

    return 0;
}
