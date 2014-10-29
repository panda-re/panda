#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include "panda_mark.h"

#define READ_END  0
#define WRITE_END 1
#define BUFFER_SIZE 100

int main(int argc, char *argv[])
{
    int fd[2];
    pid_t pid;

    if (pipe(fd) == -1) {
        fprintf(stderr, "Pipe failed");
        exit(EXIT_FAILURE);
    }

    if ((pid = fork()) < 0) {
        fprintf(stderr, "Fork error");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) { /* The parent will label the buffer then write to the pipe */
        char buffer[BUFFER_SIZE] = "The quick brown fox jumped over the lazy dog";

        printf("Parent Buffer: %s\n", buffer);

        label_buffer((uint64_t)&buffer, BUFFER_SIZE);

        close(fd[READ_END]); /* Close the unused end of the pipe */
        if (write(fd[WRITE_END], buffer, BUFFER_SIZE) < 0) {
            fprintf(stderr, "Parent: Error writing to pipe.\n");
            exit(EXIT_FAILURE);
        }

        close(fd[WRITE_END]);
    } else { /* The child will read from the pipe then query the buffer */
        char inbuf[BUFFER_SIZE];

        close(fd[WRITE_END]); /* Close the unused end of the pipe */
        if(read(fd[READ_END], inbuf, BUFFER_SIZE) < 0) {
            fprintf(stderr, "Child: Error reading from pipe.\n");
            exit(EXIT_FAILURE);
        }
        close(fd[READ_END]);

        printf("Child Buffer: %s\n", inbuf);

        query_buffer((uint64_t)&inbuf, BUFFER_SIZE);
    }
    return 0;
}
