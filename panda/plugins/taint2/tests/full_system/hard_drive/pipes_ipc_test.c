#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define READ_END  0
#define WRITE_END 1
#define BUFFER_SIZE 100

int main(int argc, char *argv[])
{
    int fd[2];
    pid_t pid;

    const char *inname  = argv[1];
    const char *outname = argv[2];

    if (argc != 3) {
        printf("usage: pipe_example input_file output_file\n");
        exit(EXIT_FAILURE);
    }

    if (pipe(fd) == -1) {
        fprintf(stderr, "Pipe failed");
        exit(EXIT_FAILURE);
    }

    if ((pid = fork()) < 0) {
        fprintf(stderr, "Fork error");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) { /* The parent will write to the pipe */
        char buffer[BUFFER_SIZE];
        int fdr;
        int num;

        close(fd[READ_END]); /* Close the unused end of the pipe */
        if ((fdr = open(inname, O_RDONLY)) < 0) {
            fprintf(stderr, "Parent: Error opening file %s for reading.\n", inname);
            exit(EXIT_FAILURE);
        }

        while ((num = read(fdr, buffer, BUFFER_SIZE)) > 0) {
            if (write(fd[WRITE_END], buffer, num) < 0) {
                fprintf(stderr, "Parent: Error writing to pipe.\n");
                exit(EXIT_FAILURE);
            }
        }
        if (num < 0) {
            fprintf(stderr, "Parent: Error reading from %s\n", inname);
            exit(EXIT_FAILURE);
        }
        close(fdr);
        close(fd[WRITE_END]);
    } else { /* The child will read from the pipe */
        char inbuf[BUFFER_SIZE];
        int fdw;
        int num;

        close(fd[WRITE_END]); /* Close the unused end of the pipe */

        fdw = open(outname, O_CREAT|O_WRONLY|O_TRUNC, 0644);
        if (fdw < 0) {
            fprintf(stderr, "Child: Can't open file %s for writing\n", outname);
            exit(EXIT_FAILURE);
        }

        while ((num = read(fd[READ_END], inbuf, BUFFER_SIZE)) > 0) {
            if (write(fdw, inbuf, num) < 0) {
                fprintf(stderr, "Child: Error writing to %s\n", outname);
                exit(EXIT_FAILURE);
            }
        }
        if (num < 0) {
            fprintf(stderr, "Child: Error reading from pipe.\n");
            exit(EXIT_FAILURE);
        }
        close(fdw);
        close(fd[READ_END]);
    }
    return 0;
}
