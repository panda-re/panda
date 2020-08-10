#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#define MAX_RUNTIME_SEC 180

FILE *log_file;
const char *log_path = "/tmp/sig_log.txt";

void sig_handler(int signo) {

    sigset_t mask, prev_mask;

    // Block other signals before file I/O
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev_mask);

    // Immediate flush to log signal recieved
    switch (signo) {
        case SIGSEGV:
            fprintf(log_file, "Received SIGSEGV (Invalid memory reference)\n");
            fflush(log_file);
            break;
        case SIGABRT:
            fprintf(log_file, "Received SIGABRT (Abort signal from abort(3))\n");
            fflush(log_file);
            break;
        case SIGINT:
            fprintf(log_file, "Received SIGINT (Interrupt from keyboard)\n");
            fflush(log_file);
            break;
        case SIGILL:
            fprintf(log_file, "Received SIGILL (Illegal Instruction)\n");
            fflush(log_file);
            break;
        case SIGWINCH:
            fprintf(log_file, "Received SIGWINCH (Window resize signal)\n");
            fflush(log_file);
            break;
        default:
            fprintf(log_file, "Received signal number %d\n", signo);
            fflush(log_file);
    }

    // Unblock other signals after file I/O
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
}

void checked_handler_register(int signo) {
    if (signal(signo, sig_handler) == SIG_ERR) {
        fprintf(stderr, "Error registering handler for signal number %d: %s\n", signo, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

int main(void) {

    log_file = fopen(log_path, "a");
    if (log_file == NULL) {
        fprintf(stderr, "Failed to open log_file file \'%s\': %s\n", log_path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    checked_handler_register(SIGSEGV);
    checked_handler_register(SIGABRT);
    checked_handler_register(SIGINT);
    checked_handler_register(SIGILL);
    checked_handler_register(SIGWINCH);

    for (int i = 0; i < MAX_RUNTIME_SEC; i++) {
        sleep(1);
    }

    return 0;
}