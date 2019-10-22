/*
 * Reproduce race condition/dead lock between crypt_suspend() and sync()
 * at Linux Kernel suspend function.
 *
 * - Do infinitive writes to a statefile using fprintf() and fflush() to
 *   enforce the race.
 * - Log timestamp and counter to logfile or stdout each second
 * - Try to implement a timeout when writing to statefile
 *
 * Copyright: Jonas Meurer <jonas@freesources.org>
 * License: GNU GPLv3
 */

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>

static bool running = true;

void int_handler(int dummy) {
    running = false;
}

/* write time to log file or stdout */
void write_log(char str[34], pid_t pid, int logcount, FILE *logfile) {
    if (fprintf(logfile, "%s // Child PID: %d // Count: %d\n", str, pid, logcount) <= 0) {
        err(EXIT_FAILURE, "fprintf failed");
    }

    /* flush writes to logfile */
    fflush(logfile);
}

/* write to state file */
void write_state(int state_fd) {
    if (write(state_fd, ".", strlen(".")) <= 0) {
        err(EXIT_FAILURE, "write failed");
    }

    /* We don't want to commit filesystem caches to disk here, as that's
     * what the sync() from Kernel suspend function is supposed to do in
     * order to run into the deadlock. So *no* `fssync(logfile)`.
     */

    /* Slow down the loop a bit */
    //sleep(1);
}

int main(int argc, char **argv) {

    if (argc != 2 && argc != 3) {
        printf("usage: ./suspend-race-reproducer <STATEFILE> [<LOGFILE>]\n"
               "<STATEFILE> is the file that we write to infinitely\n"
               "<LOGFILE> is the file that we log to each second (default STDOUT)\n");
        exit(1);

    }

    pid_t pid = 0;
    pid_t sid = 0;
    int rv = EXIT_SUCCESS;

    umask(0);

    /* fork into child process */
    pid = fork();
    if (pid < 0)
        err(EXIT_FAILURE, "fork failed!");
    if (pid > 0) {
        /* parent process */

        time_t now;
        char t_str_now[34];
        char t_str_before[34];
        struct tm *tm_info;
        int logcount = 0;

        /* open logfile */
        FILE *logfile;
        if (argc == 3) {
            logfile = fopen(argv[2], "w");
            if (logfile == NULL)
                err(EXIT_FAILURE, "fopen failed");
        } else {
            logfile = stdout;
        }

        /* catch SIGINT (Interrupt from terminal)
         * necessary to reach calls after the while loop */
        struct sigaction act;
        act.sa_handler = int_handler;
        sigaction(SIGINT, &act, NULL);

        fprintf(logfile, "\n");
        while(running) {
            /* get current time */
            time(&now);
            tm_info = localtime(&now);
            strcpy(t_str_before, t_str_now);
            if (strftime(t_str_now, sizeof(t_str_now), "Time: %Y-%m-%d %H:%M:%S", tm_info) == 0) {
                err(EXIT_FAILURE, "strftime failed");
            }

            if (strcmp(t_str_before, t_str_now) != 0) {
                logcount++;
                // TODO: watch the child process and error out it if
                // disappeared.
                write_log(t_str_now, pid, logcount, logfile);
            }
        }
    
        fclose(logfile);
        /* kill child process */
        kill(pid, SIGHUP);
    } else {
        /* child process */

        /* get new session and PID */
        sid = setsid();
        if (sid < 0)
            err(EXIT_FAILURE, "setsid failed!");

        if (chdir("/") < 0)
            err(EXIT_FAILURE, "chdir failed");

        /* close standard descriptors */
        close(STDIN_FILENO);
        //close(STDOUT_FILENO);
        //close(STDERR_FILENO);

        /* change process priority to -20 (highest) */
        if (setpriority(PRIO_PROCESS, 0, -20) == -1)
            warn("Failed to lower process priority to -20");

        /* open statefile */
        int state_fd;
        state_fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC | O_SYNC,
                    0644);
        if (state_fd < 0) {
            err(EXIT_FAILURE, "open failed");
        }

        /* prepare for select() */
        fd_set rw_fds, rw_fd_active;
        FD_ZERO(&rw_fds);
        FD_SET(state_fd, &rw_fds);

        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        int select_rv;

        while(running) {
            rw_fd_active = rw_fds;
            // doesn't work as expected yet
            select_rv = select(state_fd + 1, &rw_fd_active, &rw_fd_active, NULL, &timeout);
            if (select_rv == -1) {
                err(EXIT_FAILURE, "select failed");
            } else if (select_rv == 0) {
                err(EXIT_FAILURE, "timeout at reading statefile");
            } else {
                write_state(state_fd);
            }
        }

        close(state_fd);
    }


    return rv;
}
