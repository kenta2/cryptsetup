/*
 * Run several debugging tests around luksSuspend and system suspend.
 * 
 * writestate:
 *     Do infinitive write(2) operations to a statefile. Helpful to
 *     reproduce race condition/dead lock between crypt_suspend() and sync()
 *     at Linux Kernel suspend function.
 *
 * readblk:
 *     Try to read from block device with O_DIRECT and error out if the block
 *     device is blocked.
 *
 * We always log timestamp and a counter to logfile or stdout each second.
 *
 * Copyright: 2019 Jonas Meurer <jonas@freesources.org>
 * License: GNU GPLv3
 */

/* required for O_DIRECT */
#define _GNU_SOURCE

/* number of bytes to read from blk_dev */
const int BLK_BUF_SIZE = 8;

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

/* for block device access */
#include <linux/fs.h>
#include <sys/ioctl.h>

/* for shared memory object handling */
#include <sys/mman.h>

static bool running = true;

/* global var to be stored in shared memory for 'buffer' action */
static int *shm_counter;

void int_handler(int dummy) {
    running = false;
}

/* write time to log file or stdout */
void write_log(char str[34], pid_t pid, int logcount, FILE *logfile) {
    if (fprintf(logfile, "%s // Child PID: %d // Count: %d\n", str, pid, logcount) <= 0)
        err(EXIT_FAILURE, "fprintf failed");

    /* flush writes to logfile */
    fflush(logfile);
}

/* write to state file */
void write_state(int state_fd) {
    if (write(state_fd, ".", strlen(".")) <= 0)
        err(EXIT_FAILURE, "write failed");

    /* We don't want to commit filesystem caches to disk here, as that's
     * what the sync() from Kernel suspend function is supposed to do in
     * order to run into the deadlock. So *no* `fssync(logfile)`.
     */

    /* Slow down the loop a bit */
    //sleep(1);
}

/* read from block device */
void read_blk(int blk_fd, unsigned long long blk_size) {
    fprintf(stderr, "test\n");

    /* Get random number between 0 and (blk_size - BLK_BUF_SIZE) */
    int r = rand() % (blk_size - BLK_BUF_SIZE);

    /* reposition file offset (in bytes) */
    lseek(blk_fd, r, SEEK_SET);

    char read_buf[BLK_BUF_SIZE];
    if (read(blk_fd, &read_buf, sizeof(read_buf)) <= -1)
        err(EXIT_FAILURE, "read failed");

    fprintf(stderr, "read bytes: %s\n", read_buf);
}

/* write buffer to file */
void write_buf(int buf_fd, int *buf_counter) {
    char buf[((*buf_counter+10)/10)+2];
    snprintf(buf, sizeof(buf), "%i\n", *buf_counter);
    //fprintf(stderr, "Size of '%s': %li\n", buf, sizeof(buf));

    if (write(buf_fd, buf, strlen(buf)) <= 0)
        err(EXIT_FAILURE, "write failed");
    *buf_counter = 0;
}

int main(int argc, char **argv) {

    if ((argc != 3 && argc != 4) ||
                    ((strcmp(argv[1], "writestate") != 0) &&
                     (strcmp(argv[1], "readblk") != 0) &&
                     (strcmp(argv[1], "buffer") != 0))) {
        printf("usage: ./suspend-race-reproducer writestate <STATEFILE> [<LOGFILE>]\n"
               "       ./suspend-race-reproducer readblk <BLKDEV> [<LOGFILE>]\n"
               "       ./suspend-race-reproducer buffer <BUFFILE> [<LOGFILE>]\n"
               "<STATEFILE> is the file that we write to infinitely\n"
               "<BLKDEV> is the block device that we read from\n"
               "<BUFFILE> is the file to write to from buffer\n"
               "<LOGFILE> is the file that we log to each second (default STDOUT)\n");
        exit(1);
    }

    pid_t pid = 0;
    pid_t sid = 0;
    int rv = EXIT_SUCCESS;

    umask(0);

    /*
     * action = 0 -> writestate
     * action = 1 -> readblk
     * action = 2 -> buffer
     */
    int action;
    if (strcmp(argv[1], "writestate") == 0) {
        action = 0;
    } else if (strcmp(argv[1], "readblk") == 0) {
        action = 1;
    } else if (strcmp(argv[1], "buffer") == 0) {
        action = 2;
    }

    /* create shared memory object if action == 'buffer' */
    if (action == 2) {
        shm_counter = mmap(NULL, sizeof *shm_counter, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    }

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
        if (argc == 4) {
            logfile = fopen(argv[3], "w");
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
            if (strftime(t_str_now, sizeof(t_str_now), "Time: %Y-%m-%d %H:%M:%S", tm_info) == 0)
                err(EXIT_FAILURE, "strftime failed");

            if (strcmp(t_str_before, t_str_now) != 0) {
                logcount++;
                if (action == 2)
                    *shm_counter = logcount;
                    fprintf(stderr, "Increasing shm_counter: %i\n", *shm_counter);
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
        close(STDOUT_FILENO);
        //close(STDERR_FILENO);

        /* change process priority to -20 (highest) */
        if (setpriority(PRIO_PROCESS, 0, -20) == -1)
            warn("Failed to lower process priority to -20");

        int fd;

        switch(action) {
        case 0:
            /* open statefile for writing */
            fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC | O_SYNC,
                            0644);
            if (fd < 0)
                err(EXIT_FAILURE, "open failed");

            while(running) {
                write_state(fd);
            }
            break;
        case 1:
            /* open block device for reading */
            fd = open(argv[2], O_RDONLY | O_SYNC | O_NONBLOCK);
            if (fd < 0)
                err(EXIT_FAILURE, "open failed");

            /* seed random number generater with current time */
            srand(time(NULL));

            /* get size of block device in bytes */
            unsigned long long blk_size=0;
            if (ioctl(fd, BLKGETSIZE64, &blk_size) == -1)
                err(EXIT_FAILURE, "ioctl failed");

            warn("Block size: %llu", blk_size);

            while(running) {
                read_blk(fd, blk_size);
            }
            break;
        case 2:
            /* open ring buffer file for writing */
            fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC | O_SYNC,
                            0644);
            if (fd < 0)
                err(EXIT_FAILURE, "open failed");

            while(running) {
                if (*shm_counter != 0) {
                    write_buf(fd, shm_counter);
                }
            }
            break;
        }

        close(fd);
    }

    return rv;
}
