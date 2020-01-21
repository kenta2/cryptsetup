/*
 * Small program to LUKS suspend devices before system suspend
 *
 * License: GNU GPLv3
 * Copyright: (c) 2017 Guilhem Moulin <guilhem@debian.org>
 *            (c) 2017 Jonas Meurer <jonas@freesources.org>
 *            (c) 2019 Jonas Meurer <jonas@freesources.org>
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <libcryptsetup.h>

void usage() {
    printf("Usage: cryptsetup-suspend [-r|--reverse] <blkdev> [<blkdev> ...]\n"
           "      -r, --reverse             process luks devices in reverse order\n\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    bool reverse = 0;
    int d_size;
    bool sync_on_suspend_reset = 0;
    FILE *sos = NULL;

    /* Process commandline arguments */
    if (argc < 2) {
        usage();
    } else if ((strcmp(argv[1], "-r") == 0) || (strcmp(argv[1], "--reverse") == 0)) {
        if (argc < 3)
            usage();

        reverse = 1;
        d_size = argc-2;
    } else {
        d_size = argc-1;
    }

    /* Read in devices */
    const char *devices[d_size];
    if (!reverse) {
        for (int i = 0; i < d_size; i++) {
            devices[i] = argv[i+1];
        }
    } else {
        for (int i = 0; i < d_size; i++) {
            devices[i] = argv[argc-i-1];
        }
    }

    /* Disable sync_on_suspend in Linux kernel
     *
     * Only available in Linux kernel >= 5.6 */
    if (access("/sys/power/sync_on_suspend", W_OK) < 0) {
        if (errno == ENOENT)
            warn("kernel too old, can't disable sync on suspend");
    } else {
        sos = fopen("/sys/power/sync_on_suspend", "r+");
        if (!sos)
            err(EXIT_FAILURE, "couldn't open sysfs file");

        int sos_c = fgetc(sos);
        if (fgetc(sos) == EOF)
            err(EXIT_FAILURE, "couldn't read from file");

        if (sos_c == '0') {
            /* already disabled */
        } else if (sos_c == '1') {
            sync_on_suspend_reset = 1;
            if (fputs("0", sos) <= 0)
                err(EXIT_FAILURE, "couldn't write to file");
        } else {
            err(EXIT_FAILURE, "unexpected value from /sys/power/sync_on_suspend");
        }

        fclose(sos);
    }

    /* Change process priority to -20 (highest) to avoid races between
     * the LUKS suspend(s) and the suspend-on-ram. */
    if (setpriority(PRIO_PROCESS, 0, -20) == -1)
        warn("can't lower process priority to -20");

    /* Do the final filesystem sync since we disabled sync_on_suspend in
     * Linux kernel.
     *
     * XXX: probably no need to sync everything, should be enough to
     * syncfd(dirfd) where dird = open(filepath, O_DIRECTORY|O_RDONLY)
     * and filepath is /dev/mapper/argv[i]'s first mountpoint */
    sync();

    int rv = 0;
    for (int i = 0; i < d_size; i++) {
        struct crypt_device *cd = NULL;
        if (crypt_init_by_name(&cd, devices[i]) || crypt_suspend(cd, devices[i])) {
            warnx("couldn't suspend LUKS device %s", devices[i]);
            rv = EXIT_FAILURE;
        }
        crypt_free(cd);
    }

    fprintf(stderr, "Sleeping...\n");
    FILE *s = fopen("/sys/power/state", "w");
    if (!s || fputs("mem", s) <= 0)
        err(EXIT_FAILURE, "couldn't suspend");
    fclose(s);

    /* Restore original sync_on_suspend value */
    if (sync_on_suspend_reset) {
        sos = fopen("/sys/power/sync_on_suspend", "w");
        if (!sos)
            err(EXIT_FAILURE, "couldn't open sysfs file");
        if (fputs("1", sos) <= 0)
            err(EXIT_FAILURE, "couldn't write to file");
    }

    return rv;
}
