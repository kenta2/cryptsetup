#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <libcryptsetup.h>

int
main(int argc, char *argv[]) {
    /* change process priority to -20 (highest) to avoid races between
     * the LUKS suspend(s) and the suspend-on-ram */
    if (setpriority(PRIO_PROCESS, 0, -20) == -1)
        warn("can't lower process priority to -20");
    /* XXX no need to sync everything, should be enough to syncfd(dirfd)
	 * where dird = open(filepath, O_DIRECTORY|O_RDONLY) and filepath is
	 * /dev/mapper/argv[i]'s first mountpoint */
    sync();

    int rv = 0;
    for (int i = 1; i < argc; i++) {
        struct crypt_device *cd = NULL;
        if (crypt_init_by_name(&cd, argv[i]) || crypt_suspend(cd, argv[i]))
            warnx("couldn't suspend LUKS device %s", argv[i]);
        else
            rv = EXIT_FAILURE;
        crypt_free(cd);
    }

    fprintf(stderr, "Sleeping...\n");
    FILE *s = fopen("/sys/power/state", "w");
    if (s == NULL || fputs("mem", s) <= 0)
        err(EXIT_FAILURE, "couldn't suspend");
    fclose(s);
    return rv;
}
