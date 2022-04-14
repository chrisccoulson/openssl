#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "fips_mode.h"

#define FIPS_MODE_SWITCH_FILE "/proc/sys/crypto/fips_enabled"

static int fips_mode;

int ossl_fips_mode(void)
{
    return fips_mode;
}

void ossl_init_fips(void)
{
    const char *switch_path = FIPS_MODE_SWITCH_FILE;
    char *v;
    char c;
    int fd;

    if ((v = secure_getenv("OPENSSL_FORCE_FIPS_MODE")) != NULL) {
        fips_mode = strcmp(v, "0") == 0 ? 0 : 1;
        return;
    }

    if ((v = secure_getenv("OPENSSL_FIPS_MODE_SWITCH_PATH")) != NULL) {
        switch_path = v;
    }

    fd = open(switch_path, O_RDONLY);
    if (fd < 0) {
        fips_mode = 0;
        return;
    }

    while (read(fd, &c, sizeof(c)) < 0 && errno == EINTR);
    close(fd);

    fips_mode = c == '1' ? 1 : 0;
}
