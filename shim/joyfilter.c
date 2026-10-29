// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 haasanen
//
// joyfilter: LD_PRELOAD shim restricting which /dev/input nodes a process may open.
// Set MCPE_JOY_ALLOWED to a comma-separated list of allowed device paths
// (e.g. "/dev/input/by-id/usb-Microsoft_Xbox_Wireless_Controller_1234-joystick").
// Any other /dev/input/* open() returns EACCES, which makes GLFW/SDL skip that
// device entirely -> the instance sees exactly one gamepad.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int in_allowlist(const char *path) {
    const char *env = getenv("MCPE_JOY_ALLOWED");
    if (!env || !*env)
        return 1; // no filter configured: pass everything

    char rp_self[PATH_MAX];
    const char *self = realpath(path, rp_self) ? rp_self : path;

    const char *p = env;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        while (len && (*p == ' ' || *p == '\t')) { p++; len--; }
        while (len && (p[len-1] == ' ' || p[len-1] == '\t')) len--;
        char entry[PATH_MAX];
        if (len && len < PATH_MAX) {
            memcpy(entry, p, len);
            entry[len] = '\0';
            char rp_entry[PATH_MAX];
            const char *ent = realpath(entry, rp_entry) ? rp_entry : entry;
            if (strcmp(ent, self) == 0 || strcmp(entry, path) == 0)
                return 1;
        }
        if (!comma) break;
        p = comma + 1;
    }
    return 0;
}

static int gate(const char *path) {
    if (!path)
        return 1;
    if (strncmp(path, "/dev/input/", 11) != 0)
        return 1; // not an evdev node: none of our business
    return in_allowlist(path);
}

typedef int (*openat_t)(int, const char *, int, ...);
typedef int (*open_t)(const char *, int, ...);

static const char *resolve_dirfd(int dirfd, const char *path, char *buf, size_t bufsz) {
    if (path[0] == '/' || dirfd == AT_FDCWD)
        return path;
    if (snprintf(buf, bufsz, "/proc/self/fd/%d/%s", dirfd, path) < (int)bufsz)
        return buf;
    return path;
}

int open(const char *path, int flags, ...) {
    mode_t m = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags); m = (mode_t)va_arg(ap, int); va_end(ap);
    }
    if (!gate(path)) { errno = EACCES; return -1; }
    static open_t real;
    if (!real) real = (open_t)dlsym(RTLD_NEXT, "open");
    if (!real) { errno = ENOSYS; return -1; }
    return real(path, flags, m);
}

int open64(const char *path, int flags, ...) {
    mode_t m = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags); m = (mode_t)va_arg(ap, int); va_end(ap);
    }
    if (!gate(path)) { errno = EACCES; return -1; }
    static open_t real;
    if (!real) real = (open_t)dlsym(RTLD_NEXT, "open64");
    if (!real) real = (open_t)dlsym(RTLD_NEXT, "open");
    if (!real) { errno = ENOSYS; return -1; }
    return real(path, flags, m);
}

int openat(int dirfd, const char *path, int flags, ...) {
    mode_t m = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags); m = (mode_t)va_arg(ap, int); va_end(ap);
    }
    char buf[PATH_MAX];
    if (!gate(resolve_dirfd(dirfd, path, buf, sizeof buf))) { errno = EACCES; return -1; }
    static openat_t real;
    if (!real) real = (openat_t)dlsym(RTLD_NEXT, "openat");
    if (!real) { errno = ENOSYS; return -1; }
    return real(dirfd, path, flags, m);
}

int openat64(int dirfd, const char *path, int flags, ...) {
    mode_t m = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags); m = (mode_t)va_arg(ap, int); va_end(ap);
    }
    char buf[PATH_MAX];
    if (!gate(resolve_dirfd(dirfd, path, buf, sizeof buf))) { errno = EACCES; return -1; }
    static openat_t real;
    if (!real) real = (openat_t)dlsym(RTLD_NEXT, "openat64");
    if (!real) real = (openat_t)dlsym(RTLD_NEXT, "openat");
    if (!real) { errno = ENOSYS; return -1; }
    return real(dirfd, path, flags, m);
}
