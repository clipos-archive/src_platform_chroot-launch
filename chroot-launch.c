// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 * @file chroot-launch.c
 * Secure chroot command runner.
 *
 * Copyright (C) 2006 SGDN/DCSSI
 *
 * Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h> /* PATH_MAX */

#ifdef CHROOT_CLEAN_EXEC
#include <sys/stat.h>
#include <fcntl.h>
#endif

#include <clip/clip.h>

#ifndef BASE_DIR
#error You must define BASE_DIR
#endif

#define TO_STR(var) _TO_STR(var)
#define _TO_STR(var) #var
#define BASE_LEN sizeof(TO_STR(BASE_DIR))

static char *envp[] = {
	NULL
};

static void usage(const char *s)
{
	fprintf(stderr, "Usage: %s <chroot base>" 
			"<cmd> <arg_1> ... <arg_n>\n", s);
}

int main(int argc, char *argv[])
{
	struct passwd *pwd;
	char pathname[PATH_MAX];
	if (argc < 3) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	
	pwd = getpwuid(getuid());
	if (pwd == NULL) {
		perror("getpwuid");
		return EXIT_FAILURE;
	}

#ifndef CHROOT_ALLOW_ROOT
	if (pwd->pw_uid == 0) {
		fputs("Chroot as root not allowed\n", stderr);
		return EXIT_FAILURE;
		
	}
#endif

	pathname[PATH_MAX-1] = 'a';
	(void)strncpy(pathname, TO_STR(BASE_DIR), BASE_LEN);
	(void)strncpy(pathname + BASE_LEN - 1, argv[1], PATH_MAX - BASE_LEN + 1);

	if (pathname[PATH_MAX-1] != '\0') {
		fputs("Chroot path name too long\n", stderr);
		return EXIT_FAILURE;
	}
	if (*pathname != '/') {
		fputs("Chroot path name must be absolute\n", stderr);
		return EXIT_FAILURE;
	}
	if (*(pathname+1) == '\0') {
		fputs("Cannot chroot to '/'\n", stderr);
		return EXIT_FAILURE;
	}
	if (strstr(pathname, "..")) {
		fputs("Chroot path contains a '..'\n", stderr);
		return EXIT_FAILURE;
	}

#ifdef CHROOT_CLEAN_EXEC
	if (clip_closeall(1)<0) {
		perror("clip_closeall");
		return EXIT_FAILURE;
	} else {
		/* TODO: open a null device inside the jail.
		 * => we need such a device in the jail in 
		 * in the first place... */
		int fd = open("/dev/null", O_RDWR|O_NONBLOCK);
		if (fd == -1)
			return EXIT_FAILURE;
		if (dup2(fd, STDIN_FILENO) < 0)
			return EXIT_FAILURE;
		if (dup2(fd, STDOUT_FILENO) < 0)
			return EXIT_FAILURE;
		if (dup2(fd, STDERR_FILENO) < 0)
			return EXIT_FAILURE;
	}
#endif /*CHROOT_CLEAN_EXEC*/

	if (clip_chroot(pathname)) {
		perror("chroot");
		return EXIT_FAILURE;
	}

	if (setgroups(0, NULL)) {
		perror("setgroups");
		return EXIT_FAILURE;
	}
	if (setuid(pwd->pw_uid)) {
		perror("setuid");
		return EXIT_FAILURE;
	}
	umask(0007);
	if (clip_reducecaps(0)) 
		return EXIT_FAILURE;

	return -execve(argv[2], argv+2, envp);
}
