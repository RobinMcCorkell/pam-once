/*
	Copyright (C) 2014 Robin McCorkell <rmccorkell@karoshi.org.uk>
	This file is part of pam_once.

	pam_once is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	pam_once is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with pam_once.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Heavily influenced by pmvarrun.c from pam-mount */

#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "common.h"

enum flag_t {
	DEBUG = 0x0001U
};

struct opts_t {
	const char *user;
	int modify;
	enum flag_t flags;
};

int parse_argv(struct opts_t *options, int argc, const char **argv) {
	options->user = NULL;
	options->modify = 0;

	int nonopt = 0;
	for (int i = 1; i < argc; ++i) {
		if (strncmp(argv[i], "--", 2) == 0) {
			if (strcmp(argv[i] + 2, "debug") == 0) {
				options->flags |= DEBUG;
			} else {
				fprintf(stderr, "WARNING: Unknown option %s\n", argv[i]);
			}
		} else {
			switch (nonopt) {
			case 0:
				options->user = argv[i];
				break;
			case 1:
				options->modify = strtol(argv[i], NULL, 10);
				if (errno != 0) {
					fprintf(stderr, "ERROR: strtol(%s) failed: %m\n", argv[i]);
					return ERR_ARGS;
				}
				break;
			default:
				fprintf(stderr, "ERROR: Surplus argument %s\n", argv[i]);
				return ERR_ARGS;
				break;
			}
			++nonopt;
		}
	}

	if (options->user == NULL) {
		fprintf(stderr, "ERROR: No user provided in arguments\n");
		return ERR_ARGS;
	}

	return ERR_SUCCESS;
}

int open_and_lock(const char *path, uid_t uid) {
	struct flock lockinfo = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};

	int fd = open(path, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "ERROR: open(%s) failed: %m\n", path);
		return -ERR_FILE;
	}
	if (fchown(fd, uid, 0) < 0) {
		fprintf(stderr, "ERROR: chown(%s) failed: %m\n", path);
		return -ERR_FILE;
	}

	alarm(5);
	if (fcntl(fd, F_SETLKW, &lockinfo) < 0) {
		if (errno == EAGAIN) {
			/* Assume a broken lock, so don't perform changes */
			fprintf(stderr, "WARNING: Failed to acquire lock on %s: %m\n", path);
			close(fd);
			return -ERR_IGNORE;
		} else {
			fprintf(stderr, "ERROR: fcntl failed: %m\n");
			return -ERR_SYSTEM;
		}
	}
	alarm(0);

	return fd;
}

int create_path(const char *path) {
	static const unsigned int mode = S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;
	if (mkdir(path, mode) < 0) {
		fprintf(stderr, "ERROR: mkdir(%s) failed: %m\n", path);
		return ERR_FILE;
	}
	if (chown(path, 0, 0) < 0) {
		fprintf(stderr, "ERROR: chown(%s) failed: %m\n", path);
		return ERR_FILE;
	}
	if (chmod(path, mode) < 0) {
		fprintf(stderr, "ERROR: chmod(%s) failed: %m\n", path);
		return ERR_FILE;
	}
	return ERR_SUCCESS;
}

int read_count(int fd) {
	char buffer[16];
	int ret = read(fd, buffer, sizeof(buffer));
	if (ret < 0) {
		fprintf(stderr, "ERROR: read failed: %m");
		return -ERR_FILE;
	} else if (ret == 0) {
		/* file is empty, but ret is already 0 */
	} else if (ret < sizeof(buffer)) {
		ret = strtol(buffer, NULL, 10);
		if (errno != 0) {
			fprintf(stderr, "ERROR: strtol(%s) failed: %m\n", buffer);
			return -ERR_FILE;
		}
	} else {
		fprintf(stderr, "ERROR: Buffer overflow: %m");
		return -ERR_SYSTEM;
	}
	return ret;
}

int write_count(int fd, int value) {
	if (ftruncate(fd, 0) < 0) {
		fprintf(stderr, "ERROR: ftruncate failed: %m\n");
		return ERR_FILE;
	}
	if (lseek(fd, 0, SEEK_SET) != 0) {
		fprintf(stderr, "ERROR: lseek failed: %m\n");
		return ERR_FILE;
	}

	char *buffer;
	int bytes = asprintf(&buffer, "%d\n", value);
	if (bytes < 0) {
		fprintf(stderr, "ERROR: asprintf failed: %m\n");
		return ERR_SYSTEM;
	}

	int written = write(fd, buffer, bytes);
	free(buffer);
	if (written != bytes) {
		fprintf(stderr, "ERROR: write failed: %m\n");
		return ERR_FILE;
	}

	if (ftruncate(fd, bytes) < 0) {
		fprintf(stderr, "ERROR: ftruncate failed: %m\n");
		return ERR_FILE;
	}

	return ERR_SUCCESS;
}

int main(int argc, const char **argv) {
	struct opts_t options;
	int err = parse_argv(&options, argc, argv);
	if (err)
		return err;

	struct passwd *pwd = getpwnam(options.user);
	if (pwd == NULL) {
		if (errno == 0) {
			fprintf(stderr, "ERROR: no user found: %s\n", options.user);
			return ERR_USER;
		} else {
			fprintf(stderr, "ERROR: getpwnam(%s) failed: %m\n", options.user);
			return ERR_SYSTEM;
		}
	}

	struct stat statbuf;
	if (stat(COUNT_PATH, &statbuf) < 0) {
		if (errno != ENOENT) {
			fprintf(stderr, "ERROR: stat(%s) failed: %m\n", COUNT_PATH);
			return ERR_FILE;
		}
		err = create_path(COUNT_PATH);
		if (err)
			return err;
	}

	char *filename;
	if (asprintf(&filename, COUNT_PATH "/%s", options.user) < 0) {
		fprintf(stderr, "ERROR: asprintf failed: %m\n");
		return ERR_SYSTEM;
	}
	int fd = err = open_and_lock(filename, pwd->pw_uid);
	if (err < 0) {
		if (err == -ERR_IGNORE)
			printf("0\n");
		return -err;
	}

	int value = err = read_count(fd);
	if (err < 0) {
		close(fd);
		return -err;
	}

	value += options.modify;
	if (value < 0)
		value = 0;

	err = write_count(fd, value);
	close(fd);
	if (err)
		return err;

	printf("%d\n", value);
	return ERR_SUCCESS;
}
