/*
	Copyright (C) 2014 Robin McCorkell <rmccorkell@karoshi.org.uk>
	This file is part of pam-once.

	pam-once is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	pam-once is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with pam-once.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/select.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>

#include <pam-once.h>
#include "common.h"

#define max(x,y) ((x) > (y) ? (x) : (y))

enum pam_type_t {
	OPEN_SESSION,
	CLOSE_SESSION
};

struct opts_t {
	pam_handle_t *pamh;
	int flags;
	enum pam_type_t type;
	const char *user;
	int modify;
};

static char ** prepare_argv(struct opts_t *options) {
	/* argv: exec user operation [--debug] NULL */
	int size = (options->flags & PAM_ONCE_DEBUG) ? 5 : 4;
	if (options->flags & PAM_ONCE_DEBUG)
		pam_syslog(options->pamh, LOG_DEBUG, "argv size = %d", size);
	char **argv = malloc(size * sizeof(char *));
	if (argv == NULL) {
		return NULL;
	}
	if (options->flags & PAM_ONCE_DEBUG)
		pam_syslog(options->pamh, LOG_DEBUG, "argv[0] = " COUNT_CMD);
	if ((argv[0] = strdup(COUNT_CMD)) == NULL) {
		free(argv);
		errno = ENOMEM;
		return NULL;
	}
	if (options->flags & PAM_ONCE_DEBUG)
		pam_syslog(options->pamh, LOG_DEBUG, "argv[1] = %s", options->user);
	if ((argv[1] = strdup(options->user)) == NULL) {
		free(argv);
		errno = ENOMEM;
		return NULL;
	}
	if (options->flags & PAM_ONCE_DEBUG)
		pam_syslog(options->pamh, LOG_DEBUG, "argv[2] = %d", options->modify);
	if (asprintf(&argv[2], "%d", options->modify) < 0) {
		free(argv);
		errno = ENOMEM;
		return NULL;
	}

	if (options->flags & PAM_ONCE_DEBUG) {
		pam_syslog(options->pamh, LOG_DEBUG, "argv[3] = --debug");
		if ((argv[3] = strdup("--debug")) == NULL) {
			free(argv);
			errno = ENOMEM;
			return NULL;
		}
		argv[4] = NULL;
	} else {
		argv[3] = NULL;
	}
	return argv;
}

static int move_fd(int newfd, int fd) {
	if (newfd != fd) {
		if (dup2(newfd, fd) == -1)
			return -1;
		close(newfd);
	}
	return 0;
}

static int modify_count(struct opts_t *options) {
	int stdout_fds[2];
	int stderr_fds[2];
	if (pipe(stdout_fds) != 0) {
		pam_syslog(options->pamh, LOG_ERR, "pipe(...) failed: %m");
		return -1;
	}
	if (pipe(stderr_fds) != 0) {
		pam_syslog(options->pamh, LOG_ERR, "pipe(...) failed: %m");
		return -1;
	}

	pid_t pid = fork();
	if (pid == -1) {
		pam_syslog(options->pamh, LOG_CRIT, "fork failed: %m");
		return -1;
	}
	if (pid > 0) { /* parent */
		close(stdout_fds[1]);
		close(stderr_fds[1]);
		int maxfd = max(stdout_fds[0], stderr_fds[0]);
		int number = 0;
		while (1) {
			if (options->flags & PAM_ONCE_DEBUG)
				pam_syslog(options->pamh, LOG_DEBUG, "Listening on pipes");
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(stdout_fds[0], &fds);
			FD_SET(stderr_fds[0], &fds);

			char buffer[1024] = {0};
			int ret = select(maxfd + 1, &fds, NULL, NULL, NULL);

			if (ret < 0) {
				pam_syslog(options->pamh, LOG_CRIT, "select() failed: %m");
				return -1;
			} else if (ret > 0) {
				if (FD_ISSET(stdout_fds[0], &fds)) {
					int bytes = read(stdout_fds[0], buffer, sizeof(buffer) - 1);
					if (options->flags & PAM_ONCE_DEBUG)
						pam_syslog(options->pamh, LOG_DEBUG,
						           "Got %d bytes from stdout pipe: %s",
						           bytes, buffer);
					if (bytes == 0) {
						break;
					} else if (bytes < 0) {
						pam_syslog(options->pamh, LOG_ERR, "read(stdout) failed: %m");
						return -1;
					}
					number = strtol(buffer, NULL, 10);
					if (options->flags & PAM_ONCE_DEBUG)
						pam_syslog(options->pamh, LOG_DEBUG, "New number: %d",
						           number);
				}
				if (FD_ISSET(stderr_fds[0], &fds)) {
					int bytes = read(stderr_fds[0], buffer, sizeof(buffer) - 1);
					if (options->flags & PAM_ONCE_DEBUG)
						pam_syslog(options->pamh, LOG_DEBUG,
						           "Got %d bytes from stderr pipe: %s",
						           bytes, buffer);
					if (bytes == 0) {
						break;
					} else if (bytes < 0) {
						pam_syslog(options->pamh, LOG_ERR, "read(stderr) failed: %m");
						return -1;
					}
					pam_syslog(options->pamh, LOG_ERR, "stderr: %s", buffer);
				}
			}
		}
		close(stdout_fds[0]);
		close(stderr_fds[0]);

		if (options->flags & PAM_ONCE_DEBUG)
			pam_syslog(options->pamh, LOG_DEBUG, "Pipes closed, waiting for process");

		pid_t retval;
		int status;
		while ((retval = waitpid(pid, &status, 0)) == -1 && errno == EINTR);
		if (retval == (pid_t) -1) {
			pam_syslog(options->pamh, LOG_ERR, "waitpid returns with -1: %m");
			return -1;
		} else if (status != 0) {
			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) == ERR_IGNORE) {
					pam_syslog(options->pamh, LOG_NOTICE, "%s exited with ignore",
					           COUNT_CMD);
					return 0;
				} else {
					pam_syslog(options->pamh, LOG_ERR, "%s failed: exit code %d",
					           COUNT_CMD, WEXITSTATUS(status));
				}
			} else if (WIFSIGNALED(status)) {
				pam_syslog(options->pamh, LOG_ERR, "%s failed: caught signal %d%s",
				           COUNT_CMD, WTERMSIG(status),
				           WCOREDUMP(status) ? " (core dumped)" : "");
			} else {
				pam_syslog(options->pamh, LOG_ERR, "%s failed: unknown status 0x%x",
				           COUNT_CMD, status);
			}
			return -1;
		}
		return number;
	} else { /* child */
		close(stdout_fds[0]);
		close(stderr_fds[0]);
		move_fd(stdout_fds[1], STDOUT_FILENO);
		move_fd(stderr_fds[1], STDERR_FILENO);

		close(STDIN_FILENO);

		char **argv = prepare_argv(options);
		if (argv == NULL) {
			int err = errno;
			pam_syslog(options->pamh, LOG_CRIT, "Failed preparing argv: %m");
			_exit(err);
		}
		char **envlist = pam_getenvlist(options->pamh);
		if (envlist == NULL) {
			int err = errno;
			pam_syslog(options->pamh, LOG_CRIT, "Failed preparing envlist: %m");
			_exit(err);
		}

		execve(argv[0], argv, envlist);
		int err = errno;
		pam_syslog(options->pamh, LOG_CRIT, "execve(%s) failed: %m", argv[0]);
		free(argv);
		free(envlist);
		_exit(err);
	}
}

static void cleanup_count(pam_handle_t *pamh, void *data, int error_status) {
	free((int *) data);
}

static void cleanup_type(pam_handle_t *pamh, void *data, int error_status) {
	free((enum pam_type_t *) data);
}

static int get_count_cached(struct opts_t *options) {
	const enum pam_type_t *type;
	if (pam_get_data(options->pamh, PACKAGE "_type", (const void **) &type)
	    == PAM_SUCCESS) {
		if (options->flags & PAM_ONCE_DEBUG)
			pam_syslog(options->pamh, LOG_DEBUG, "found type %d, want %d",
			           *type, options->type);
		if (*type != options->type)
			return -1;
	} else {
		return -1;
	}

	const int *count;
	if (pam_get_data(options->pamh, PACKAGE "_count", (const void **) &count)
	    == PAM_SUCCESS)
		return *count;
	else
		return -1;
}

static int set_count_cached(struct opts_t *options, int count) {
	int err;
	int *newcount = malloc(sizeof(int));
	if (newcount == NULL) {
		pam_syslog(options->pamh, LOG_CRIT, "malloc failed: %m");
		return PAM_SYSTEM_ERR;
	}
	*newcount = count;
	enum pam_type_t *newtype = malloc(sizeof(enum pam_type_t));
	if (newtype == NULL) {
		pam_syslog(options->pamh, LOG_CRIT, "malloc failed: %m");
		return PAM_SYSTEM_ERR;
	}
	*newtype = options->type;

	if (options->flags & PAM_ONCE_DEBUG)
		pam_syslog(options->pamh, LOG_DEBUG, "pam_set_data(" PACKAGE "_count, %d)",
		           count);
	if ((err = pam_set_data(options->pamh, PACKAGE "_count", (void *) newcount,
	                        cleanup_count)) != PAM_SUCCESS) {
		pam_syslog(options->pamh, LOG_ERR, "Failed setting data: %s",
		           pam_strerror(options->pamh, err));
		return err;
	}

	if (options->flags & PAM_ONCE_DEBUG)
		pam_syslog(options->pamh, LOG_DEBUG, "pam_set_data(" PACKAGE "_type, %d)",
		           options->type);
	if ((err = pam_set_data(options->pamh, PACKAGE "_type", (void *) newtype,
	                        cleanup_type)) != PAM_SUCCESS) {
		pam_syslog(options->pamh, LOG_ERR, "Failed setting data: %s",
		           pam_strerror(options->pamh, err));
		return err;
	}
	return PAM_SUCCESS;
}

/******************
 * extern functions
 ******************/

int pam_once_open_session(pam_handle_t *pamh, int flags) {
	struct opts_t options;
	options.pamh = pamh;
	options.flags = flags;
	options.type = OPEN_SESSION;
	options.modify = 1;

	if (options.flags & PAM_ONCE_DEBUG)
		pam_syslog(options.pamh, LOG_DEBUG, "*** pam_once_open_session init ***");

	int ret;
	if ((ret = pam_get_user(options.pamh, &options.user, NULL)) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "pam_get_user failed: %s",
		           pam_strerror(options.pamh, ret));
		return ret;
	}

	int count = get_count_cached(&options);
	if (count == -1) {
		count = modify_count(&options);
		if (count == -1)
			return PAM_SYSTEM_ERR;
		ret = set_count_cached(&options, count);
		if (ret != PAM_SUCCESS)
			return ret;
	} else {
		if (options.flags & PAM_ONCE_DEBUG)
			pam_syslog(options.pamh, LOG_DEBUG, "Found cached count");
	}

	if (options.flags & PAM_ONCE_DEBUG)
		pam_syslog(options.pamh, LOG_DEBUG, "count = %d", count);

	if (options.flags & PAM_ONCE_DEBUG)
		pam_syslog(options.pamh, LOG_DEBUG, "*** pam_once_open_session end ***");

	if (count == 1)
		return PAM_SUCCESS;

	return PAM_IGNORE;
}

int pam_once_close_session(pam_handle_t *pamh, int flags) {
	struct opts_t options;
	options.pamh = pamh;
	options.flags = flags;
	options.type = CLOSE_SESSION;
	options.modify = -1;

	if (options.flags & PAM_ONCE_DEBUG)
		pam_syslog(options.pamh, LOG_DEBUG, "*** pam_once_close_session init ***");

	int ret;
	if ((ret = pam_get_user(options.pamh, &options.user, NULL)) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "pam_get_user failed: %s",
		           pam_strerror(options.pamh, ret));
		return ret;
	}

	int count = get_count_cached(&options);
	if (count == -1) {
		count = modify_count(&options);
		if (count == -1)
			return PAM_SYSTEM_ERR;
		ret = set_count_cached(&options, count);
		if (ret != PAM_SUCCESS)
			return ret;
	} else {
		if (options.flags & PAM_ONCE_DEBUG)
			pam_syslog(options.pamh, LOG_DEBUG, "Found cached count");
	}

	if (options.flags & PAM_ONCE_DEBUG)
		pam_syslog(options.pamh, LOG_DEBUG, "count = %d", count);

	if (options.flags & PAM_ONCE_DEBUG)
		pam_syslog(options.pamh, LOG_DEBUG, "*** pam_once_close_session end ***");

	if (count == 0)
		return PAM_SUCCESS;

	return PAM_IGNORE;
}
