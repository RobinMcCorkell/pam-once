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
#include "common.h"

#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>

#define max(x,y) ((x) > (y) ? (x) : (y))

static char ** prepare_argv(const char *user, int modify) {
	/* argv: exec user operation NULL */
	char **argv = malloc(4 * sizeof(char *));
	if (argv == NULL) {
		return NULL;
	}
	if ((argv[0] = strdup(COUNT_CMD)) == NULL) {
		free(argv);
		errno = ENOMEM;
		return NULL;
	}
	if ((argv[1] = strdup(user)) == NULL) {
		free(argv[0]);
		free(argv);
		errno = ENOMEM;
		return NULL;
	}
	if (asprintf(&argv[2], "%d", modify) < 0) {
		free(argv[0]);
		free(argv[1]);
		free(argv);
		errno = ENOMEM;
		return NULL;
	}
	argv[3] = NULL;
	return argv;
}

static void free_argv(char **argv) {
	free(argv[0]);
	free(argv[1]);
	free(argv[2]);
	free(argv);
}

static int move_fd(int newfd, int fd) {
	if (newfd != fd) {
		if (dup2(newfd, fd) == -1)
			return -1;
		close(newfd);
	}
	return 0;
}

static int modify_count(pam_handle_t *pamh, const char *user, int modify) {
	int stdout_fds[2];
	int stderr_fds[2];
	if (pipe(stdout_fds) != 0) {
		pam_syslog(pamh, LOG_ERR, "pipe(...) failed: %m");
		return -1;
	}
	if (pipe(stderr_fds) != 0) {
		pam_syslog(pamh, LOG_ERR, "pipe(...) failed: %m");
		return -1;
	}

	pid_t pid = fork();
	if (pid == -1) {
		pam_syslog(pamh, LOG_CRIT, "fork failed: %m");
		return -1;
	}
	if (pid > 0) { /* parent */
		close(stdout_fds[1]);
		close(stderr_fds[1]);
		int maxfd = max(stdout_fds[0], stderr_fds[0]);
		int number = 0;
		while (1) {
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(stdout_fds[0], &fds);
			FD_SET(stderr_fds[0], &fds);

			char buffer[1024] = {0};
			int ret = select(maxfd + 1, &fds, NULL, NULL, NULL);

			if (ret < 0) {
				pam_syslog(pamh, LOG_CRIT, "select() failed: %m");
				return -1;
			} else if (ret > 0) {
				if (FD_ISSET(stdout_fds[0], &fds)) {
					int bytes = read(stdout_fds[0], buffer, sizeof(buffer) - 1);
					if (bytes == 0) {
						break;
					} else if (bytes < 0) {
						pam_syslog(pamh, LOG_ERR, "read(stdout) failed: %m");
						return -1;
					}
					number = strtol(buffer, NULL, 10);
				}
				if (FD_ISSET(stderr_fds[0], &fds)) {
					int bytes = read(stderr_fds[0], buffer, sizeof(buffer) - 1);
					if (bytes == 0) {
						break;
					} else if (bytes < 0) {
						pam_syslog(pamh, LOG_ERR, "read(stderr) failed: %m");
						return -1;
					}
					pam_syslog(pamh, LOG_ERR, "stderr: %s", buffer);
				}
			}
		}
		close(stdout_fds[0]);
		close(stderr_fds[0]);

		pid_t retval;
		int status;
		while ((retval = waitpid(pid, &status, 0)) == -1 && errno == EINTR);
		if (retval == (pid_t) -1) {
			pam_syslog(pamh, LOG_ERR, "waitpid returns with -1: %m");
			return -1;
		} else if (status != 0) {
			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) == ERR_IGNORE) {
					pam_syslog(pamh, LOG_NOTICE, "%s exited with ignore",
					           COUNT_CMD);
					return 0;
				} else {
					pam_syslog(pamh, LOG_ERR, "%s failed: exit code %d",
					           COUNT_CMD, WEXITSTATUS(status));
				}
			} else if (WIFSIGNALED(status)) {
				pam_syslog(pamh, LOG_ERR, "%s failed: caught signal %d%s",
				           COUNT_CMD, WTERMSIG(status),
				           WCOREDUMP(status) ? " (core dumped)" : "");
			} else {
				pam_syslog(pamh, LOG_ERR, "%s failed: unknown status 0x%x",
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

		char **argv = prepare_argv(user, modify);
		if (argv == NULL) {
			int err = errno;
			pam_syslog(pamh, LOG_CRIT, "Failed preparing argv: %m");
			_exit(err);
		}
		char **envlist = pam_getenvlist(pamh);
		if (envlist == NULL) {
			int err = errno;
			pam_syslog(pamh, LOG_CRIT, "Failed preparing envlist: %m");
			free_argv(argv);
			_exit(err);
		}

		execve(argv[0], argv, envlist);
		int err = errno;
		pam_syslog(pamh, LOG_CRIT, "execve(%s) failed: %m", argv[0]);
		free_argv(argv);
		free(envlist);
		_exit(err);
	}
}

static void cleanup_count(pam_handle_t *pamh, void *data, int error_status) {
	free((int *) data);
}

static int get_count_cached(pam_handle_t *pamh, const char *user) {
	const int *count;
	if (pam_get_data(pamh, PACKAGE "_count", (const void **) &count)
	    == PAM_SUCCESS)
		return *count;
	else
		return -1;
}

static int set_count_cached(pam_handle_t *pamh, const char *user, int count) {
	int err;
	int *newcount = malloc(sizeof(int));
	if (newcount == NULL) {
		pam_syslog(pamh, LOG_CRIT, "malloc failed: %m");
		return PAM_SYSTEM_ERR;
	}
	*newcount = count;
	if ((err = pam_set_data(pamh, PACKAGE "_count", (void *) newcount,
	                        cleanup_count)) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "Failed setting data: %s",
		           pam_strerror(pamh, err));
		return err;
	}
	return PAM_SUCCESS;
}

/******************
 *	PAM functions
 ******************/

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
                    int argc, const char **argv) {
	const char *user;
	int err = pam_get_user(pamh, &user, NULL);
	if (err != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "pam_get_user failed: %s",
		           pam_strerror(pamh, err));
		return err;
	}

	int count = get_count_cached(pamh, user);
	if (count == -1) {
		count = modify_count(pamh, user, 1);
		if (count == -1)
			return PAM_SYSTEM_ERR;
		err = set_count_cached(pamh, user, count);
		if (err != PAM_SUCCESS)
			return err;
	}

	if (count == 1)
		return PAM_SUCCESS;

	return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
                     int argc, const char **argv) {
	const char *user;
	int err = pam_get_user(pamh, &user, NULL);
	if (err != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "pam_get_user failed: %s",
		           pam_strerror(pamh, err));
		return err;
	}

	int count = get_count_cached(pamh, user);
	if (count == -1) {
		count = modify_count(pamh, user, -1);
		if (count == -1)
			return PAM_SYSTEM_ERR;
		err = set_count_cached(pamh, user, count);
		if (err != PAM_SUCCESS)
			return err;
	}

	if (count == 0)
		return PAM_SUCCESS;

	return PAM_IGNORE;
}
