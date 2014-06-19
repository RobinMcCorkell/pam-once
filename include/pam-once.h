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

#ifndef PAM_ONCE_H
#define PAM_ONCE_H

#include <security/_pam_types.h>

#define PAM_ONCE_DEBUG 0x0100U

int pam_once_open_session(pam_handle_t *pamh, int flags);
int pam_once_close_session(pam_handle_t *pamh, int flags);

#endif
