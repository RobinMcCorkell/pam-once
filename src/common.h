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

#include "config.h"

#define COUNT_CMD LIBEXECDIR "/po_count"
#define COUNT_PATH RUNDIR "/" PACKAGE

/* po_count return codes */
#define ERR_SUCCESS 0
#define ERR_GENERIC 1
#define ERR_ARGS    2
#define ERR_USER    3
#define ERR_FILE    4
#define ERR_SYSTEM  5
#define ERR_IGNORE  6

