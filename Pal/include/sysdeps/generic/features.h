/*
   This file is part of Graphene Library OS.
   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.
   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * features.h
 *
 * This file contains definition of function attributes.
 */

#ifndef _FEATURES_H
#define _FEATURES_H

#ifdef _ALL_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(_POSIX_SOURCE) && !defined(_POSIX_C_SOURCE) \
 && !defined(_XOPEN_SOURCE) && !defined(_GNU_SOURCE) \
 && !defined(_BSD_SOURCE) && !defined(__STRICT_ANSI__)
#define _BSD_SOURCE 1
#define _XOPEN_SOURCE 700
#endif

#if __STDC_VERSION__ >= 199901L
#define __restrict restrict
#elif !defined(__GNUC__)
#define __restrict
#endif

#if __STDC_VERSION__ >= 199901L || defined(__cplusplus)
#define __inline inline
#endif

#if __STDC_VERSION__ >= 201112L
#elif defined(__GNUC__)
#define _Noreturn __attribute__((__noreturn__))
#else
#define _Noreturn
#endif

#endif
