#
# PCI MMIO tool
#
# Copyright (C) 2017-2018 NEC Corporation
# This file is part of the PCI MMIO tool.
#
# The PCI MMIO tool is free software; you can redistribute it
# and/or modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either version
# 2.1 of the License, or (at your option) any later version.
#
# The PCI MMIO tool is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with the PCI MMIO tool; if not, see
# <http://www.gnu.org/licenses/>.
#
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([pci_mmio], [1.0.2], [t-aoyama@ap.jp.nec.com])
AC_CONFIG_SRCDIR([src/pci_mmio.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([./build-aux])

RELEASE=1
AC_SUBST(RELEASE)

AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_PROG_AR
LT_INIT
AC_CONFIG_MACRO_DIR([m4])
# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([pci], [pci_alloc], [],
	     [AC_MSG_ERROR([pci library support missing/incomplete])])
AC_CHECK_LIB([udev], [udev_new], [],
	     [AC_MSG_ERROR([udev library support missing/incomplete])])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h], [],
		[AC_MSG_ERROR(fcntl.h not found)])
AC_CHECK_HEADERS([limits.h], [],
		[AC_MSG_ERROR(limits.h not found)])
AC_CHECK_HEADERS([stdlib.h], [],
		[AC_MSG_ERROR(stdlib.h not found)])
AC_CHECK_HEADERS([string.h], [],
		[AC_MSG_ERROR(string.h not found)])
AC_CHECK_HEADERS([unistd.h], [],
		[AC_MSG_ERROR(unistd.h not found)])
AC_CHECK_HEADERS([pci/pci.h], [],
		[AC_MSG_ERROR(pci/pci.h not found)])
AC_CHECK_HEADERS([libudev.h], [],
		[AC_MSG_ERROR(libudev.h not found)])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([munmap strerror strtoull])

AC_CONFIG_FILES([Makefile
		 pci_mmio.spec
		 src/Makefile
		 src/lib/Makefile])
AC_OUTPUT
