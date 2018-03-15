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

AM_CFLAGS = -I./lib
AM_LDFLAGS = -L./lib -lpcim

bin_PROGRAMS = pci_mmio
pci_mmio_SOURCES = pci_mmio.c

SUBDIRS = lib
