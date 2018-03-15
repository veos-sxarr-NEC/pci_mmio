/*
 * PCI MMIO tool
 *
 * Copyright (C) 2017-2018 NEC Corporation
 * This file is part of the PCI MMIO tool.
 *
 * The PCI MMIO tool is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * The PCI MMIO tool is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the PCI MMIO tool; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _PCIM_LIB_H
#define _PCIM_LIB_H

struct pcim_access {
	size_t map_size;
	unsigned char *iomem;
};

struct pcim_access *get_pcim(int domain, int bus, int slot, int func, int bar);
struct pcim_access *get_pcim_devfile(const char *devfile, int bar);
void free_pcim(struct pcim_access *accs);
int pcim_read_block(struct pcim_access *accs, off_t pos, void *data,
		size_t size);
int pcim_write_block(struct pcim_access *accs, off_t pos, void *data,
		size_t size);
int pcim_read_qword(struct pcim_access *accs, off_t pos,
		unsigned long long *data);
int pcim_write_qword(struct pcim_access *accs, off_t pos,
		unsigned long long data);
int pcim_dump_to_file(struct pcim_access *accs, const char *filename);
#endif
