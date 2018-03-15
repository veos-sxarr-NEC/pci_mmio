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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pci/pci.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <limits.h>
#include <libudev.h>
#include "pcim.h"

static inline char *
sysfs_name(struct pci_access *a)
{
  return pci_get_param(a, "sysfs.path");
}

static struct pcim_access *_get_pcim(const char *fname, int bar)
{
	int ret;
	int fd;
	struct stat st;
	struct pcim_access *pcim;

	pcim = (struct pcim_access *)malloc(sizeof(struct pcim_access));
	if (pcim == NULL) {
		fprintf(stderr, "malloc of pcim_access failed.\n");
		return NULL;
	}

	fd = open(fname, O_RDWR | O_SYNC);
	if (fd < 0) {
		fprintf(stderr, "Open failed '%s': %s\n",
				fname, strerror(errno));
		goto err_open;
	}
	ret = fstat(fd, &st);
	if (ret < 0) {
		fprintf(stderr, "fstat failed '%s': %s\n",
				fname, strerror(errno));
		goto err_fstat;
	}
	pcim->map_size = st.st_size;
	pcim->iomem = (unsigned char *)mmap(NULL, pcim->map_size,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (pcim->iomem == (unsigned char *)MAP_FAILED)
		fprintf(stderr, "mmap failed '%s': %s\n",
				fname, strerror(errno));
	close(fd);
	return pcim;

err_fstat:
	close(fd);
err_open:
	free(pcim);
	return NULL;
}

struct pcim_access *get_pcim(int domain, int bus, int slot, int func,
		int bar)
{
	int ret;
	struct pcim_access *pcim;
	struct pci_access *pacc;
	char fname[PATH_MAX];

	pacc = pci_alloc();
	pci_init(pacc);

	ret = snprintf(fname, PATH_MAX,
			"%s/devices/%04x:%02x:%02x.%d/resource%d",
			sysfs_name(pacc), domain, bus, slot, func, bar);
	pci_cleanup(pacc);
	if (ret < 0 || ret >= PATH_MAX) {
		fprintf(stderr, "file name too long.\n");
		return NULL;
	}
	pcim = _get_pcim(fname, bar);

	return pcim;
}

struct pcim_access *get_pcim_devfile(const char *devfile, int bar)
{
	int ret;
	char fname[PATH_MAX];
	int fd;
	struct stat sb;
	struct pcim_access *pcim;
	struct udev *udev;
	struct udev_device *udev_dev;

	udev = udev_new();
	fd = open(devfile, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Open failed '%s': %s\n",
				devfile, strerror(errno));
		return NULL;
	}
	ret = fstat(fd, &sb);
	if (ret < 0) {
		fprintf(stderr, "fstat failed '%s': %s\n",
				devfile, strerror(errno));
		goto err_fstat;
	}

	udev_dev = udev_device_new_from_devnum(udev, 'c', sb.st_rdev);
	ret = snprintf(fname, PATH_MAX,
			"%s/device/resource%d",
			udev_device_get_syspath(udev_dev), bar);
	if (ret < 0 || ret >= PATH_MAX) {
		fprintf(stderr, "file name too long.\n");
		goto err_snprintf;
	}
	pcim = _get_pcim(fname, bar);

	return pcim;

err_snprintf:
err_fstat:
	close(fd);
	return NULL;
}

void free_pcim(struct pcim_access *accs)
{
	int ret;

	ret = munmap(accs->iomem, accs->map_size);
	if (ret)
		fprintf(stderr, "munmap failed: %s\n", strerror(errno));
	free(accs);
}

int pcim_read_block(struct pcim_access *accs, off_t pos, void *data,
		size_t size)
{
	if (pos + size > accs->map_size)
		return -1;
	memcpy(data, accs->iomem + pos, size);
	return 0;
}

int pcim_write_block(struct pcim_access *accs, off_t pos, void *data,
		size_t size)
{
	if (pos + size > accs->map_size)
		return -1;
	memcpy(accs->iomem + pos, data, size);
	return 0;
}

int pcim_read_qword(struct pcim_access *accs, off_t pos,
		unsigned long long *data)
{
	return pcim_read_block(accs, pos, data, 8);
}

int pcim_write_qword(struct pcim_access *accs, off_t pos,
		unsigned long long data)
{
	return pcim_write_block(accs, pos, &data, 8);
}

int pcim_dump_to_file(struct pcim_access *accs, const char *filename)
{
	FILE *dfile;

	dfile = fopen(filename, "w+");
	if (!dfile) {
		fprintf(stderr, "Open failed '%s': %s\n",
				filename, strerror(errno));
		return -1;
	}
	fwrite(accs->iomem, accs->map_size, 1, dfile);
	fclose(dfile);

	return 0;
}
