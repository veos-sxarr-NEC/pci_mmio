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
#include "pcim.h"

#define READ_MODE (0)
#define WRITE_MODE (1)
#define DUMP_MODE (2)
#define PCI_SLOT_MODE (0)
#define DEV_FILE_MODE (1)

#ifdef DEBUG
#define DPRINTF(...) do { \
	fprintf(stderr, "DEBUG: "__VA_ARGS__); } \
	while (0)
#else
#define DPRINTF(...) do {} while (0)
#endif

static void print_usage(int exit_code)
{
	printf("Usage: pci_mmio [<options>]\n"
			"\nSelection of devices:\n"
			"-s [[[[<domain>]:]<bus>]:][<slot>][.[<func>]]\n"
			"-f <filename>\tPCI device driver file\n"
			"\nSelection of BARs:\n"
			"-b <BAR number>\n"
			"\nBAR Access Modes:\n"
			"-r \t\tRead Mode\n"
			"-w \t\tWrite Mode\n"
			"-D <filename>\t"
			"Dump to file (IO Options will be ignored)\n"
			"\nIO Options:\n"
			"-o <offset>\tOffset from top of each BAR\n"
			"-O\t\tIgnore Offset error check\n"
			"-d <data>\tData to write\n"
			"-l <length>\tIO Length\n");
	exit(exit_code);
}

int enable_command_memory(struct pci_access *pacc, struct pci_filter *filter)
{
	struct pci_dev *dev;
	u16 cmd;
	int ret = 0;

	dev = pci_get_dev(pacc, filter->domain, filter->bus,
			filter->slot, filter->func);
	cmd = pci_read_word(dev, PCI_COMMAND);
	if ((cmd & PCI_COMMAND_MEMORY) == 0) {
		ret = pci_write_word(dev, PCI_COMMAND,
				cmd | PCI_COMMAND_MEMORY);
		DPRINTF("Memory Space Enabled\n");
	}

	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	int bar = -1;
	int rw_mode = -1;
	int dev_mode = -1;
	int offset_check_ignore = 0;
	char *msg;
	off_t offset, acc_offset;
	size_t length = 8;
	unsigned long long data;
	int data_flag = 0;
	char fname[PATH_MAX];
	char dfile[PATH_MAX];
	struct pci_access *pacc;
	struct pci_filter filter;
	struct pcim_access *accs;

	pacc = pci_alloc();
	pci_init(pacc);
	pci_scan_bus(pacc);
	pci_filter_init(pacc, &filter);

	filter.domain = 0;
	filter.bus = 0;
	filter.slot = 0;
	filter.func = 0;
	offset = 0;

	while ((ret = getopt(argc, argv, "hs:f:b:o:rwd:l:D:O")) != -1)
		switch (ret) {
			case 'h':
				print_usage(0);
				break;
			case 's':
				if (dev_mode == DEV_FILE_MODE) {
					fprintf(stderr,
						"-s and -f can't be"
						" used at the same time\n");
					print_usage(EXIT_FAILURE);
				}
				msg = pci_filter_parse_slot(&filter, optarg);
				if (msg) {
					fprintf(stderr, "-s failed: %s\n", msg);
					return -1;
				}
				dev_mode = PCI_SLOT_MODE;
				break;
			case 'f':
				if (dev_mode == PCI_SLOT_MODE) {
					fprintf(stderr,
						"-s and -f can't be"
						" used at the same time\n");
					print_usage(EXIT_FAILURE);
				}
				strncpy(fname, optarg, PATH_MAX);
				dev_mode = DEV_FILE_MODE;
				break;
			case 'b':
				bar = atoi(optarg);
				break;
			case 'o':
				offset = strtoull(optarg, NULL, 0);
				break;
			case 'r':
				if (rw_mode != READ_MODE &&
						rw_mode != -1) {
					fprintf(stderr,
						"-r and -w are exclusive\n");
					print_usage(EXIT_FAILURE);
				}
				rw_mode = READ_MODE;
				break;
			case 'w':
				if (rw_mode != WRITE_MODE &&
						rw_mode != -1) {
					fprintf(stderr,
						"-r and -w are exclusive\n");
					print_usage(EXIT_FAILURE);
				}
				rw_mode = WRITE_MODE;
				break;
			case 'D':
				if (rw_mode != DUMP_MODE &&
						rw_mode != -1) {
					fprintf(stderr,
					"-r, -w and -D are exclusive\n");
					print_usage(EXIT_FAILURE);
				}
				rw_mode = DUMP_MODE;

				strncpy(dfile, optarg, PATH_MAX);
				break;
			case 'd':
				data = strtoull(optarg, NULL, 0);
				data_flag = 1;
				break;
			case 'l':
				length = strtoll(optarg, NULL, 0);
				break;
			case 'O':
				offset_check_ignore = 1;
				break;
			default:
				print_usage(EXIT_FAILURE);
				break;
		}
	if (dev_mode == -1 || bar == -1 || rw_mode == -1) {
		fprintf(stderr, "Missing mandatory options.\n");
		print_usage(EXIT_FAILURE);
	}
	if (rw_mode == WRITE_MODE && !data_flag) {
		fprintf(stderr, "Specify data to write.\n");
		print_usage(EXIT_FAILURE);
	}

	if (length % 8 != 0) {
		fprintf(stderr,
				"length must be"
				" 8byte aligned\n");
		print_usage(EXIT_FAILURE);
	}
	if ((offset % 8 != 0) && !offset_check_ignore) {
		fprintf(stderr,
				"offset must be"
				" 8byte aligned\n");
		print_usage(EXIT_FAILURE);
	}

	if (dev_mode == PCI_SLOT_MODE) {
		accs = get_pcim(filter.domain, filter.bus,
				filter.slot, filter.func, bar);
		enable_command_memory(pacc, &filter);
	} else
		accs = get_pcim_devfile(fname, bar);
	if (accs == NULL) {
		fprintf(stderr, "get_pcim() failed.\n");
		exit(EXIT_FAILURE);
	}

	if (rw_mode == DUMP_MODE) {
		ret = pcim_dump_to_file(accs, dfile);
		if (ret)
			exit(EXIT_FAILURE);
		goto success;
	}

	for (acc_offset = offset; acc_offset < offset + length;
			acc_offset += 8) {
		if (rw_mode == READ_MODE) {
			ret = pcim_read_qword(accs, acc_offset, &data);
			if (!ret)
				printf("0x%08lx: 0x%016llx\n", acc_offset,
						data);
			else
				exit(EXIT_FAILURE); /* TODO: error message */
		} else {
			DPRINTF("write 0x%08lx: 0x%016llx\n", acc_offset,
					data);
			ret = pcim_write_qword(accs, acc_offset, data);
			if (ret)
				exit(EXIT_FAILURE); /* TODO: error message */
		}
	}

success:
	pci_cleanup(pacc);
	free_pcim(accs);
	return 0;
}
