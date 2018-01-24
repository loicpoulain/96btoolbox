/*
 * Copyright (C) 2018 Linaro Limited
 * Copyright (C) 2018 Loic Poulain <loic.poulain@linaro.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <byteswap.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <limits.h>

#include "puff.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le16_to_cpu(val) (val)
#define le32_to_cpu(val) (val)
#define le64_to_cpu(val) (val)
#define cpu_to_le16(val) (val)
#define cpu_to_le32(val) (val)
#define cpu_to_le64(val) (val)
#define be16_to_cpu(val) bswap_16(val)
#define be32_to_cpu(val) bswap_32(val)
#define be64_to_cpu(val) bswap_64(val)
#define cpu_to_be16(val) bswap_16(val)
#define cpu_to_be32(val) bswap_32(val)
#define cpu_to_be64(val) bswap_64(val)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define le16_to_cpu(val) bswap_16(val)
#define le32_to_cpu(val) bswap_32(val)
#define le64_to_cpu(val) bswap_64(val)
#define cpu_to_le16(val) bswap_16(val)
#define cpu_to_le32(val) bswap_32(val)
#define cpu_to_le64(val) bswap_64(val)
#define be16_to_cpu(val) (val)
#define be32_to_cpu(val) (val)
#define be64_to_cpu(val) (val)
#define cpu_to_be16(val) (val)
#define cpu_to_be32(val) (val)
#define cpu_to_be64(val) (val)
#else
#error "Unknown byte order"
#endif

struct gzip_hdr {
	uint16_t	magic;	/* 0x8b1f */
	uint8_t		method;
	uint8_t		flags;
	uint32_t	time;
	uint8_t		extra_flags;
	uint8_t		os;
	uint8_t		extra[0];
} __attribute__((packed)); /* little endian */
static const char magic_gzip[2] = { 0x1f, 0x8b };
#define METHOD_DEFLATE	0x08
#define FTEXT		0x01
#define FHCRC		0x02
#define FEXTRA		0x04
#define FNAME		0x08
#define FCOMMENT	0x10

struct aboot_hdr {
	uint64_t	magic; /* ANDROID! */
	uint32_t	kernel_size;
	uint32_t	kernel_addr;
	uint32_t	ramdisk_size;
	uint32_t	ramdisk_addr;
	uint32_t	second_size;
	uint32_t	second_addr;
	uint32_t	kernel_tags_addr;
	uint32_t	page_size;
	uint64_t	unused;
	uint8_t		name[16];
	uint8_t		cmdline[512];
	uint64_t	id;
	uint8_t		extra_cmdline[1024];
} __attribute__((packed)); /* little endian */
static const char magic_aboot[8] = { 'A', 'N', 'D', 'R', 'O', 'I', 'D', '!' };

struct dtb_hdr {
	uint32_t magic; /* 0xd00dfeed */
	uint32_t totalsize;
	uint32_t off_dt_struct;
	uint32_t off_dt_strings;
	uint32_t off_mem_rsvmap;
	uint32_t version;
	uint32_t last_comp_version;
	uint32_t boot_cpuid_phys;
	uint32_t size_dt_strings;
	uint32_t size_dt_struct;
} __attribute__((packed)); /* Big endian */
uint32_t magic_dtb = 0xd00dfeed;

static ssize_t gzip_size(struct gzip_hdr *gzip, size_t gzip_len)
{
	unsigned long max_ulong = -1;
	size_t extra_sz = 0;
	int err;
	void *ptr;

	/* RFC 1952 */

	if (memcmp(&gzip->magic, magic_gzip, sizeof(magic_gzip))) {
		fprintf(stderr, "error: No gzipped kernel found\n");
		return -EINVAL;
	}

	if (gzip->method != METHOD_DEFLATE) {
		fprintf(stderr, "error: Unsupported gzip compression method\n");
		return -EINVAL;
	}

	if (gzip->flags & FEXTRA) {
		uint16_t xlen = le16_to_cpu(*((uint16_t *)&gzip->extra[0]));
		extra_sz = sizeof(xlen) + xlen;
	}

	if (gzip->flags & FNAME)
		while(gzip->extra[extra_sz++]); /* NULL terminated name */

	if (gzip->flags & FCOMMENT)
		while(gzip->extra[extra_sz++]); /* NULL terminated name */

	if (gzip->flags & FHCRC)
		extra_sz += 2; /* crc16*/

	/* compressed block start here */
	ptr = (void *)gzip + sizeof(*gzip) + extra_sz;

	/* don't really want to inflate, just walk the file to get its size */
	err = puff(NULL, &max_ulong, ptr, &gzip_len);
	if (err) {
		fprintf(stderr, "error inflating kernel (%d)\n", err);
		return -EINVAL;
	}

	ptr += gzip_len;

	/* gzip footer */
	ptr += 4; /* crc32 */
	ptr += 4; /* uncompressed data size */

	return (ptr - (void *)gzip);
}

static ssize_t kernel_size(void *kernel)
{
	return gzip_size(kernel, UINT_MAX);
}

static ssize_t dtb_size(void *dtb)
{
	return be32_to_cpu(((struct dtb_hdr *)dtb)->totalsize);
}

static ssize_t aboot_size(const struct aboot_hdr *aboot)
{
	int page_size, n, m, o;

	page_size = le32_to_cpu(aboot->page_size);
	n = (le32_to_cpu(aboot->kernel_size) + page_size - 1) / page_size;
	m = (le32_to_cpu(aboot->ramdisk_size) + page_size - 1) / page_size;
	o = (le32_to_cpu(aboot->second_size) + page_size - 1) / page_size;

 	return (1 + n + m + o) * page_size;
}

static void *aboot_load_fromfd(int fd_aboot)
{
	struct aboot_hdr *aboot;
	int ret, to_read;

	aboot = malloc(sizeof(*aboot));
	if (!aboot)
		return NULL;

	ret = read(fd_aboot, aboot, sizeof(*aboot));
	if (ret != sizeof(*aboot)) {
		fprintf(stderr, "invalid boot image\n");
		free(aboot);
		return NULL;
	}

	if (memcmp(&aboot->magic, magic_aboot, sizeof(magic_aboot))) {
		fprintf(stderr, "invalid boot image (bad magic)\n");
		free(aboot);
		return NULL;
	}

	aboot = realloc(aboot, aboot_size(aboot));
	if (!aboot)
		return NULL;

	to_read = aboot_size(aboot) - sizeof(struct aboot_hdr);
	ret = read(fd_aboot, (void *)aboot + sizeof(struct aboot_hdr), to_read);
	if (ret != to_read) {
		fprintf(stderr, "invalid boot image\n");
		free(aboot);
		return NULL;
	}

	return aboot;
}

static void *aboot_get_dtb(struct aboot_hdr *aboot)
{
	int page_sz, kernel_sz;
	struct dtb_hdr *dtb;
	void *kernel;

	page_sz = le32_to_cpu(aboot->page_size);
	kernel = (void *)aboot + page_sz;

	kernel_sz = kernel_size(kernel);
	if (kernel_sz < 0)
		return NULL;

	dtb = kernel + kernel_sz;

	/* Check DTB magic */
	if (be32_to_cpu(dtb->magic) != magic_dtb) {
		fprintf(stderr, "DTB not found in boot image\n");
		return NULL;
	}

	return dtb;
}

static void *aboot_get_kernel(void *aboot)
{
	return aboot + le32_to_cpu(((struct aboot_hdr*)aboot)->page_size);
}

static void *aboot_get_ramdisk(void *boot)
{
	struct aboot_hdr *aboot = boot;
	int page_size, n;

	page_size = le32_to_cpu(aboot->page_size);
	n = (le32_to_cpu(aboot->kernel_size) + page_size - 1) / page_size;

	return (void *)aboot + (1 + n) * page_size;
}

static void *aboot_get_end(void *boot)
{
	return boot + aboot_size(boot);
}

static void *aboot_update_dtb(void *boot, void *dtb, bool force)
{
	struct aboot_hdr *aboot, *old_aboot = boot;
	struct dtb_hdr *old_dtb;
	void *kernel, *ptr;
	ssize_t page_sz, kernel_sz, align_sz;

	page_sz = le32_to_cpu(old_aboot->page_size);

	kernel = aboot_get_kernel(old_aboot);
	if (!kernel)
		return NULL;

	kernel_sz = kernel_size(kernel);

	old_dtb = aboot_get_dtb(old_aboot);
	if (!old_dtb)
		return NULL;

	/* Check DTB version */
	if (old_dtb->version != ((struct dtb_hdr *)dtb)->version) {
		fprintf(stderr, "DTB version mismatch, Old=%d New=%d\n",
			be32_to_cpu(old_dtb->version),
			be32_to_cpu(((struct dtb_hdr *)dtb)->version));
		if (force) {
			printf("forcing update\n");
		} else {
			fprintf(stderr, "Use -f option to force update\n");
			return NULL;
		}
	}

	aboot = malloc(aboot_size(old_aboot) + dtb_size(dtb));
	if (!aboot)
		return NULL;

	/* Now we can generate our new abootimg */
	ptr = aboot;

	/* copy first block, aboot hdr + kernel.gz */
	memcpy(ptr, old_aboot, page_sz + kernel_sz);
	ptr += page_sz + kernel_sz;

	/* modify kernel size (kernel.gz + dtb) */
	aboot->kernel_size = cpu_to_le32(kernel_sz + dtb_size(dtb));

	/* copy new DTB */
	memcpy(ptr, dtb, dtb_size(dtb));
	ptr += dtb_size(dtb);

	/* align on page */
	align_sz = page_sz - le32_to_cpu(aboot->kernel_size) % page_sz;
	if (align_sz != page_sz) {
		memset(ptr, 0, align_sz);
		ptr += align_sz;
	}

	/* copy remaining data */
	memcpy(ptr, aboot_get_ramdisk(old_aboot),
	       aboot_get_end(old_aboot) - aboot_get_ramdisk(old_aboot));

	return aboot;
}

static void *dtb_load_fromfd(int fd_dtb)
{
	struct dtb_hdr *dtb;
	int ret, to_read;

	dtb = malloc(sizeof(*dtb));
	if (!dtb)
		return NULL;

	ret = read(fd_dtb, dtb, sizeof(*dtb));
	if (ret != sizeof(*dtb)) {
		fprintf(stderr, "invalid DTB\n");
		free(dtb);
		return NULL;
	}

	/* Check DTB magic */
	if (be32_to_cpu(dtb->magic) != magic_dtb) {
		fprintf(stderr, "invalid DTB (bad magic)\n");
		return NULL;
	}

	dtb = realloc(dtb, dtb_size(dtb));
	if (!dtb)
		return NULL;

	to_read = dtb_size(dtb) - sizeof(struct dtb_hdr);
	ret = read(fd_dtb, (void *)dtb + sizeof(struct dtb_hdr), to_read);
	if (ret != to_read) {
		fprintf(stderr, "invalid DTB image\n");
		free(dtb);
		return NULL;
	}

	return dtb;
}

static int dbboot_fdt_extract(int fd_boot, int fd_fdt)
{
	void *aboot, *dtb;

	aboot = aboot_load_fromfd(fd_boot);
	if (!aboot)
		return -EINVAL;

	dtb = aboot_get_dtb(aboot);
	if (!dtb)
		return -EINVAL;

	write(fd_fdt, dtb, dtb_size(dtb));

	return 0;
}

static int dbboot_fdt_update(int fd_boot, int fd_fdt, int fd_dst)
{
	void *aboot, *new_aboot, *dtb;

	aboot = aboot_load_fromfd(fd_boot);
	if (!aboot)
		return -EINVAL;

	dtb = dtb_load_fromfd(fd_fdt);
	if (!dtb) {
		free(aboot);
		return -EINVAL;
	}

	new_aboot = aboot_update_dtb(aboot, dtb, false);
	if (!new_aboot)
		return -EINVAL;

	if (fd_boot == fd_dst)
		lseek(fd_dst, 0, 0);

	write(fd_dst, new_aboot, aboot_size(new_aboot));

	free(new_aboot);
	free(aboot);
	free(dtb);

	return 0;
}

static int dbboot_info(int fd_boot)
{
	struct aboot_hdr *aboot;

	aboot = aboot_load_fromfd(fd_boot);
	if (!aboot)
		return -EINVAL;


	printf("name:    %s\n", aboot->name);
	printf("aboot size:    %ld bytes\n", aboot_size(aboot));
	printf("kernel.gz+dtb: %d bytes\n", le32_to_cpu(aboot->kernel_size));
	printf("ramdisk:       %d bytes\n", le32_to_cpu(aboot->ramdisk_size));
	printf("second:        %d bytes\n", le32_to_cpu(aboot->second_size));
	printf("page size:     %d bytes\n", le32_to_cpu(aboot->page_size));
	printf("cmdline: %s\n", aboot->cmdline);

	return 0;
}

static void usage(void)
{
	printf("Usage: dbboot [options] <bootimg>\n" \
	       "options:\n" \
	       "   -x, --extract <arg>\n" \
	       "         Extract blob, valid blob types are:\n" \
	       "                 dtb: device-tree blob\n"  \
	       "   -u, --update <arg> [newblob]\n" \
	       "         Update blob, valid blob types are:\n" \
	       "                 dtb: device-tree blob\n"  \
	       "   -i, --info\n" \
	       "   -o, --out <arg>\n" \
	       "         Output file\n" \
	       );

}

static const struct option main_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "extract", required_argument, NULL, 'x' },
	{ "update", required_argument, NULL, 'u' },
	{ "out", required_argument, NULL, 'o' },
	{ "info", required_argument, NULL, 'i' },
	{ },
};

int main(int argc, char *argv[])
{
	bool extract = false, update = false, info = false;
	int fd_boot = -1, fd_out = -1;
	char *path_boot = NULL, *path_out = NULL;
	char *type = NULL;

	for (;;) {
		int opt = getopt_long(argc, argv, ":x:u:o:hi", main_options,
				      NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'x':
			extract = true;
			type = optarg;
			break;
		case 'u':
			update = true;
			type = optarg;
			break;
		case 'o':
			path_out = optarg;
			break;
		case 'i':
			info = true;
			break;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			break;
		}
	}

	if (!info && !type) {
		fprintf(stderr, "you must specify a blob type\n");
		usage();
		return -EINVAL;
	}

	path_boot = argv[optind++];
	if (!path_boot) {
		fprintf(stderr, "no boot image path specified\n");
		return -EINVAL;
	}

	if (path_boot) {
		fd_boot = open(path_boot, update ? O_RDWR: O_RDONLY);
		if (fd_boot < 0) {
			fprintf(stderr, "unable to open boot image %s\n",
				path_boot);
			return -EINVAL;
		}
	}

	if (path_out) {
		fd_out = open(path_out, O_WRONLY|O_CREAT, 0644);
		if (fd_out < 0) {
			fprintf(stderr, "unable to out file %s\n", path_out);
			close(fd_boot);
			return -EINVAL;
		}
	}

	if (info) {
		dbboot_info(fd_boot);
	} else if (!strcmp(type, "dtb") || !strcmp(type, "fdt")) {
		/* TODO rework this */
		if (extract) {
			if (fd_out < 0)
				fd_out = STDOUT_FILENO;
			return dbboot_fdt_extract(fd_boot, fd_out);
		} else if (update) {
			char *dtb_path = argv[optind++];
			int fd_in = STDIN_FILENO;

			if (dtb_path) {
				fd_in = open(dtb_path, O_RDONLY, 0644);
				if (fd_in < 0) {
					fprintf(stderr, "unable to open %s\n",
					        dtb_path);
					close(fd_boot);
					return -EINVAL;
				}
			}

			if (fd_out < 0)
				fd_out = fd_boot;

			return dbboot_fdt_update(fd_boot, fd_in, fd_out);
		}
	} else {
		fprintf(stderr, "unknown blob type: %s", type);
	}


	return EXIT_SUCCESS;
}
