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

#include "libfdt.h"

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

static ssize_t dtb_size(void *dtb)
{
	return be32_to_cpu(((struct dtb_hdr *)dtb)->totalsize);
}

static int dtb_find_node(void *dtb, char *node_name)
{
	int node = 0, depth = 0;

	do {
		const char *name;
		int lenp;

		node = fdt_next_node(dtb, node, &depth);
		if (node < 0)
			break;

		name = fdt_get_name(dtb, node, &lenp);
		if (!name)
			continue;

		if (!strcmp(node_name, name))
			return node;
	} while (1);

	return -1;
}

static int dtb_set_prop(void *dtb, char *node_name, char *prop_name,
			void *value, size_t lenv)
{
	int node;

	node = dtb_find_node(dtb, node_name);
	if (node < 0) {
		fprintf(stderr, "'%s' not found\n", node_name);
		return -EINVAL;
	}

	return fdt_setprop(dtb, node, prop_name, value, lenv);
}

/*static int dtb_dev_print(void *dtb, char *name)
{
	const struct fdt_property *prop;
	int node, lenp;

	node = dtb_find_node(dtb, name);
	if (node < 0) {
		fprintf(stderr, "unknown device %s\n", name);
		return -EINVAL;
	}

	prop = fdt_get_property(dtb, node, "status", &lenp);
	if (prop && strcmp("ok", prop->data) && strcmp("okay", prop->data))
		printf("%s (disabled)\n", name);
	else
		printf("%s\n", name);

	printf("%s {\n");
	fdt_for_each_property_offset(propoff, dtb, node) {
		struct fdt_property *prop;
		const char *prop_name;
		int lenp;

		prop = fdt_get_property_by_offset(dtb, propoff, &lenp);
		prop_name = fdt_string(dtb, fdt32_to_cpu(prop->nameoff));

		printf("\t%s = %s\n", prop_name, prop->data);
	}
	printf("};\n");
}*/

static int dtb_print_all_devs(void *dtb)
{
	int node = 0, depth = 0;

	do {
		const struct fdt_property *prop;
		const char *name;
		int lenp, i;

		node = fdt_next_node(dtb, node, &depth);
		if (node < 0)
			break;

		name = fdt_get_name(dtb, node, &lenp);
		if (!name)
			continue;

		prop = fdt_get_property(dtb, node, "compatible", &lenp);
		if (!prop) /* not a device */
			continue;

		i = depth;
		while (i--)
			printf("  ");
		prop = fdt_get_property(dtb, node, "status", &lenp);
		if (prop && strcmp("ok", prop->data)
			&& strcmp("okay", prop->data)) {
			printf("%s (disabled)\n", name);
		} else {
			printf("%s\n", name);
		}
	} while (1);

	return 0;
}
static void *dtb_load_fromfd(int fd_dtb, int reserve)
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

	dtb = realloc(dtb, dtb_size(dtb) + reserve);
	if (!dtb)
		return NULL;

	to_read = dtb_size(dtb) - sizeof(struct dtb_hdr);
	ret = read(fd_dtb, (void *)dtb + sizeof(struct dtb_hdr), to_read);
	if (ret != to_read) {
		fprintf(stderr, "invalid DTB image\n");
		free(dtb);
		return NULL;
	}

	/* init and add free space */
	memset((void *)dtb + dtb_size(dtb), 0, reserve);
	dtb->totalsize = cpu_to_be32(dtb_size(dtb) + reserve);

	return dtb;
}

static int dtb_enable_device(void *dtb, char *devname, bool enable)
{
	if (enable) {
		return dtb_set_prop(dtb, devname, "status", "ok", sizeof("ok"));
	} else {
		return dtb_set_prop(dtb, devname, "status", "disabled",
				    sizeof("disabled"));
	}
}

static int dtbtool_show_devices(int fd_dtb)
{
	void *dtb;
	int ret;

	dtb = dtb_load_fromfd(fd_dtb, 0);
	if (!dtb)
		return -EINVAL;

	ret = dtb_print_all_devs(dtb);

	free(dtb);

	return ret;
}

static int dtbtool_enable_device(int fd_dtb, int fd_out, char *devname,
				 bool enable)
{
	void *dtb;
	int ret;

	dtb = dtb_load_fromfd(fd_dtb, 32); /* Fix this magic */
	if (!dtb)
		return -EINVAL;

	ret = dtb_enable_device(dtb, devname, enable);
	if (ret) {
		printf ("%d\n", ret);
		free(dtb);
		return ret;
	}

	fdt_pack(dtb);

	ret = write(fd_out, dtb, dtb_size(dtb));
	if (ret != dtb_size(dtb)) {
		fprintf(stderr, "Error writing DTB\n");
		free(dtb);
		return -EINVAL;
	}

	return 0;
}

static const struct option main_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "enable-dev", required_argument, NULL, 'e' },
	{ "disable-dev", required_argument, NULL, 'd' },
	{ "show-devs", no_argument, NULL, 's' },
	{ "out", required_argument, NULL, 'o' },
	{ },
};

int main(int argc, char *argv[])
{
	int ret = 0, fd_dtb = -1, fd_out = -1;
	char *path_dtb = NULL, *path_out = NULL;
	char *devname = NULL;
	bool enable = false;
	bool show_dev = false;

	for (;;) {
		int opt = getopt_long(argc, argv, ":x:u:o:sh", main_options,
				      NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'e':
			enable = true;
			devname = optarg;
			break;
		case 'd':
			enable = false;
			devname = optarg;
			break;
		case 's':
			show_dev = true;
			break;
		case 'o':
			path_out = optarg;
			break;
		case 'h':
			/*usage();*/
			return EXIT_SUCCESS;
		default:
			break;
		}
	}

	path_dtb = argv[optind++];
	if (path_dtb) {
		fd_dtb = open(path_dtb, O_RDWR);
		if (fd_dtb < 0) {
			fprintf(stderr, "unable to open DTB %s\n",
				path_dtb);
			return -EINVAL;
		}
	} else {
		fd_dtb = STDIN_FILENO;
	}

	if (!path_out && path_dtb)
		path_out = path_dtb;

	if (path_out) {
		fd_out = open(path_out, O_WRONLY|O_CREAT, 0644);
		if (fd_out < 0) {
			fprintf(stderr, "unable to out file %s\n", path_out);
			close(fd_dtb);
			return -EINVAL;
		}
	} else {
		fd_out = STDOUT_FILENO;
	}

	if (show_dev) {
		ret = dtbtool_show_devices(fd_dtb);
	} else if (devname) {
		ret = dtbtool_enable_device(fd_dtb, fd_out, devname, enable);
	}

	close(fd_out);
	close(fd_dtb);

	return ret;
}
