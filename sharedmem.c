#include <sys/mman.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rmtfs.h"

static int rmtfs_mem_enumerate(void);

static uint64_t rmtfs_mem_address;
static uint64_t rmtfs_mem_size;
static void *rmtfs_mem_base;
static int rmtfs_mem_fd;

int rmtfs_mem_open(void)
{
	void *base;
	int ret;
	int fd;

	ret = rmtfs_mem_enumerate();
	if (ret < 0)
		return ret;

	fd = open("/dev/mem", O_RDWR|O_SYNC);
	if (fd < 0) {
		fprintf(stderr, "failed to open /dev/mem\n");
		return fd;
	}

	base = mmap(0, rmtfs_mem_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, rmtfs_mem_address);
	if (base == MAP_FAILED) {
		fprintf(stderr, "failed to mmap: %s\n", strerror(errno));
		return -errno;
	}

	rmtfs_mem_base = base;
	rmtfs_mem_fd = fd;

	return 0;
}

int64_t rmtfs_mem_alloc(size_t alloc_size)
{
	if (alloc_size > rmtfs_mem_size) {
		fprintf(stderr,
			"[RMTFS] rmtfs shared memory not large enough for allocation request 0x%zx vs 0x%lx\n",
			alloc_size, rmtfs_mem_size);
		return -EINVAL;
	}

	return rmtfs_mem_address;
}

void rmtfs_mem_free(void)
{
}

void *rmtfs_mem_ptr(unsigned phys_address, size_t len)
{
	uint64_t start;
	uint64_t end;

	start = phys_address;
	end = start + len;

	if (start < rmtfs_mem_address || end > rmtfs_mem_address + rmtfs_mem_size)
		return NULL;

	return rmtfs_mem_base + phys_address - rmtfs_mem_address;
}

void rmtfs_mem_close(void)
{
	munmap(rmtfs_mem_base, rmtfs_mem_size);
	close(rmtfs_mem_fd);

	rmtfs_mem_fd = -1;
	rmtfs_mem_base = MAP_FAILED;
}

static int rmtfs_mem_enumerate(void)
{
	union {
		uint32_t dw[2];
		uint64_t qw[2];
	} reg;
	struct dirent *de;
	int basefd;
	int dirfd;
	int regfd;
	DIR *dir;
	int ret = 0;
	int n;

	basefd = open("/proc/device-tree/reserved-memory/", O_DIRECTORY);
	dir = fdopendir(basefd);
	if (!dir) {
		fprintf(stderr,
			"Unable to open reserved-memory device tree node: %s\n",
			strerror(-errno));
		close(basefd);
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		if (strncmp(de->d_name, "rmtfs", 5) != 0)
			continue;

		dirfd = openat(basefd, de->d_name, O_DIRECTORY);
		if (dirfd < 0) {
			fprintf(stderr, "failed to open %s: %s\n",
				de->d_name, strerror(-errno));
			ret = -1;
			goto out;
		}

		regfd = openat(dirfd, "reg", O_RDONLY);
		if (regfd < 0) {
			fprintf(stderr, "failed to open reg of %s: %s\n",
				de->d_name, strerror(-errno));
			ret = -1;
			goto out;
		}

		n = read(regfd, &reg, sizeof(reg));
		if (n == 2 * sizeof(uint32_t)) {
			rmtfs_mem_address = be32toh(reg.dw[0]);
			rmtfs_mem_size = be32toh(reg.dw[1]);
		} else if (n == 2 * sizeof(uint64_t)) {
			rmtfs_mem_address = be64toh(reg.qw[0]);
			rmtfs_mem_size = be64toh(reg.qw[1]);
		} else {
			fprintf(stderr, "failed to read reg of %s: %s\n",
				de->d_name, strerror(-errno));
			ret = -1;
		}

		close(regfd);
		close(dirfd);
		break;
	}

out:
	closedir(dir);
	close(basefd);
	return ret;
}
