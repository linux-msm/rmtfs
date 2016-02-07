#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rmtfs.h"

#define SHAREDMEM_BASE 0x0fd80000
#define SHAREDMEM_SIZE 0x180000

static uint64_t rmtfs_mem_address = SHAREDMEM_BASE;
static uint64_t rmtfs_mem_size = SHAREDMEM_SIZE;
static void *rmtfs_mem_base;
static bool rmtfs_mem_busy;
static int rmtfs_mem_fd;

int rmtfs_mem_open(void)
{
	void *base;
	int fd;

	fd = open("/dev/mem", O_RDWR|O_SYNC);
	if (fd < 0) {
		fprintf(stderr, "failed to open /dev/mem\n");
		return fd;
	}

	base = mmap(0, SHAREDMEM_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, SHAREDMEM_BASE);
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
	if (rmtfs_mem_busy) {
		fprintf(stderr, "[RMTFS] rmtfs shared memory already allocated\n");
		return -EBUSY;
	}

	if (alloc_size > rmtfs_mem_size) {
		fprintf(stderr,
			"[RMTFS] rmtfs shared memory not large enough for allocation request 0x%zx vs 0x%lx\n",
			alloc_size, rmtfs_mem_size);
		return -EINVAL;
	}

	rmtfs_mem_busy = true;

	return rmtfs_mem_address;
}

void rmtfs_mem_free(void)
{
	rmtfs_mem_busy = false;
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
