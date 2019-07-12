#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rmtfs.h"

#define MAX_CALLERS 10

struct partition {
	const char *path;
	const char *actual;
};

struct caller {
	unsigned id;
	unsigned node;
	int fd;
	unsigned dev_error;
	const struct partition *partition;
};

static const char *storage_dir = "/boot";

static const struct partition partition_table[] = {
	{ "/boot/modem_fs1", "modem_fs1" },
	{ "/boot/modem_fs2", "modem_fs2" },
	{ "/boot/modem_fsc", "modem_fsc" },
	{ "/boot/modem_fsg", "modem_fsg" },
	{}
};

static struct caller caller_handles[MAX_CALLERS];

int storage_open(const char *storage_root)
{
	int i;

	if (storage_root)
		storage_dir = storage_root;

	for (i = 0; i < MAX_CALLERS; i++) {
		caller_handles[i].id = i;
		caller_handles[i].fd = -1;
	}

	return 0;
}

int storage_get(unsigned node, const char *path)
{
	char *fspath;
	const struct partition *part;
	struct caller *caller = NULL;
	size_t pathlen;
	int saved_errno;
	int fd;
	int i;

	for (part = partition_table; part->path; part++) {
		if (strcmp(part->path, path) == 0)
			goto found;
	}

	fprintf(stderr, "[RMTFS storage] request for unknown partition '%s', rejecting\n", path);
	return -EPERM;

found:
	/* Check if this node already has the requested path open */
	for (i = 0; i < MAX_CALLERS; i++) {
		if (caller_handles[i].fd != -1 &&
		    caller_handles[i].node == node &&
		    caller_handles[i].partition == part)
			return caller_handles[i].id;
	}

	for (i = 0; i < MAX_CALLERS; i++) {
		if (caller_handles[i].fd == -1) {
			caller = &caller_handles[i];
			break;
		}
	}
	if (!caller) {
		fprintf(stderr, "[storage] out of free caller handles\n");
		return -EBUSY;
	}

	pathlen = strlen(storage_dir) + strlen(part->actual) + 2;
	fspath = alloca(pathlen);
	snprintf(fspath, pathlen, "%s/%s", storage_dir, part->actual);
	fd = open(fspath, O_RDWR);
	if (fd < 0) {
		saved_errno = errno;
		fprintf(stderr, "[storage] failed to open '%s' (requested '%s'): %s\n",
				fspath, part->path, strerror(saved_errno));
		return -saved_errno;
	}

	caller->node = node;
	caller->fd = fd;
	caller->partition = part;

	return caller->id;
}

int storage_put(unsigned node, int caller_id)
{
	struct caller *caller;

	if (caller_id >= MAX_CALLERS)
		return -EINVAL;

	caller = &caller_handles[caller_id];
	if (caller->node != node)
		return -EINVAL;

	close(caller->fd);
	caller->fd = -1;
	caller->partition = NULL;

	return 0;
}

int storage_get_handle(unsigned node, int caller_id)
{
	struct caller *caller;

	if (caller_id >= MAX_CALLERS)
		return -EINVAL;

	caller = &caller_handles[caller_id];
	if (caller->node != node)
		return -EINVAL;

	return caller->fd;
}

int storage_get_error(unsigned node, int caller_id)
{
	struct caller *caller;

	if (caller_id >= MAX_CALLERS)
		return -EINVAL;

	caller = &caller_handles[caller_id];
	if (caller->node != node)
		return -EINVAL;

	return caller->dev_error;
}

void storage_close(void)
{
	int i;

	for (i = 0; i < MAX_CALLERS; i++) {
		if (caller_handles[i].fd >= 0)
			close(caller_handles[i].fd);
	}
}

ssize_t storage_pread(int fildes, void *buf, size_t nbyte, off_t offset)
{
	return pread(fildes, buf, nbyte, offset);
}

ssize_t storage_pwrite(int fildes, const void *buf, size_t nbyte, off_t offset)
{
	return pwrite(fildes, buf, nbyte, offset);
}

