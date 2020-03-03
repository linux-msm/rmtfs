#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rmtfs.h"

#define MAX_CALLERS 10
#define STORAGE_MAX_SIZE (16 * 1024 * 1024)

#define BY_PARTLABEL_PATH "/dev/disk/by-partlabel"

#define MIN(x, y) ((x) < (y) ? (x) : (y))

struct partition {
	const char *path;
	const char *actual;
	const char *partlabel;
};

struct rmtfd {
	unsigned id;
	unsigned node;
	int fd;
	unsigned dev_error;
	const struct partition *partition;

	void *shadow_buf;
	size_t shadow_len;
};

static const char *storage_dir = "/boot";
static int storage_read_only;
static int storage_use_partitions;

static const struct partition partition_table[] = {
	{ "/boot/modem_fs1", "modem_fs1", "modemst1" },
	{ "/boot/modem_fs2", "modem_fs2", "modemst2" },
	{ "/boot/modem_fsc", "modem_fsc", "fsc" },
	{ "/boot/modem_fsg", "modem_fsg", "fsg" },
	{}
};

static struct rmtfd rmtfds[MAX_CALLERS];

static int storage_populate_shadow_buf(struct rmtfd *rmtfd, const char *file);

int storage_init(const char *storage_root, bool read_only, bool use_partitions)
{
	int i;

	if (storage_root)
		storage_dir = storage_root;

	if (use_partitions) {
		if (!storage_root)
			storage_dir = BY_PARTLABEL_PATH;
		storage_use_partitions = true;
	}

	storage_read_only = read_only;

	for (i = 0; i < MAX_CALLERS; i++) {
		rmtfds[i].id = i;
		rmtfds[i].fd = -1;
		rmtfds[i].shadow_buf = NULL;
	}

	return 0;
}

struct rmtfd *storage_open(unsigned node, const char *path)
{
	char *fspath;
	const struct partition *part;
	struct rmtfd *rmtfd = NULL;
	const char *file;
	size_t pathlen;
	int saved_errno;
	int ret;
	int fd;
	int i;

	for (part = partition_table; part->path; part++) {
		if (strcmp(part->path, path) == 0)
			goto found;
	}

	fprintf(stderr, "[RMTFS storage] request for unknown partition '%s', rejecting\n", path);
	return NULL;

found:
	/* Check if this node already has the requested path open */
	for (i = 0; i < MAX_CALLERS; i++) {
		if ((rmtfds[i].fd != -1 || rmtfds[i].shadow_buf) &&
		    rmtfds[i].node == node &&
		    rmtfds[i].partition == part)
			return &rmtfds[i];
	}

	for (i = 0; i < MAX_CALLERS; i++) {
		if (rmtfds[i].fd == -1 && !rmtfds[i].shadow_buf) {
			rmtfd = &rmtfds[i];
			break;
		}
	}
	if (!rmtfd) {
		fprintf(stderr, "[storage] out of free rmtfd handles\n");
		return NULL;
	}

	if (storage_use_partitions)
		file = part->partlabel;
	else
		file = part->actual;

	pathlen = strlen(storage_dir) + strlen(file) + 2;
	fspath = alloca(pathlen);
	snprintf(fspath, pathlen, "%s/%s", storage_dir, file);
	if (!storage_read_only) {
		fd = open(fspath, O_RDWR);
		if (fd < 0) {
			saved_errno = errno;
			fprintf(stderr, "[storage] failed to open '%s' (requested '%s'): %s\n",
					fspath, part->path, strerror(saved_errno));
			errno = saved_errno;
			return NULL;
		}
		rmtfd->fd = fd;
		rmtfd->shadow_len = 0;
	} else {
		ret = storage_populate_shadow_buf(rmtfd, fspath);
		if (ret < 0) {
			saved_errno = errno;
			fprintf(stderr, "[storage] failed to open '%s' (requested '%s'): %s\n",
					fspath, part->path, strerror(saved_errno));
			errno = saved_errno;
			return NULL;
		}
	}

	rmtfd->node = node;
	rmtfd->partition = part;

	return rmtfd;
}

void storage_close(struct rmtfd *rmtfd)
{
	close(rmtfd->fd);
	rmtfd->fd = -1;

	free(rmtfd->shadow_buf);
	rmtfd->shadow_buf = NULL;
	rmtfd->shadow_len = 0;

	rmtfd->partition = NULL;
}

struct rmtfd *storage_get(unsigned node, int caller_id)
{
	struct rmtfd *rmtfd;

	if (caller_id >= MAX_CALLERS)
		return NULL;

	rmtfd = &rmtfds[caller_id];
	if (rmtfd->node != node)
		return NULL;

	return rmtfd;
}

int storage_get_caller_id(const struct rmtfd *rmtfd)
{
	return rmtfd->id;
}

int storage_get_error(const struct rmtfd *rmtfd)
{
	return rmtfd->dev_error;
}

void storage_exit(void)
{
	int i;

	for (i = 0; i < MAX_CALLERS; i++) {
		if (rmtfds[i].fd >= 0)
			close(rmtfds[i].fd);
	}
}

ssize_t storage_pread(const struct rmtfd *rmtfd, void *buf, size_t nbyte, off_t offset)
{
	ssize_t n;

	if (!storage_read_only) {
		n = pread(rmtfd->fd, buf, nbyte, offset);
	} else {
		n = MIN(nbyte, rmtfd->shadow_len - offset);
		if (n > 0)
			memcpy(buf, (char*)rmtfd->shadow_buf + offset, n);
		else
			n = 0;
	}

	if (n < nbyte)
		memset((char*)buf + n, 0, nbyte - n);

	return nbyte;
}

ssize_t storage_pwrite(struct rmtfd *rmtfd, const void *buf, size_t nbyte, off_t offset)
{
	size_t new_len = offset + nbyte;
	void *new_buf;

	if (!storage_read_only)
		return pwrite(rmtfd->fd, buf, nbyte, offset);

	if (new_len >= STORAGE_MAX_SIZE) {
		fprintf(stderr, "write to %zd bytes exceededs max size\n", new_len);
		errno = -EINVAL;
		return -1;
	}

	if (new_len > rmtfd->shadow_len) {
		new_buf = realloc(rmtfd->shadow_buf, new_len);
		if (!new_buf) {
			errno = -ENOMEM;
			return -1;
		}

		rmtfd->shadow_buf = new_buf;
		rmtfd->shadow_len = new_len;
	}

	memcpy((char*)rmtfd->shadow_buf + offset, buf, nbyte);

	return nbyte;
}

static int storage_populate_shadow_buf(struct rmtfd *rmtfd, const char *file)
{
	ssize_t len;
	ssize_t n;
	void *buf;
	int ret;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return -1;

	len = lseek(fd, 0, SEEK_END);
	if (len < 0) {
		ret = -1;
		goto err_close_fd;
	}

	lseek(fd, 0, SEEK_SET);

	buf = calloc(1, len);
	if (!buf) {
		ret = -1;
		goto err_close_fd;
	}

	n = read(fd, buf, len);
	if (n < 0) {
		ret = -1;
		goto err_close_fd;
	}

	rmtfd->shadow_buf = buf;
	rmtfd->shadow_len = n;

	ret = 0;

err_close_fd:
	close(fd);

	return ret;
}
