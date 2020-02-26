#include <sys/syscall.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "rmtfs.h"

#define RPROC_BASE_PATH		"/sys/bus/platform/drivers/qcom-q6v5-mss/"

static pthread_t start_thread;
static pthread_t stop_thread;
static int rproc_state_fd;
static int rproc_pipe[2];

int rproc_init(void)
{
	struct dirent *device_de;
	struct dirent *rproc_de;
	int rproc_base_fd;
	DIR *rproc_dir;
	DIR *base_dir;
	int device_fd;
	int rproc_fd;
	int base_fd;
	int ret;

	rproc_state_fd = -1;

	base_fd = open(RPROC_BASE_PATH, O_RDONLY | O_DIRECTORY);
	if (base_fd < 0)
		return -1;

	base_dir = fdopendir(base_fd);
	if (!base_dir) {
		fprintf(stderr, "failed to open mss driver path\n");
		close(base_fd);
		return -1;
	}

	while (rproc_state_fd < 0 && (device_de = readdir(base_dir)) != NULL) {
		if (!strcmp(device_de->d_name, ".") ||
		    !strcmp(device_de->d_name, ".."))
			continue;

		device_fd = openat(base_fd, device_de->d_name, O_RDONLY | O_DIRECTORY);
		if (device_fd < 0)
			continue;

		rproc_base_fd = openat(device_fd, "remoteproc", O_RDONLY | O_DIRECTORY);
		if (rproc_base_fd < 0) {
			close(device_fd);
			continue;
		}

		rproc_dir = fdopendir(rproc_base_fd);
		while (rproc_state_fd < 0 && (rproc_de = readdir(rproc_dir)) != NULL) {
			if (!strcmp(rproc_de->d_name, ".") ||
			    !strcmp(rproc_de->d_name, ".."))
				continue;

			rproc_fd = openat(rproc_base_fd, rproc_de->d_name, O_RDONLY | O_DIRECTORY);
			if (rproc_fd < 0)
				continue;

			rproc_state_fd = openat(rproc_fd, "state", O_WRONLY);
			if (rproc_state_fd < 0) {
				fprintf(stderr,
					"unable to open remoteproc \"state\" control file of %s\n",
					device_de->d_name);
			}

			close(rproc_fd);

		}
		closedir(rproc_dir);
		close(rproc_base_fd);
		close(device_fd);
	}
	closedir(base_dir);
	close(base_fd);

	if (rproc_state_fd < 0)
		return -1;

	ret = pipe(rproc_pipe);
	if (ret < 0) {
		close(rproc_state_fd);
		return -1;
	}

	return rproc_pipe[0];
}

static void *do_rproc_start(void *unused __unused)
{
	ssize_t ret;

	ret = pwrite(rproc_state_fd, "start", 5, 0);
	if (ret < 4)
		fprintf(stderr, "failed to update start state\n");

	return NULL;
}

int rproc_start()
{
	return pthread_create(&start_thread, NULL, do_rproc_start, NULL);
}

static void *do_rproc_stop(void *unused __unused)
{
	ssize_t ret;

	ret = pwrite(rproc_state_fd, "stop", 4, 0);
	if (ret < 4)
		fprintf(stderr, "failed to update stop state\n");

	ret = write(rproc_pipe[1], "Y", 1);
	if (ret != 1) {
		fprintf(stderr, "failed to signal event loop about exit\n");
		exit(0);
	}

	return NULL;
}

int rproc_stop(void)
{
	return pthread_create(&stop_thread, NULL, do_rproc_stop, NULL);
}
