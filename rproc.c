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
#define RPROC_CLASS_PATH	"/sys/class/remoteproc/"

static pthread_t start_thread;
static pthread_t stop_thread;
static int rproc_state_fd;
static int rproc_pipe[2];

static int rproc_init_by_modalias(void)
{
	struct dirent *rproc_de;
	char modalias[256];
	DIR *base_dir;
	int modalias_fd;
	int rproc_fd;
	int state_fd = -1;
	int base_fd;
	int ret;

	base_fd = open(RPROC_CLASS_PATH, O_RDONLY | O_DIRECTORY);
	if (base_fd < 0)
		return -1;

	base_dir = fdopendir(base_fd);
	if (!base_dir) {
		fprintf(stderr, "failed to open remoteproc class path\n");
		close(base_fd);
		return -1;
	}

	while (state_fd < 0 && (rproc_de = readdir(base_dir)) != NULL) {
		if (!strcmp(rproc_de->d_name, ".") ||
		    !strcmp(rproc_de->d_name, ".."))
			continue;

		rproc_fd = openat(base_fd, rproc_de->d_name, O_RDONLY | O_DIRECTORY);
		if (rproc_fd < 0)
			continue;

		modalias_fd = openat(rproc_fd, "device/modalias", O_RDONLY);
		if (modalias_fd < 0)
			goto close_rproc_fd;

		ret = read(modalias_fd, modalias, sizeof(modalias) - 1);
		if (ret < 0)
			goto close_modalias_fd;
		modalias[ret] = '\0';

		if (!strstr(modalias, "-mpss-pas") && !strstr(modalias, "-mss-pil"))
			goto close_modalias_fd;

		state_fd = openat(rproc_fd, "state", O_WRONLY);
		if (state_fd < 0) {
			fprintf(stderr,
				"unable to open remoteproc \"state\" control file of %s\n",
				rproc_de->d_name);
		}

close_modalias_fd:
		close(modalias_fd);
close_rproc_fd:
		close(rproc_fd);
	}
	closedir(base_dir);
	close(base_fd);

	return state_fd;
}

static int rproc_init_by_mss_driver(void)
{
	struct dirent *device_de;
	struct dirent *rproc_de;
	int rproc_base_fd;
	DIR *rproc_dir;
	DIR *base_dir;
	int device_fd;
	int rproc_fd;
	int state_fd = -1;
	int base_fd;

	base_fd = open(RPROC_BASE_PATH, O_RDONLY | O_DIRECTORY);
	if (base_fd < 0)
		return -1;

	base_dir = fdopendir(base_fd);
	if (!base_dir) {
		fprintf(stderr, "failed to open mss driver path\n");
		close(base_fd);
		return -1;
	}

	while (state_fd < 0 && (device_de = readdir(base_dir)) != NULL) {
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
		while (state_fd < 0 && (rproc_de = readdir(rproc_dir)) != NULL) {
			if (!strcmp(rproc_de->d_name, ".") ||
			    !strcmp(rproc_de->d_name, ".."))
				continue;

			rproc_fd = openat(rproc_base_fd, rproc_de->d_name, O_RDONLY | O_DIRECTORY);
			if (rproc_fd < 0)
				continue;

			state_fd = openat(rproc_fd, "state", O_WRONLY);
			if (state_fd < 0) {
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

	return state_fd;
}

int rproc_init(void)
{
	int state_fd;
	int ret;

	state_fd = rproc_init_by_modalias();
	if (state_fd < 0) {
		state_fd = rproc_init_by_mss_driver();
		if (state_fd < 0)
			return -1;
	}

	ret = pipe(rproc_pipe);
	if (ret < 0) {
		close(state_fd);
		return -1;
	}

	rproc_state_fd = state_fd;

	return rproc_pipe[0];
}

static void *do_rproc_start(void *unused)
{
	ssize_t ret;

	ret = pwrite(rproc_state_fd, "start", 5, 0);
	if (ret < 4) {
		fprintf(stderr, "failed to update start state: %s\n",
			strerror(errno));
	}

	return NULL;
}

int rproc_start()
{
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	return pthread_create(&start_thread, &attr, do_rproc_start, NULL);
}

static void *do_rproc_stop(void *unused)
{
	ssize_t ret;

	ret = pwrite(rproc_state_fd, "stop", 4, 0);
	if (ret < 4) {
		fprintf(stderr, "failed to update stop state: %s\n",
			strerror(errno));
	}

	ret = write(rproc_pipe[1], "Y", 1);
	if (ret != 1) {
		fprintf(stderr, "failed to signal event loop about exit\n");
		exit(0);
	}

	return NULL;
}

int rproc_stop(void)
{
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	return pthread_create(&stop_thread, &attr, do_rproc_stop, NULL);
}
