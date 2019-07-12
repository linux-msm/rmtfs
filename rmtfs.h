#ifndef __RMTFS_H__
#define __RMTFS_H__

#include <stdint.h>
#include "qmi_rmtfs.h"

#define SECTOR_SIZE		512

struct qmi_packet {
	uint8_t flags;
	uint16_t txn_id;
	uint16_t msg_id;
	uint16_t msg_len;
	uint8_t data[];
} __attribute__((__packed__));

struct rmtfs_mem;

struct rmtfs_mem *rmtfs_mem_open(void);
void rmtfs_mem_close(struct rmtfs_mem *rmem);
int64_t rmtfs_mem_alloc(struct rmtfs_mem *rmem, size_t size);
void rmtfs_mem_free(struct rmtfs_mem *rmem);
ssize_t rmtfs_mem_read(struct rmtfs_mem *rmem, unsigned long phys_address, void *buf, ssize_t len);
ssize_t rmtfs_mem_write(struct rmtfs_mem *rmem, unsigned long phys_address, const void *buf, ssize_t len);

int storage_open(const char *storage_root);
int storage_get(unsigned node, const char *path);
int storage_put(unsigned node, int caller_id);
int storage_get_handle(unsigned node, int caller_id);
int storage_get_error(unsigned node, int caller_id);
void storage_close(void);
ssize_t storage_pread(int fildes, void *buf, size_t nbyte, off_t offset);
ssize_t storage_pwrite(int fildes, const void *buf, size_t nbyte, off_t offset);

#endif
