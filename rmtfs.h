#ifndef __RMTFS_H__
#define __RMTFS_H__

#include <stdint.h>
#include "qmi_rmtfs.h"

struct qmi_packet {
	uint8_t flags;
	uint16_t txn_id;
	uint16_t msg_id;
	uint16_t msg_len;
	uint8_t data[];
} __attribute__((__packed__));

int rmtfs_mem_open(void);
void rmtfs_mem_close(void);
int64_t rmtfs_mem_alloc(size_t size);
void *rmtfs_mem_ptr(unsigned phys_address, size_t len);
void rmtfs_mem_free(void);

int storage_open(void);
int storage_get(unsigned node, const char *path);
int storage_put(unsigned node, int caller_id);
int storage_get_handle(unsigned node, int caller_id);
int storage_get_error(unsigned node, int caller_id);
void storage_close(void);

#endif
