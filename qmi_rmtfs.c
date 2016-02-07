#include <errno.h>
#include <string.h>
#include "qmi_rmtfs.h"

struct rmtfs_open_req *rmtfs_open_req_alloc(unsigned txn)
{
	return (struct rmtfs_open_req*)qmi_tlv_init(txn, 1);
}

struct rmtfs_open_req *rmtfs_open_req_parse(void *buf, size_t len, unsigned *txn)
{
	return (struct rmtfs_open_req*)qmi_tlv_decode(buf, len, txn);
}

void *rmtfs_open_req_encode(struct rmtfs_open_req *open_req, size_t *len)
{
	return qmi_tlv_encode((struct qmi_tlv*)open_req, len);
}

void rmtfs_open_req_free(struct rmtfs_open_req *open_req)
{
	qmi_tlv_free((struct qmi_tlv*)open_req);
}

int rmtfs_open_req_set_path(struct rmtfs_open_req *open_req, char *buf, size_t len)
{
	return qmi_tlv_set((struct qmi_tlv*)open_req, 1, buf, len);
}

int rmtfs_open_req_get_path(struct rmtfs_open_req *open_req, char *buf, size_t buflen)
{
	size_t len;
	char *ptr;

	ptr = qmi_tlv_get((struct qmi_tlv*)open_req, 1, &len);
	if (!ptr)
		return -ENOENT;

	if (len >= buflen)
		return -ENOMEM;

	memcpy(buf, ptr, len);
	buf[len] = '\0';
	return len;
}

struct rmtfs_open_resp *rmtfs_open_resp_alloc(unsigned txn)
{
	return (struct rmtfs_open_resp*)qmi_tlv_init(txn, 1);
}

struct rmtfs_open_resp *rmtfs_open_resp_parse(void *buf, size_t len, unsigned *txn)
{
	return (struct rmtfs_open_resp*)qmi_tlv_decode(buf, len, txn);
}

void *rmtfs_open_resp_encode(struct rmtfs_open_resp *open_resp, size_t *len)
{
	return qmi_tlv_encode((struct qmi_tlv*)open_resp, len);
}

void rmtfs_open_resp_free(struct rmtfs_open_resp *open_resp)
{
	qmi_tlv_free((struct qmi_tlv*)open_resp);
}

int rmtfs_open_resp_set_result(struct rmtfs_open_resp *open_resp, struct rmtfs_qmi_result *val)
{
	return qmi_tlv_set((struct qmi_tlv*)open_resp, 2, val, sizeof(struct rmtfs_qmi_result));
}

struct rmtfs_qmi_result *rmtfs_open_resp_get_result(struct rmtfs_open_resp *open_resp)
{
	size_t len;
	void *ptr;

	ptr = qmi_tlv_get((struct qmi_tlv*)open_resp, 2, &len);
	if (!ptr)
		return NULL;

	if (len != sizeof(struct rmtfs_qmi_result))
		return NULL;

	return ptr;
}

int rmtfs_open_resp_set_caller_id(struct rmtfs_open_resp *open_resp, uint32_t val)
{
	return qmi_tlv_set((struct qmi_tlv*)open_resp, 16, &val, sizeof(uint32_t));
}

int rmtfs_open_resp_get_caller_id(struct rmtfs_open_resp *open_resp, uint32_t *val)
{
	uint32_t *ptr;
	size_t len;

	ptr = qmi_tlv_get((struct qmi_tlv*)open_resp, 16, &len);
	if (!ptr)
		return -ENOENT;

	if (len != sizeof(uint32_t))
		return -EINVAL;

	*val = *(uint32_t*)ptr;
	return 0;
}

struct rmtfs_close_req *rmtfs_close_req_alloc(unsigned txn)
{
	return (struct rmtfs_close_req*)qmi_tlv_init(txn, 2);
}

struct rmtfs_close_req *rmtfs_close_req_parse(void *buf, size_t len, unsigned *txn)
{
	return (struct rmtfs_close_req*)qmi_tlv_decode(buf, len, txn);
}

void *rmtfs_close_req_encode(struct rmtfs_close_req *close_req, size_t *len)
{
	return qmi_tlv_encode((struct qmi_tlv*)close_req, len);
}

void rmtfs_close_req_free(struct rmtfs_close_req *close_req)
{
	qmi_tlv_free((struct qmi_tlv*)close_req);
}

int rmtfs_close_req_set_caller_id(struct rmtfs_close_req *close_req, uint32_t val)
{
	return qmi_tlv_set((struct qmi_tlv*)close_req, 1, &val, sizeof(uint32_t));
}

int rmtfs_close_req_get_caller_id(struct rmtfs_close_req *close_req, uint32_t *val)
{
	uint32_t *ptr;
	size_t len;

	ptr = qmi_tlv_get((struct qmi_tlv*)close_req, 1, &len);
	if (!ptr)
		return -ENOENT;

	if (len != sizeof(uint32_t))
		return -EINVAL;

	*val = *(uint32_t*)ptr;
	return 0;
}

struct rmtfs_close_resp *rmtfs_close_resp_alloc(unsigned txn)
{
	return (struct rmtfs_close_resp*)qmi_tlv_init(txn, 2);
}

struct rmtfs_close_resp *rmtfs_close_resp_parse(void *buf, size_t len, unsigned *txn)
{
	return (struct rmtfs_close_resp*)qmi_tlv_decode(buf, len, txn);
}

void *rmtfs_close_resp_encode(struct rmtfs_close_resp *close_resp, size_t *len)
{
	return qmi_tlv_encode((struct qmi_tlv*)close_resp, len);
}

void rmtfs_close_resp_free(struct rmtfs_close_resp *close_resp)
{
	qmi_tlv_free((struct qmi_tlv*)close_resp);
}

int rmtfs_close_resp_set_result(struct rmtfs_close_resp *close_resp, struct rmtfs_qmi_result *val)
{
	return qmi_tlv_set((struct qmi_tlv*)close_resp, 2, val, sizeof(struct rmtfs_qmi_result));
}

struct rmtfs_qmi_result *rmtfs_close_resp_get_result(struct rmtfs_close_resp *close_resp)
{
	size_t len;
	void *ptr;

	ptr = qmi_tlv_get((struct qmi_tlv*)close_resp, 2, &len);
	if (!ptr)
		return NULL;

	if (len != sizeof(struct rmtfs_qmi_result))
		return NULL;

	return ptr;
}

struct rmtfs_iovec_req *rmtfs_iovec_req_alloc(unsigned txn)
{
	return (struct rmtfs_iovec_req*)qmi_tlv_init(txn, 3);
}

struct rmtfs_iovec_req *rmtfs_iovec_req_parse(void *buf, size_t len, unsigned *txn)
{
	return (struct rmtfs_iovec_req*)qmi_tlv_decode(buf, len, txn);
}

void *rmtfs_iovec_req_encode(struct rmtfs_iovec_req *iovec_req, size_t *len)
{
	return qmi_tlv_encode((struct qmi_tlv*)iovec_req, len);
}

void rmtfs_iovec_req_free(struct rmtfs_iovec_req *iovec_req)
{
	qmi_tlv_free((struct qmi_tlv*)iovec_req);
}

int rmtfs_iovec_req_set_caller_id(struct rmtfs_iovec_req *iovec_req, uint32_t val)
{
	return qmi_tlv_set((struct qmi_tlv*)iovec_req, 1, &val, sizeof(uint32_t));
}

int rmtfs_iovec_req_get_caller_id(struct rmtfs_iovec_req *iovec_req, uint32_t *val)
{
	uint32_t *ptr;
	size_t len;

	ptr = qmi_tlv_get((struct qmi_tlv*)iovec_req, 1, &len);
	if (!ptr)
		return -ENOENT;

	if (len != sizeof(uint32_t))
		return -EINVAL;

	*val = *(uint32_t*)ptr;
	return 0;
}

int rmtfs_iovec_req_set_direction(struct rmtfs_iovec_req *iovec_req, uint8_t val)
{
	return qmi_tlv_set((struct qmi_tlv*)iovec_req, 2, &val, sizeof(uint8_t));
}

int rmtfs_iovec_req_get_direction(struct rmtfs_iovec_req *iovec_req, uint8_t *val)
{
	uint8_t *ptr;
	size_t len;

	ptr = qmi_tlv_get((struct qmi_tlv*)iovec_req, 2, &len);
	if (!ptr)
		return -ENOENT;

	if (len != sizeof(uint8_t))
		return -EINVAL;

	*val = *(uint8_t*)ptr;
	return 0;
}

int rmtfs_iovec_req_set_iovec(struct rmtfs_iovec_req *iovec_req, struct rmtfs_iovec_entry *val, size_t count)
{
	return qmi_tlv_set_array((struct qmi_tlv*)iovec_req, 3, 1, val, count, sizeof(struct rmtfs_iovec_entry));
}

struct rmtfs_iovec_entry *rmtfs_iovec_req_get_iovec(struct rmtfs_iovec_req *iovec_req, size_t *count)
{
	size_t size;
	size_t len;
	void *ptr;

	ptr = qmi_tlv_get_array((struct qmi_tlv*)iovec_req, 3, 1, &len, &size);
	if (!ptr)
		return NULL;

	if (size != sizeof(struct rmtfs_iovec_entry))
		return NULL;

	*count = len;
	return ptr;
}

int rmtfs_iovec_req_set_is_force_sync(struct rmtfs_iovec_req *iovec_req, uint8_t val)
{
	return qmi_tlv_set((struct qmi_tlv*)iovec_req, 4, &val, sizeof(uint8_t));
}

int rmtfs_iovec_req_get_is_force_sync(struct rmtfs_iovec_req *iovec_req, uint8_t *val)
{
	uint8_t *ptr;
	size_t len;

	ptr = qmi_tlv_get((struct qmi_tlv*)iovec_req, 4, &len);
	if (!ptr)
		return -ENOENT;

	if (len != sizeof(uint8_t))
		return -EINVAL;

	*val = *(uint8_t*)ptr;
	return 0;
}

struct rmtfs_iovec_resp *rmtfs_iovec_resp_alloc(unsigned txn)
{
	return (struct rmtfs_iovec_resp*)qmi_tlv_init(txn, 3);
}

struct rmtfs_iovec_resp *rmtfs_iovec_resp_parse(void *buf, size_t len, unsigned *txn)
{
	return (struct rmtfs_iovec_resp*)qmi_tlv_decode(buf, len, txn);
}

void *rmtfs_iovec_resp_encode(struct rmtfs_iovec_resp *iovec_resp, size_t *len)
{
	return qmi_tlv_encode((struct qmi_tlv*)iovec_resp, len);
}

void rmtfs_iovec_resp_free(struct rmtfs_iovec_resp *iovec_resp)
{
	qmi_tlv_free((struct qmi_tlv*)iovec_resp);
}

int rmtfs_iovec_resp_set_result(struct rmtfs_iovec_resp *iovec_resp, struct rmtfs_qmi_result *val)
{
	return qmi_tlv_set((struct qmi_tlv*)iovec_resp, 2, val, sizeof(struct rmtfs_qmi_result));
}

struct rmtfs_qmi_result *rmtfs_iovec_resp_get_result(struct rmtfs_iovec_resp *iovec_resp)
{
	size_t len;
	void *ptr;

	ptr = qmi_tlv_get((struct qmi_tlv*)iovec_resp, 2, &len);
	if (!ptr)
		return NULL;

	if (len != sizeof(struct rmtfs_qmi_result))
		return NULL;

	return ptr;
}

struct rmtfs_alloc_buf_req *rmtfs_alloc_buf_req_alloc(unsigned txn)
{
	return (struct rmtfs_alloc_buf_req*)qmi_tlv_init(txn, 4);
}

struct rmtfs_alloc_buf_req *rmtfs_alloc_buf_req_parse(void *buf, size_t len, unsigned *txn)
{
	return (struct rmtfs_alloc_buf_req*)qmi_tlv_decode(buf, len, txn);
}

void *rmtfs_alloc_buf_req_encode(struct rmtfs_alloc_buf_req *alloc_buf_req, size_t *len)
{
	return qmi_tlv_encode((struct qmi_tlv*)alloc_buf_req, len);
}

void rmtfs_alloc_buf_req_free(struct rmtfs_alloc_buf_req *alloc_buf_req)
{
	qmi_tlv_free((struct qmi_tlv*)alloc_buf_req);
}

int rmtfs_alloc_buf_req_set_caller_id(struct rmtfs_alloc_buf_req *alloc_buf_req, uint32_t val)
{
	return qmi_tlv_set((struct qmi_tlv*)alloc_buf_req, 1, &val, sizeof(uint32_t));
}

int rmtfs_alloc_buf_req_get_caller_id(struct rmtfs_alloc_buf_req *alloc_buf_req, uint32_t *val)
{
	uint32_t *ptr;
	size_t len;

	ptr = qmi_tlv_get((struct qmi_tlv*)alloc_buf_req, 1, &len);
	if (!ptr)
		return -ENOENT;

	if (len != sizeof(uint32_t))
		return -EINVAL;

	*val = *(uint32_t*)ptr;
	return 0;
}

int rmtfs_alloc_buf_req_set_buff_size(struct rmtfs_alloc_buf_req *alloc_buf_req, uint32_t val)
{
	return qmi_tlv_set((struct qmi_tlv*)alloc_buf_req, 2, &val, sizeof(uint32_t));
}

int rmtfs_alloc_buf_req_get_buff_size(struct rmtfs_alloc_buf_req *alloc_buf_req, uint32_t *val)
{
	uint32_t *ptr;
	size_t len;

	ptr = qmi_tlv_get((struct qmi_tlv*)alloc_buf_req, 2, &len);
	if (!ptr)
		return -ENOENT;

	if (len != sizeof(uint32_t))
		return -EINVAL;

	*val = *(uint32_t*)ptr;
	return 0;
}

struct rmtfs_alloc_buf_resp *rmtfs_alloc_buf_resp_alloc(unsigned txn)
{
	return (struct rmtfs_alloc_buf_resp*)qmi_tlv_init(txn, 4);
}

struct rmtfs_alloc_buf_resp *rmtfs_alloc_buf_resp_parse(void *buf, size_t len, unsigned *txn)
{
	return (struct rmtfs_alloc_buf_resp*)qmi_tlv_decode(buf, len, txn);
}

void *rmtfs_alloc_buf_resp_encode(struct rmtfs_alloc_buf_resp *alloc_buf_resp, size_t *len)
{
	return qmi_tlv_encode((struct qmi_tlv*)alloc_buf_resp, len);
}

void rmtfs_alloc_buf_resp_free(struct rmtfs_alloc_buf_resp *alloc_buf_resp)
{
	qmi_tlv_free((struct qmi_tlv*)alloc_buf_resp);
}

int rmtfs_alloc_buf_resp_set_result(struct rmtfs_alloc_buf_resp *alloc_buf_resp, struct rmtfs_qmi_result *val)
{
	return qmi_tlv_set((struct qmi_tlv*)alloc_buf_resp, 2, val, sizeof(struct rmtfs_qmi_result));
}

struct rmtfs_qmi_result *rmtfs_alloc_buf_resp_get_result(struct rmtfs_alloc_buf_resp *alloc_buf_resp)
{
	size_t len;
	void *ptr;

	ptr = qmi_tlv_get((struct qmi_tlv*)alloc_buf_resp, 2, &len);
	if (!ptr)
		return NULL;

	if (len != sizeof(struct rmtfs_qmi_result))
		return NULL;

	return ptr;
}

int rmtfs_alloc_buf_resp_set_buff_address(struct rmtfs_alloc_buf_resp *alloc_buf_resp, uint64_t val)
{
	return qmi_tlv_set((struct qmi_tlv*)alloc_buf_resp, 16, &val, sizeof(uint64_t));
}

int rmtfs_alloc_buf_resp_get_buff_address(struct rmtfs_alloc_buf_resp *alloc_buf_resp, uint64_t *val)
{
	uint64_t *ptr;
	size_t len;

	ptr = qmi_tlv_get((struct qmi_tlv*)alloc_buf_resp, 16, &len);
	if (!ptr)
		return -ENOENT;

	if (len != sizeof(uint64_t))
		return -EINVAL;

	*val = *(uint64_t*)ptr;
	return 0;
}

struct rmtfs_dev_error_req *rmtfs_dev_error_req_alloc(unsigned txn)
{
	return (struct rmtfs_dev_error_req*)qmi_tlv_init(txn, 5);
}

struct rmtfs_dev_error_req *rmtfs_dev_error_req_parse(void *buf, size_t len, unsigned *txn)
{
	return (struct rmtfs_dev_error_req*)qmi_tlv_decode(buf, len, txn);
}

void *rmtfs_dev_error_req_encode(struct rmtfs_dev_error_req *dev_error_req, size_t *len)
{
	return qmi_tlv_encode((struct qmi_tlv*)dev_error_req, len);
}

void rmtfs_dev_error_req_free(struct rmtfs_dev_error_req *dev_error_req)
{
	qmi_tlv_free((struct qmi_tlv*)dev_error_req);
}

int rmtfs_dev_error_req_set_caller_id(struct rmtfs_dev_error_req *dev_error_req, uint32_t val)
{
	return qmi_tlv_set((struct qmi_tlv*)dev_error_req, 1, &val, sizeof(uint32_t));
}

int rmtfs_dev_error_req_get_caller_id(struct rmtfs_dev_error_req *dev_error_req, uint32_t *val)
{
	uint32_t *ptr;
	size_t len;

	ptr = qmi_tlv_get((struct qmi_tlv*)dev_error_req, 1, &len);
	if (!ptr)
		return -ENOENT;

	if (len != sizeof(uint32_t))
		return -EINVAL;

	*val = *(uint32_t*)ptr;
	return 0;
}

struct rmtfs_dev_error_resp *rmtfs_dev_error_resp_alloc(unsigned txn)
{
	return (struct rmtfs_dev_error_resp*)qmi_tlv_init(txn, 5);
}

struct rmtfs_dev_error_resp *rmtfs_dev_error_resp_parse(void *buf, size_t len, unsigned *txn)
{
	return (struct rmtfs_dev_error_resp*)qmi_tlv_decode(buf, len, txn);
}

void *rmtfs_dev_error_resp_encode(struct rmtfs_dev_error_resp *dev_error_resp, size_t *len)
{
	return qmi_tlv_encode((struct qmi_tlv*)dev_error_resp, len);
}

void rmtfs_dev_error_resp_free(struct rmtfs_dev_error_resp *dev_error_resp)
{
	qmi_tlv_free((struct qmi_tlv*)dev_error_resp);
}

int rmtfs_dev_error_resp_set_result(struct rmtfs_dev_error_resp *dev_error_resp, struct rmtfs_qmi_result *val)
{
	return qmi_tlv_set((struct qmi_tlv*)dev_error_resp, 2, val, sizeof(struct rmtfs_qmi_result));
}

struct rmtfs_qmi_result *rmtfs_dev_error_resp_get_result(struct rmtfs_dev_error_resp *dev_error_resp)
{
	size_t len;
	void *ptr;

	ptr = qmi_tlv_get((struct qmi_tlv*)dev_error_resp, 2, &len);
	if (!ptr)
		return NULL;

	if (len != sizeof(struct rmtfs_qmi_result))
		return NULL;

	return ptr;
}

int rmtfs_dev_error_resp_set_status(struct rmtfs_dev_error_resp *dev_error_resp, uint8_t val)
{
	return qmi_tlv_set((struct qmi_tlv*)dev_error_resp, 16, &val, sizeof(uint8_t));
}

int rmtfs_dev_error_resp_get_status(struct rmtfs_dev_error_resp *dev_error_resp, uint8_t *val)
{
	uint8_t *ptr;
	size_t len;

	ptr = qmi_tlv_get((struct qmi_tlv*)dev_error_resp, 16, &len);
	if (!ptr)
		return -ENOENT;

	if (len != sizeof(uint8_t))
		return -EINVAL;

	*val = *(uint8_t*)ptr;
	return 0;
}

struct rmtfs_force_sync *rmtfs_force_sync_alloc(unsigned txn)
{
	return (struct rmtfs_force_sync*)qmi_tlv_init(txn, 6);
}

struct rmtfs_force_sync *rmtfs_force_sync_parse(void *buf, size_t len, unsigned *txn)
{
	return (struct rmtfs_force_sync*)qmi_tlv_decode(buf, len, txn);
}

void *rmtfs_force_sync_encode(struct rmtfs_force_sync *force_sync, size_t *len)
{
	return qmi_tlv_encode((struct qmi_tlv*)force_sync, len);
}

void rmtfs_force_sync_free(struct rmtfs_force_sync *force_sync)
{
	qmi_tlv_free((struct qmi_tlv*)force_sync);
}

int rmtfs_force_sync_set_caller_id(struct rmtfs_force_sync *force_sync, uint32_t *val, size_t count)
{
	return qmi_tlv_set_array((struct qmi_tlv*)force_sync, 1, 1, val, count, sizeof(uint32_t));
}

uint32_t *rmtfs_force_sync_get_caller_id(struct rmtfs_force_sync *force_sync, size_t *count)
{
	uint32_t *ptr;
	size_t size;
	size_t len;

	ptr = qmi_tlv_get_array((struct qmi_tlv*)force_sync, 1, 1, &len, &size);
	if (!ptr)
		return NULL;

	if (size != sizeof(uint32_t))
		return NULL;

	*count = len;
	return ptr;
}

