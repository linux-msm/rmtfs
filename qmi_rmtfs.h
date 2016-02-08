#ifndef __QMI_RMTFS_H__
#define __QMI_RMTFS_H__

#include <stdint.h>
#include <stdlib.h>

struct qmi_tlv;

struct qmi_tlv *qmi_tlv_init(unsigned txn, unsigned msg_id, unsigned type);
struct qmi_tlv *qmi_tlv_decode(void *buf, size_t len, unsigned *txn, unsigned type);
void *qmi_tlv_encode(struct qmi_tlv *tlv, size_t *len);
void qmi_tlv_free(struct qmi_tlv *tlv);

void *qmi_tlv_get(struct qmi_tlv *tlv, unsigned id, size_t *len);
void *qmi_tlv_get_array(struct qmi_tlv *tlv, unsigned id, unsigned len_size, size_t *len, size_t *size);
int qmi_tlv_set(struct qmi_tlv *tlv, unsigned id, void *buf, size_t len);
int qmi_tlv_set_array(struct qmi_tlv *tlv, unsigned id, unsigned len_size, void *buf, size_t len, size_t size);

#define QMI_RMTFS_RESULT_SUCCESS 0
#define QMI_RMTFS_RESULT_FAILURE 1
#define QMI_RMTFS_ERR_NONE 0
#define QMI_RMTFS_ERR_INTERNAL 1
#define QMI_RMTFS_ERR_MALFORMED_MSG 2
#define QMI_RMTFS_OPEN 1
#define QMI_RMTFS_CLOSE 2
#define QMI_RMTFS_RW_IOVEC 3
#define QMI_RMTFS_ALLOC_BUFF 4
#define QMI_RMTFS_GET_DEV_ERROR 5
#define QMI_RMTFS_FORCE_SYNC_IND 6

struct rmtfs_qmi_result {
	uint16_t result;
	uint16_t error;
};

struct rmtfs_iovec_entry {
	uint32_t sector_addr;
	uint32_t phys_offset;
	uint32_t num_sector;
};

struct rmtfs_open_req;
struct rmtfs_open_resp;
struct rmtfs_close_req;
struct rmtfs_close_resp;
struct rmtfs_iovec_req;
struct rmtfs_iovec_resp;
struct rmtfs_alloc_buf_req;
struct rmtfs_alloc_buf_resp;
struct rmtfs_dev_error_req;
struct rmtfs_dev_error_resp;
struct rmtfs_force_sync;

/*
 * rmtfs_open_req message
 */
struct rmtfs_open_req *rmtfs_open_req_alloc(unsigned txn);
struct rmtfs_open_req *rmtfs_open_req_parse(void *buf, size_t len, unsigned *txn);
void *rmtfs_open_req_encode(struct rmtfs_open_req *open_req, size_t *len);
void rmtfs_open_req_free(struct rmtfs_open_req *open_req);

int rmtfs_open_req_set_path(struct rmtfs_open_req *open_req, char *buf, size_t len);
int rmtfs_open_req_get_path(struct rmtfs_open_req *open_req, char *buf, size_t buflen);

/*
 * rmtfs_open_resp message
 */
struct rmtfs_open_resp *rmtfs_open_resp_alloc(unsigned txn);
struct rmtfs_open_resp *rmtfs_open_resp_parse(void *buf, size_t len, unsigned *txn);
void *rmtfs_open_resp_encode(struct rmtfs_open_resp *open_resp, size_t *len);
void rmtfs_open_resp_free(struct rmtfs_open_resp *open_resp);

int rmtfs_open_resp_set_result(struct rmtfs_open_resp *open_resp, struct rmtfs_qmi_result *val);
struct rmtfs_qmi_result *rmtfs_open_resp_get_result(struct rmtfs_open_resp *open_resp);

int rmtfs_open_resp_set_caller_id(struct rmtfs_open_resp *open_resp, uint32_t val);
int rmtfs_open_resp_get_caller_id(struct rmtfs_open_resp *open_resp, uint32_t *val);

/*
 * rmtfs_close_req message
 */
struct rmtfs_close_req *rmtfs_close_req_alloc(unsigned txn);
struct rmtfs_close_req *rmtfs_close_req_parse(void *buf, size_t len, unsigned *txn);
void *rmtfs_close_req_encode(struct rmtfs_close_req *close_req, size_t *len);
void rmtfs_close_req_free(struct rmtfs_close_req *close_req);

int rmtfs_close_req_set_caller_id(struct rmtfs_close_req *close_req, uint32_t val);
int rmtfs_close_req_get_caller_id(struct rmtfs_close_req *close_req, uint32_t *val);

/*
 * rmtfs_close_resp message
 */
struct rmtfs_close_resp *rmtfs_close_resp_alloc(unsigned txn);
struct rmtfs_close_resp *rmtfs_close_resp_parse(void *buf, size_t len, unsigned *txn);
void *rmtfs_close_resp_encode(struct rmtfs_close_resp *close_resp, size_t *len);
void rmtfs_close_resp_free(struct rmtfs_close_resp *close_resp);

int rmtfs_close_resp_set_result(struct rmtfs_close_resp *close_resp, struct rmtfs_qmi_result *val);
struct rmtfs_qmi_result *rmtfs_close_resp_get_result(struct rmtfs_close_resp *close_resp);

/*
 * rmtfs_iovec_req message
 */
struct rmtfs_iovec_req *rmtfs_iovec_req_alloc(unsigned txn);
struct rmtfs_iovec_req *rmtfs_iovec_req_parse(void *buf, size_t len, unsigned *txn);
void *rmtfs_iovec_req_encode(struct rmtfs_iovec_req *iovec_req, size_t *len);
void rmtfs_iovec_req_free(struct rmtfs_iovec_req *iovec_req);

int rmtfs_iovec_req_set_caller_id(struct rmtfs_iovec_req *iovec_req, uint32_t val);
int rmtfs_iovec_req_get_caller_id(struct rmtfs_iovec_req *iovec_req, uint32_t *val);

int rmtfs_iovec_req_set_direction(struct rmtfs_iovec_req *iovec_req, uint8_t val);
int rmtfs_iovec_req_get_direction(struct rmtfs_iovec_req *iovec_req, uint8_t *val);

int rmtfs_iovec_req_set_iovec(struct rmtfs_iovec_req *iovec_req, struct rmtfs_iovec_entry *val, size_t count);
struct rmtfs_iovec_entry *rmtfs_iovec_req_get_iovec(struct rmtfs_iovec_req *iovec_req, size_t *count);

int rmtfs_iovec_req_set_is_force_sync(struct rmtfs_iovec_req *iovec_req, uint8_t val);
int rmtfs_iovec_req_get_is_force_sync(struct rmtfs_iovec_req *iovec_req, uint8_t *val);

/*
 * rmtfs_iovec_resp message
 */
struct rmtfs_iovec_resp *rmtfs_iovec_resp_alloc(unsigned txn);
struct rmtfs_iovec_resp *rmtfs_iovec_resp_parse(void *buf, size_t len, unsigned *txn);
void *rmtfs_iovec_resp_encode(struct rmtfs_iovec_resp *iovec_resp, size_t *len);
void rmtfs_iovec_resp_free(struct rmtfs_iovec_resp *iovec_resp);

int rmtfs_iovec_resp_set_result(struct rmtfs_iovec_resp *iovec_resp, struct rmtfs_qmi_result *val);
struct rmtfs_qmi_result *rmtfs_iovec_resp_get_result(struct rmtfs_iovec_resp *iovec_resp);

/*
 * rmtfs_alloc_buf_req message
 */
struct rmtfs_alloc_buf_req *rmtfs_alloc_buf_req_alloc(unsigned txn);
struct rmtfs_alloc_buf_req *rmtfs_alloc_buf_req_parse(void *buf, size_t len, unsigned *txn);
void *rmtfs_alloc_buf_req_encode(struct rmtfs_alloc_buf_req *alloc_buf_req, size_t *len);
void rmtfs_alloc_buf_req_free(struct rmtfs_alloc_buf_req *alloc_buf_req);

int rmtfs_alloc_buf_req_set_caller_id(struct rmtfs_alloc_buf_req *alloc_buf_req, uint32_t val);
int rmtfs_alloc_buf_req_get_caller_id(struct rmtfs_alloc_buf_req *alloc_buf_req, uint32_t *val);

int rmtfs_alloc_buf_req_set_buff_size(struct rmtfs_alloc_buf_req *alloc_buf_req, uint32_t val);
int rmtfs_alloc_buf_req_get_buff_size(struct rmtfs_alloc_buf_req *alloc_buf_req, uint32_t *val);

/*
 * rmtfs_alloc_buf_resp message
 */
struct rmtfs_alloc_buf_resp *rmtfs_alloc_buf_resp_alloc(unsigned txn);
struct rmtfs_alloc_buf_resp *rmtfs_alloc_buf_resp_parse(void *buf, size_t len, unsigned *txn);
void *rmtfs_alloc_buf_resp_encode(struct rmtfs_alloc_buf_resp *alloc_buf_resp, size_t *len);
void rmtfs_alloc_buf_resp_free(struct rmtfs_alloc_buf_resp *alloc_buf_resp);

int rmtfs_alloc_buf_resp_set_result(struct rmtfs_alloc_buf_resp *alloc_buf_resp, struct rmtfs_qmi_result *val);
struct rmtfs_qmi_result *rmtfs_alloc_buf_resp_get_result(struct rmtfs_alloc_buf_resp *alloc_buf_resp);

int rmtfs_alloc_buf_resp_set_buff_address(struct rmtfs_alloc_buf_resp *alloc_buf_resp, uint64_t val);
int rmtfs_alloc_buf_resp_get_buff_address(struct rmtfs_alloc_buf_resp *alloc_buf_resp, uint64_t *val);

/*
 * rmtfs_dev_error_req message
 */
struct rmtfs_dev_error_req *rmtfs_dev_error_req_alloc(unsigned txn);
struct rmtfs_dev_error_req *rmtfs_dev_error_req_parse(void *buf, size_t len, unsigned *txn);
void *rmtfs_dev_error_req_encode(struct rmtfs_dev_error_req *dev_error_req, size_t *len);
void rmtfs_dev_error_req_free(struct rmtfs_dev_error_req *dev_error_req);

int rmtfs_dev_error_req_set_caller_id(struct rmtfs_dev_error_req *dev_error_req, uint32_t val);
int rmtfs_dev_error_req_get_caller_id(struct rmtfs_dev_error_req *dev_error_req, uint32_t *val);

/*
 * rmtfs_dev_error_resp message
 */
struct rmtfs_dev_error_resp *rmtfs_dev_error_resp_alloc(unsigned txn);
struct rmtfs_dev_error_resp *rmtfs_dev_error_resp_parse(void *buf, size_t len, unsigned *txn);
void *rmtfs_dev_error_resp_encode(struct rmtfs_dev_error_resp *dev_error_resp, size_t *len);
void rmtfs_dev_error_resp_free(struct rmtfs_dev_error_resp *dev_error_resp);

int rmtfs_dev_error_resp_set_result(struct rmtfs_dev_error_resp *dev_error_resp, struct rmtfs_qmi_result *val);
struct rmtfs_qmi_result *rmtfs_dev_error_resp_get_result(struct rmtfs_dev_error_resp *dev_error_resp);

int rmtfs_dev_error_resp_set_status(struct rmtfs_dev_error_resp *dev_error_resp, uint8_t val);
int rmtfs_dev_error_resp_get_status(struct rmtfs_dev_error_resp *dev_error_resp, uint8_t *val);

/*
 * rmtfs_force_sync message
 */
struct rmtfs_force_sync *rmtfs_force_sync_alloc(unsigned txn);
struct rmtfs_force_sync *rmtfs_force_sync_parse(void *buf, size_t len, unsigned *txn);
void *rmtfs_force_sync_encode(struct rmtfs_force_sync *force_sync, size_t *len);
void rmtfs_force_sync_free(struct rmtfs_force_sync *force_sync);

int rmtfs_force_sync_set_caller_id(struct rmtfs_force_sync *force_sync, uint32_t *val, size_t count);
uint32_t *rmtfs_force_sync_get_caller_id(struct rmtfs_force_sync *force_sync, size_t *count);

#endif
