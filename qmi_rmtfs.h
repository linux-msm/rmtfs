#ifndef __QMI_RMTFS_H__
#define __QMI_RMTFS_H__

#include <stdint.h>
#include <stdbool.h>

#include "libqrtr.h"

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

struct rmtfs_open_req {
	uint32_t path_len;
	char path[256];
};

struct rmtfs_open_resp {
	struct rmtfs_qmi_result result;
	bool caller_id_valid;
	uint32_t caller_id;
};

struct rmtfs_close_req {
	uint32_t caller_id;
};

struct rmtfs_close_resp {
	struct rmtfs_qmi_result result;
};

struct rmtfs_iovec_req {
	uint32_t caller_id;
	uint8_t direction;
	size_t iovec_len;
	struct rmtfs_iovec_entry iovec[255];
	uint8_t is_force_sync;
};

struct rmtfs_iovec_resp {
	struct rmtfs_qmi_result result;
};

struct rmtfs_alloc_buf_req {
	uint32_t caller_id;
	uint32_t buff_size;
};

struct rmtfs_alloc_buf_resp {
	struct rmtfs_qmi_result result;
	bool buff_address_valid;
	uint64_t buff_address;
};

struct rmtfs_dev_error_req {
	uint32_t caller_id;
};

struct rmtfs_dev_error_resp {
	struct rmtfs_qmi_result result;
	bool status_valid;
	uint8_t status;
};

struct rmtfs_force_sync {
	size_t caller_id_len;
	uint32_t caller_id[10];
};

extern struct qmi_elem_info rmtfs_open_req_ei[];
extern struct qmi_elem_info rmtfs_open_resp_ei[];
extern struct qmi_elem_info rmtfs_close_req_ei[];
extern struct qmi_elem_info rmtfs_close_resp_ei[];
extern struct qmi_elem_info rmtfs_iovec_req_ei[];
extern struct qmi_elem_info rmtfs_iovec_resp_ei[];
extern struct qmi_elem_info rmtfs_alloc_buf_req_ei[];
extern struct qmi_elem_info rmtfs_alloc_buf_resp_ei[];
extern struct qmi_elem_info rmtfs_dev_error_req_ei[];
extern struct qmi_elem_info rmtfs_dev_error_resp_ei[];
extern struct qmi_elem_info rmtfs_force_sync_ei[];

#endif
