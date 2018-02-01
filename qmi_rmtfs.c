#include <errno.h>
#include <string.h>
#include "qmi_rmtfs.h"

struct qmi_elem_info rmtfs_qmi_result_ei[] = {
	{
		.data_type = QMI_UNSIGNED_2_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint16_t),
		.offset = offsetof(struct rmtfs_qmi_result, result),
	},
	{
		.data_type = QMI_UNSIGNED_2_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint16_t),
		.offset = offsetof(struct rmtfs_qmi_result, error),
	},
	{}
};

struct qmi_elem_info rmtfs_iovec_entry_ei[] = {
	{
		.data_type = QMI_UNSIGNED_4_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint32_t),
		.offset = offsetof(struct rmtfs_iovec_entry, sector_addr),
	},
	{
		.data_type = QMI_UNSIGNED_4_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint32_t),
		.offset = offsetof(struct rmtfs_iovec_entry, phys_offset),
	},
	{
		.data_type = QMI_UNSIGNED_4_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint32_t),
		.offset = offsetof(struct rmtfs_iovec_entry, num_sector),
	},
	{}
};

struct qmi_elem_info rmtfs_open_req_ei[] = {
	{
		.data_type = QMI_STRING,
		.elem_len = 256,
		.elem_size = sizeof(char),
		.array_type = VAR_LEN_ARRAY,
		.tlv_type = 1,
		.offset = offsetof(struct rmtfs_open_req, path)
	},
	{}
};

struct qmi_elem_info rmtfs_open_resp_ei[] = {
	{
		.data_type = QMI_STRUCT,
		.elem_len = 1,
		.elem_size = sizeof(struct rmtfs_qmi_result),
		.tlv_type = 2,
		.offset = offsetof(struct rmtfs_open_resp, result),
		.ei_array = rmtfs_qmi_result_ei,
	},
	{
		.data_type = QMI_OPT_FLAG,
		.elem_len = 1,
		.elem_size = sizeof(bool),
		.tlv_type = 16,
		.offset = offsetof(struct rmtfs_open_resp, caller_id_valid),
	},
	{
		.data_type = QMI_UNSIGNED_4_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint32_t),
		.tlv_type = 16,
		.offset = offsetof(struct rmtfs_open_resp, caller_id),
	},
	{}
};

struct qmi_elem_info rmtfs_close_req_ei[] = {
	{
		.data_type = QMI_UNSIGNED_4_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint32_t),
		.tlv_type = 1,
		.offset = offsetof(struct rmtfs_close_req, caller_id),
	},
	{}
};

struct qmi_elem_info rmtfs_close_resp_ei[] = {
	{
		.data_type = QMI_STRUCT,
		.elem_len = 1,
		.elem_size = sizeof(struct rmtfs_qmi_result),
		.tlv_type = 2,
		.offset = offsetof(struct rmtfs_close_resp, result),
		.ei_array = rmtfs_qmi_result_ei,
	},
	{}
};

struct qmi_elem_info rmtfs_iovec_req_ei[] = {
	{
		.data_type = QMI_UNSIGNED_4_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint32_t),
		.tlv_type = 1,
		.offset = offsetof(struct rmtfs_iovec_req, caller_id),
	},
	{
		.data_type = QMI_UNSIGNED_1_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint8_t),
		.tlv_type = 2,
		.offset = offsetof(struct rmtfs_iovec_req, direction),
	},
	{
		.data_type = QMI_DATA_LEN,
		.elem_len = 1,
		.elem_size = sizeof(uint8_t),
		.tlv_type = 3,
		.offset = offsetof(struct rmtfs_iovec_req, iovec_len),
	},
	{
		.data_type = QMI_STRUCT,
		.elem_len = 255,
		.elem_size = sizeof(struct rmtfs_iovec_entry),
		.array_type = VAR_LEN_ARRAY,
		.tlv_type = 3,
		.offset = offsetof(struct rmtfs_iovec_req, iovec),
		.ei_array = rmtfs_iovec_entry_ei,
	},
	{
		.data_type = QMI_UNSIGNED_1_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint8_t),
		.tlv_type = 4,
		.offset = offsetof(struct rmtfs_iovec_req, is_force_sync),
	},
	{}
};

struct qmi_elem_info rmtfs_iovec_resp_ei[] = {
	{
		.data_type = QMI_STRUCT,
		.elem_len = 1,
		.elem_size = sizeof(struct rmtfs_qmi_result),
		.tlv_type = 2,
		.offset = offsetof(struct rmtfs_iovec_resp, result),
		.ei_array = rmtfs_qmi_result_ei,
	},
	{}
};

struct qmi_elem_info rmtfs_alloc_buf_req_ei[] = {
	{
		.data_type = QMI_UNSIGNED_4_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint32_t),
		.tlv_type = 1,
		.offset = offsetof(struct rmtfs_alloc_buf_req, caller_id),
	},
	{
		.data_type = QMI_UNSIGNED_4_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint32_t),
		.tlv_type = 2,
		.offset = offsetof(struct rmtfs_alloc_buf_req, buff_size),
	},
	{}
};

struct qmi_elem_info rmtfs_alloc_buf_resp_ei[] = {
	{
		.data_type = QMI_STRUCT,
		.elem_len = 1,
		.elem_size = sizeof(struct rmtfs_qmi_result),
		.tlv_type = 2,
		.offset = offsetof(struct rmtfs_alloc_buf_resp, result),
		.ei_array = rmtfs_qmi_result_ei,
	},
	{
		.data_type = QMI_OPT_FLAG,
		.elem_len = 1,
		.elem_size = sizeof(bool),
		.tlv_type = 16,
		.offset = offsetof(struct rmtfs_alloc_buf_resp, buff_address_valid),
	},
	{
		.data_type = QMI_UNSIGNED_8_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint64_t),
		.tlv_type = 16,
		.offset = offsetof(struct rmtfs_alloc_buf_resp, buff_address),
	},
	{}
};

struct qmi_elem_info rmtfs_dev_error_req_ei[] = {
	{
		.data_type = QMI_UNSIGNED_4_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint32_t),
		.tlv_type = 1,
		.offset = offsetof(struct rmtfs_dev_error_req, caller_id),
	},
	{}
};

struct qmi_elem_info rmtfs_dev_error_resp_ei[] = {
	{
		.data_type = QMI_STRUCT,
		.elem_len = 1,
		.elem_size = sizeof(struct rmtfs_qmi_result),
		.tlv_type = 2,
		.offset = offsetof(struct rmtfs_dev_error_resp, result),
		.ei_array = rmtfs_qmi_result_ei,
	},
	{
		.data_type = QMI_OPT_FLAG,
		.elem_len = 1,
		.elem_size = sizeof(bool),
		.tlv_type = 16,
		.offset = offsetof(struct rmtfs_dev_error_resp, status_valid),
	},
	{
		.data_type = QMI_UNSIGNED_1_BYTE,
		.elem_len = 1,
		.elem_size = sizeof(uint8_t),
		.tlv_type = 16,
		.offset = offsetof(struct rmtfs_dev_error_resp, status),
	},
	{}
};

struct qmi_elem_info rmtfs_force_sync_ei[] = {
	{
		.data_type = QMI_DATA_LEN,
		.elem_len = 1,
		.elem_size = sizeof(uint8_t),
		.tlv_type = 1,
		.offset = offsetof(struct rmtfs_force_sync, caller_id_len),
	},
	{
		.data_type = QMI_UNSIGNED_1_BYTE,
		.elem_len = 10,
		.elem_size = sizeof(uint32_t),
		.array_type = VAR_LEN_ARRAY,
		.tlv_type = 1,
		.offset = offsetof(struct rmtfs_force_sync, caller_id),
	},
	{}
};

