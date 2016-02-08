#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "qmi_rmtfs.h"

struct qmi_packet {
	uint8_t flags;
	uint16_t txn_id;
	uint16_t msg_id;
	uint16_t msg_len;
	uint8_t data[];
} __attribute__((__packed__));

struct qmi_tlv {
	void *allocated;
	void *buf;
	size_t size;
	int error;
};

struct qmi_tlv_item {
	uint8_t key;
	uint16_t len;
	uint8_t data[];
} __attribute__((__packed__));

struct qmi_tlv *qmi_tlv_init(unsigned txn, unsigned msg_id, unsigned msg_type)
{
	struct qmi_packet *pkt;
	struct qmi_tlv *tlv;

	tlv = malloc(sizeof(struct qmi_tlv));
	memset(tlv, 0, sizeof(struct qmi_tlv));

	tlv->size = sizeof(struct qmi_packet);
	tlv->allocated = malloc(tlv->size);
	tlv->buf = tlv->allocated;

	pkt = tlv->buf;
	pkt->flags = msg_type;
	pkt->txn_id = txn;
	pkt->msg_id = msg_id;
	pkt->msg_len = 0;

	return tlv;
}

struct qmi_tlv *qmi_tlv_decode(void *buf, size_t len, unsigned *txn, unsigned msg_type)
{
	struct qmi_packet *pkt = buf;
	struct qmi_tlv *tlv;

	if (pkt->flags != msg_type)
		return NULL;

	tlv = malloc(sizeof(struct qmi_tlv));
	memset(tlv, 0, sizeof(struct qmi_tlv));

	tlv->buf = buf;
	tlv->size = len;

	if (txn)
		*txn = pkt->txn_id;

	return tlv;
}

void *qmi_tlv_encode(struct qmi_tlv *tlv, size_t *len)
{

	struct qmi_packet *pkt;

	if (!tlv || tlv->error)
		return NULL;

	pkt = tlv->buf;
	pkt->msg_len = tlv->size - sizeof(struct qmi_packet);

	*len = tlv->size;
	return tlv->buf;
}

void qmi_tlv_free(struct qmi_tlv *tlv)
{
	free(tlv->allocated);
	free(tlv);
}

static struct qmi_tlv_item *qmi_tlv_get_item(struct qmi_tlv *tlv, unsigned id)
{
	struct qmi_tlv_item *item;
	struct qmi_packet *pkt;
	unsigned offset = 0;
	void *pkt_data;

	pkt = tlv->buf;
	pkt_data = pkt->data;

	while (offset < tlv->size) {
		item = pkt_data + offset;
		if (item->key == id)
			return pkt_data + offset;

		offset += sizeof(struct qmi_tlv_item) + item->len;
	}
	return NULL;
}

void *qmi_tlv_get(struct qmi_tlv *tlv, unsigned id, size_t *len)
{
	struct qmi_tlv_item *item;

	item = qmi_tlv_get_item(tlv, id);
	if (!item)
		return NULL;

	*len = item->len;
	return item->data;
}

void *qmi_tlv_get_array(struct qmi_tlv *tlv, unsigned id, unsigned len_size, size_t *len, size_t *size)
{
	struct qmi_tlv_item *item;
	unsigned count;
	void *ptr;

	item = qmi_tlv_get_item(tlv, id);
	if (!item)
		return NULL;

	ptr = item->data;
	switch (len_size) {
	case 4:
		count = *(uint32_t*)ptr++;
		break;
	case 2:
		count = *(uint16_t*)ptr++;
		break;
	case 1:
		count = *(uint8_t*)ptr++;
		break;
	}

	*len = count;
	*size = (item->len - len_size) / count;

	return ptr;
}

static struct qmi_tlv_item *qmi_tlv_alloc_item(struct qmi_tlv *tlv, unsigned id, size_t len)
{
	struct qmi_tlv_item *item;
	size_t new_size;
	bool migrate;
	void *newp;

	/* If using user provided buffer, migrate data */
	migrate = !tlv->allocated;

	new_size = tlv->size + sizeof(struct qmi_tlv_item) + len;
	newp = realloc(tlv->allocated, new_size);
	if (!newp)
		return NULL;

	if (migrate)
		memcpy(newp, tlv->buf, tlv->size);

	item = newp + tlv->size;
	item->key = id;
	item->len = len;

	tlv->buf = tlv->allocated = newp;
	tlv->size = new_size;

	return item;
}

int qmi_tlv_set(struct qmi_tlv *tlv, unsigned id, void *buf, size_t len)
{
	struct qmi_tlv_item *item;

	if (!tlv)
		return -EINVAL;

	item = qmi_tlv_alloc_item(tlv, id, len);
	if (!item) {
		tlv->error = ENOMEM;
		return -ENOMEM;
	}

	memcpy(item->data, buf, len);

	return 0;
}

int qmi_tlv_set_array(struct qmi_tlv *tlv, unsigned id, unsigned len_size, void *buf, size_t len, size_t size)
{
	struct qmi_tlv_item *item;
	size_t array_size;
	void *ptr;

	if (!tlv)
		return -EINVAL;

	array_size = len * size;
	item = qmi_tlv_alloc_item(tlv, id, len_size + array_size);
	if (!item) {
		tlv->error = ENOMEM;
		return -ENOMEM;
	}

	ptr = item->data;

	switch (len_size) {
	case 4:
		*(uint32_t*)ptr++ = len;
		break;
	case 2:
		*(uint16_t*)ptr++ = len;
		break;
	case 1:
		*(uint8_t*)ptr++ = len;
		break;
	}
	memcpy(ptr, buf, array_size);

	return 0;
}


