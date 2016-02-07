OUT := rmtfs

CFLAGS := -Wall -g -I../qrtr/lib
LDFLAGS := -L../qrtr -lqrtr

SRCS := qmi_rmtfs.c qmi_tlv.c rmtfs.c sharedmem.c storage.c util.c
OBJS := $(SRCS:.c=.o)

$(OUT): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

test: $(OUT)
	./$(OUT)

clean:
	rm -f $(OUT) $(OBJS)

