OUT := rmtfs

CFLAGS := -Wall -g -I../qrtr/lib
LDFLAGS := -L../qrtr -lqrtr
prefix := /usr/local

SRCS := qmi_rmtfs.c qmi_tlv.c rmtfs.c sharedmem.c storage.c util.c
OBJS := $(SRCS:.c=.o)

$(OUT): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.c: %.qmi
	qmic < $<

install: $(OUT)
	install -D -m 755 $< $(DESTDIR)$(prefix)/bin/$<

clean:
	rm -f $(OUT) $(OBJS)

