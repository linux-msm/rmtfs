OUT := rmtfs

CFLAGS := -Wall -g -I../qrtr/lib -O2
LDFLAGS := -L../qrtr -lqrtr -ludev
prefix := /usr/local

SRCS := qmi_rmtfs.c rmtfs.c sharedmem.c storage.c util.c
OBJS := $(SRCS:.c=.o)

$(OUT): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.c: %.qmi
	qmic < $<

install: $(OUT)
	install -D -m 755 $< $(DESTDIR)$(prefix)/bin/$<

clean:
	rm -f $(OUT) $(OBJS)

