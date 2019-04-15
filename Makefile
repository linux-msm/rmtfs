OUT := rmtfs

CFLAGS += -Wall -g -O2
LDFLAGS += -lqrtr -ludev -lpthread
prefix = /usr/local

SRCS := qmi_rmtfs.c rmtfs.c rproc.c sharedmem.c storage.c util.c
OBJS := $(SRCS:.c=.o)

$(OUT): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.c: %.qmi
	qmic -k < $<

install: $(OUT)
	install -D -m 755 $< $(DESTDIR)$(prefix)/bin/$<

clean:
	rm -f $(OUT) $(OBJS)

