OUT := rmtfs

CFLAGS += -Wall -g -O2
LDFLAGS += -lqrtr -ludev -lpthread
prefix = /usr/local
bindir := $(prefix)/bin
servicedir := $(prefix)/lib/systemd/system

SRCS := qmi_rmtfs.c rmtfs.c rproc.c sharedmem.c storage.c util.c
OBJS := $(SRCS:.c=.o)

$(OUT): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.c: %.qmi
	qmic -k < $<

rmtfs.service: rmtfs.service.in
	@sed 's+RMTFS_PATH+$(bindir)+g' $< > $@

install: $(OUT) rmtfs.service
	@install -D -m 755 $(OUT) $(DESTDIR)$(prefix)/bin/$(OUT)
	@install -D -m 644 rmtfs.service $(DESTDIR)$(servicedir)/rmtfs.service

clean:
	rm -f $(OUT) $(OBJS) rmtfs.service

