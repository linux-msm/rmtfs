OUT := rmtfs

CFLAGS += -Wall -g -O2
LDFLAGS += -lqrtr -ludev -lpthread
prefix = /usr/local
bindir := $(prefix)/bin
servicedir := $(prefix)/lib/systemd/system

RMTFS_EFS_PATH ?= /var/lib/rmtfs

SRCS := qmi_rmtfs.c rmtfs.c rproc.c sharedmem.c storage.c util.c
OBJS := $(SRCS:.c=.o)

$(OUT): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.c: %.qmi
	qmic -k < $<

%.service: %.service.in
	@sed -e 's+RMTFS_PATH+$(bindir)+g' -e 's+RMTFS_EFS_PATH+$(RMTFS_EFS_PATH)+g' $< > $@

install: $(OUT) rmtfs.service rmtfs-dir.service
	@install -D -m 755 $(OUT) $(DESTDIR)$(prefix)/bin/$(OUT)
	@install -D -m 644 rmtfs.service $(DESTDIR)$(servicedir)/rmtfs.service
	@install -D -m 644 rmtfs-dir.service $(DESTDIR)$(servicedir)/rmtfs-dir.service

clean:
	rm -f $(OUT) $(OBJS) rmtfs.service
	rm -f $(OUT) $(OBJS) rmtfs-dir.service

