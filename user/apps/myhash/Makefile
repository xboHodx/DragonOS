ifeq ($(ARCH), x86_64)
	CROSS_COMPILE=x86_64-linux-musl-
else ifeq ($(ARCH), riscv64)
	CROSS_COMPILE=riscv64-linux-musl-
endif

CC=$(CROSS_COMPILE)gcc


all: main.c MD5.c file_reader.c SHA256.c
	$(CC) -static -o myhash main.c MD5.c file_reader.c SHA256.c

.PHONY: install clean
install: all
	mv myhash $(DADK_CURRENT_BUILD_DIR)/myhash

clean:
	rm myhash *.o

fmt:
