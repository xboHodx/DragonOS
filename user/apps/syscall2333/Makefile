ifeq ($(ARCH), x86_64)
	CROSS_COMPILE=x86_64-linux-musl-
else ifeq ($(ARCH), riscv64)
	CROSS_COMPILE=riscv64-linux-musl-
endif

CC=$(CROSS_COMPILE)gcc


all: main.c
	$(CC) -static -o syscall2333 main.c

.PHONY: install clean
install: all
	mv syscall2333 $(DADK_CURRENT_BUILD_DIR)/syscall2333

clean:
	rm syscall2333 *.o

fmt:
