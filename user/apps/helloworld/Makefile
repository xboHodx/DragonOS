ifeq ($(ARCH), x86_64)
	CROSS_COMPILE=x86_64-linux-musl-
else ifeq ($(ARCH), riscv64)
	CROSS_COMPILE=riscv64-linux-musl-
endif

CC=$(CROSS_COMPILE)gcc


all: main.c
	$(CC) -static -o helloworld main.c

.PHONY: install clean
install: all
	mv helloworld $(DADK_CURRENT_BUILD_DIR)/helloworld

clean:
	rm helloworld *.o

fmt:
