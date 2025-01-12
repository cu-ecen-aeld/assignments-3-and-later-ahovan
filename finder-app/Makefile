# launch make to compile for the host
# launch make CROSS_COMPILE=aarch64-none-linux-gnu- to compile for ARM64 target
CC=$(CROSS_COMPILE)gcc
writer: writer.c
	$(CC) writer.c -o writer
.PHONY: clean
clean:
	@rm -f writer
