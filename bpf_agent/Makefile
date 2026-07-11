CC = gcc
CLANG = clang
BPFTOOL = bpftool
BPF_CFLAGS = -O2 -g -target bpf -I/usr/include/bpf -D__TARGET_ARCH_x86
CFLAGS = -O2 -Wall -I/usr/include/bpf
LDFLAGS = -lbpf -lelf -lz

all: trace

# BPF program
tracer.bpf.o: tracer.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton header
tracer.skel.h: tracer.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# User-space loader
trace: loader.c tracer.skel.h
	$(CC) $(CFLAGS) -o $@ loader.c $(LDFLAGS)

clean:
	rm -f tracer.bpf.o tracer.skel.h trace

.PHONY: all clean
