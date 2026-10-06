.PHONY: all generate build clean bpf

CLANG    ?= clang
CFLAGS   := -O2 -g -Wall -Werror
BPF_SRC  := internal/collector/ebpf/conntrack.bpf.c
BPF_OBJ  := internal/collector/ebpf/conntrack_bpfel.o

all: generate build

generate:
	cd internal/collector/ebpf && go generate ./...

build:
	CGO_ENABLED=0 go build -o bin/estc ./cmd/agent

clean:
	rm -rf bin/
	rm -f internal/collector/ebpf/conntrack_bpfel*.go
	rm -f internal/collector/ebpf/conntrack_bpfel*.o

bpf:
	$(CLANG) $(CFLAGS) -target bpfel -c $(BPF_SRC) -o $(BPF_OBJ) \
		-I/usr/include/bpf -I/usr/include
