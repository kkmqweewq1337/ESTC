# ESTC Linux Agent

## Зависимости

- Go 1.22+
- clang/llvm 14+
- linux-headers (для vmlinux.h)
- libbpf-dev
- bpftool
- ClickHouse server

## Подготовка eBPF

```bash
# Сгенерировать vmlinux.h
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 . Скопировать в /usr/include/ или указать путь в CFLAGS

# Установить libbpf
sudo apt install libbpf-dev linux-headers-$(uname -r)

# Сборка
make clean && make all
