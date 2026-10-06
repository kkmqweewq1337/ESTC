package util

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
)

// CheckEBPFSupport проверяет, подходит ли ядро для eBPF с kprobes.
// Требования: ядро >= 4.9 (в идеале >= 5.8 для полноценной поддержки BTF).
// Возвращает (поддерживается, версия_ядра, причина).
func CheckEBPFSupport() (bool, string, string) {
	// 1. Читаем версию ядра
	uname, err := os.ReadFile("/proc/version")
	if err != nil {
		return false, "", fmt.Sprintf("cannot read /proc/version: %v", err)
	}

	re := regexp.MustCompile(`Linux version (\d+)\.(\d+)\.(\d+)`)
	matches := re.FindStringSubmatch(string(uname))
	if len(matches) < 4 {
		return false, "", "cannot parse kernel version"
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])
	version := fmt.Sprintf("%d.%d.%d", major, minor, patch)

	// 2. Проверяем версию
	// eBPF с kprobes стабильно работает с 4.9+
	// BTF (нужен для CO-RE) — с 5.2+, но лучше 5.8+
	if major < 4 || (major == 4 && minor < 9) {
		return false, version, fmt.Sprintf("kernel %s < 4.9 (minimum for eBPF kprobes)", version)
	}

	// 3. Проверяем наличие BTF (для CO-RE, который мы используем)
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		// BTF нет — CO-RE не сработает, но "raw" eBPF может работать.
		// Мы всё равно попробуем загрузить, но предупредим.
		if major < 5 || (major == 5 && minor < 2) {
			return false, version, fmt.Sprintf("kernel %s has no BTF support (needs >= 5.2)", version)
		}
		// Для 5.2+ попробуем загрузить, вдруг BTF есть, но смонтирован в другом месте
		return true, version, "BTF not found at /sys/kernel/btf/vmlinux (may fail)"
	}

	return true, version, ""
}
