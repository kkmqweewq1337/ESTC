package util

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProcInfo хранит информацию о процессе, владеющем сокетом
type ProcInfo struct {
	PID  uint32
	Name string
}

// BuildInodeMap сканирует /proc один раз и возвращает карту socket inode -> ProcInfo.
// Это Highly Optimized версия: она читает /proc/[pid]/comm только один раз на процесс,
// а не на каждый файловый дескриптор, как было в старой реализации.
func BuildInodeMap() map[string]ProcInfo {
	m := make(map[string]ProcInfo, 2048)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		
		// Проверяем, является ли имя директории числом (PID)
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}

		pid, _ := strconv.ParseUint(e.Name(), 10, 32)
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // Процесс мог завершиться во время сканирования
		}

		// Читаем имя процесса (comm) ОДИН РАЗ для всех его дескрипторов
		commBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		comm := strings.TrimSpace(string(commBytes))
		if comm == "" {
			comm = "unknown"
		}

		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// Формат ссылки: socket:[12345]
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inode := link[8 : len(link)-1]
				// Сохраняем, если еще не сохраняли (первый найденный PID побеждает)
				if _, exists := m[inode]; !exists {
					m[inode] = ProcInfo{PID: uint32(pid), Name: comm}
				}
			}
		}
	}
	return m
}
