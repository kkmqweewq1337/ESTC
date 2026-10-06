package util

import (
	"log"
	"syscall"
)

var hostNetnsIno uint32

// InitHostNetns определяет inode сетевого пространства имен хоста (init_netns).
// Вызывается один раз при старте агента.
func InitHostNetns() {
	var stat syscall.Stat_t
	// /proc/1/ns/net всегда указывает на init_netns (пространство имен хоста)
	err := syscall.Stat("/proc/1/ns/net", &stat)
	if err != nil {
		log.Printf("⚠️ [util] Failed to stat /proc/1/ns/net: %v. Falling back to 0", err)
		hostNetnsIno = 0
		return
	}
	hostNetnsIno = uint32(stat.Ino)
	log.Printf("✅ [util] Host network namespace inode initialized: %d", hostNetnsIno)
}

// IsContainerNetns проверяет, принадлежит ли соединение контейнеру,
// сравнивая inode сетевого пространства имен сокета (из eBPF) с inode хоста.
// Это мгновенная операция в памяти, без системных вызовов!
func IsContainerNetns(netnsIno uint32) bool {
	// Если netnsIno == 0, значит eBPF не смог его получить (fallback).
	// Если netnsIno == hostNetnsIno, значит это хост.
	return netnsIno != 0 && netnsIno != hostNetnsIno
}
