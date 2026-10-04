package utils

import (
	"fmt"
	"time"
)

const (
	ColorReset  = "\033[0m"
	ColorBlue   = "\033[34m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorRed    = "\033[31m"
)

func LogInfo(msg string) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s] [*] %s%s\n", ColorBlue, timestamp, msg, ColorReset)
}

func LogSuccess(msg string) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s] [+] %s%s\n", ColorGreen, timestamp, msg, ColorReset)
}

func LogWarning(msg string) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s] [!] %s%s\n", ColorYellow, timestamp, msg, ColorReset)
}

func LogError(msg string) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s] [-] %s%s\n", ColorRed, timestamp, msg, ColorReset)
}
