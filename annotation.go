package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

var annotationMutex sync.Mutex

func WriteAnnotation(message string) {
	annotationMutex.Lock()
	defer annotationMutex.Unlock()

	if strings.Contains(message, "api.snapcraft.io") {
		return
	}

	dir := "/home/agent"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		_ = os.Mkdir(dir, 0644)
	}

	f, _ := os.OpenFile("/home/agent/annotation.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	defer f.Close()

	f.WriteString(fmt.Sprintf("%s\n", message))
}
