package main

import (
	"fmt"
	"os"
	"sync"
)

var annotationMutex sync.Mutex

func WriteAnnotation(message string) {
	annotationMutex.Lock()
	defer annotationMutex.Unlock()

	f, _ := os.OpenFile("/home/agent/annotation.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	defer f.Close()

	f.WriteString(fmt.Sprintf("%s\n", message))
}
