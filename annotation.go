package main

import (
	"fmt"
	"os"
	"sync"
)

var annotationMutex sync.Mutex

const AnnotationError = "error"

func WriteAnnotation(annotationType, message string) {
	annotationMutex.Lock()
	defer annotationMutex.Unlock()

	f, _ := os.OpenFile("/home/agent/annotation.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	defer f.Close()

	f.WriteString(fmt.Sprintf("%s:%s\n", annotationType, message))
}
