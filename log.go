package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var logMutex sync.Mutex

func WriteLog(message string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	f, _ := os.OpenFile("/home/agent/agent.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	defer f.Close()
	
	if message == "\n" {
		
		f.WriteString(fmt.Sprintf("\n"))
	} else{
		
		f.WriteString(fmt.Sprintf("%s:%s\n", time.Now().String(), message))
	}
	

	
}
