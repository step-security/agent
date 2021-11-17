package main

import (
	"testing"
)

func TestProcessMonitor_PrepareEvent(t *testing.T) {
	processMonitor := &ProcessMonitor{}
	processMonitor.Events = make(map[int]*Event)

	netEventPart1 := make(map[string]interface{})
	netEventPart1["tags"] = []string{"netmon"}
	netEventPart1["syscall"] = "connect"

	netEventPart2 := make(map[string]interface{})
	netEventPart2["addr"] = "2.2.2.2"
	netEventPart2["port"] = "443"

	processMonitor.PrepareEvent(1, netEventPart1)
	processMonitor.PrepareEvent(1, netEventPart2)

	isReady := isEventReady(processMonitor.Events[1])

	if !isReady {
		t.Errorf("Event ready expected")
	}

	fileEventPart1 := make(map[string]interface{})
	fileEventPart1["tags"] = []string{"filemon"}
	fileEventPart1["syscall"] = "open"

	fileEventPart2 := make(map[string]interface{})
	fileEventPart2["nametype"] = "CREATE"
	fileEventPart2["name"] = "file1.txt"

	fileEventPart3 := make(map[string]interface{})
	fileEventPart3["cwd"] = "/dir"

	processMonitor.PrepareEvent(2, fileEventPart1)
	processMonitor.PrepareEvent(2, fileEventPart2)
	processMonitor.PrepareEvent(2, fileEventPart3)

	isReady = isEventReady(processMonitor.Events[2])

	if !isReady {
		t.Errorf("Event ready expected")
	}
}
