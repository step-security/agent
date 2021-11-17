package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

type EventHandler struct {
	CorrelationId        string
	Repo                 string
	ApiClient            *ApiClient
	ProcessConnectionMap map[string]bool
	ProcessFileMap       map[string]bool
	ProcessMap           map[string]*Process
	netMutex             sync.RWMutex
	fileMutex            sync.RWMutex
}

func (eventHandler *EventHandler) handleFileEvent(event *Event) {
	eventHandler.fileMutex.Lock()

	if !strings.HasPrefix(event.FileName, "/") {
		event.FileName = path.Join(event.Path, event.FileName)
	}

	if strings.Contains(event.FileName, "post_event.json") {
		writeLog("post_event called")

		// send done signal to post step
		writeDone()
	}

	_, found := eventHandler.ProcessFileMap[event.Pid]
	fileType := ""
	if !found {

		if strings.Contains(event.FileName, "/node_modules/") && strings.HasSuffix(event.FileName, ".js") {
			fileType = "Dependencies"

		} else if strings.Contains(event.FileName, ".git/objects") {
			fileType = "Source Code"
		}

		if fileType != "" {
			toolChecksum, _ := getProgramChecksum(event.Exe)
			exe := filepath.Base(event.Exe)
			eventHandler.ApiClient.sendFileEvent(eventHandler.CorrelationId, eventHandler.Repo, fileType, event.Timestamp, exe, toolChecksum)
			eventHandler.ProcessFileMap[event.Pid] = true
		}
	}

	eventHandler.fileMutex.Unlock()
}
func (eventHandler *EventHandler) handleProcessEvent() {

}
func (eventHandler *EventHandler) handleNetworkEvent(event *Event) {
	eventHandler.netMutex.Lock()
	cacheKey := fmt.Sprintf("%s%s%s", event.Pid, event.IPAddress, event.Port)

	_, found := eventHandler.ProcessConnectionMap[cacheKey]

	if !found {
		writeLog(fmt.Sprintf("handleNetworkEvent %v", event))
		image := GetContainerByPid(event.Pid)
		checksum := ""
		exe := ""
		if image == "" {

			if event.Exe != "" {
				checksum, _ = getProgramChecksum(event.Exe)

			}
			exe = filepath.Base(event.Exe)
		} else {
			event.Exe = image
			checksum = image
			exe = image
		}

		eventHandler.ApiClient.sendNetConnection(eventHandler.CorrelationId, eventHandler.Repo, event.IPAddress, event.Port, "", event.Timestamp, exe, checksum)
		eventHandler.ProcessConnectionMap[cacheKey] = true
	}
	eventHandler.netMutex.Unlock()
}

func (eventHandler *EventHandler) HandleEvent(event *Event) {
	switch event.EventType {
	case netMonitorTag:
		eventHandler.handleNetworkEvent(event)
	case fileMonitorTag:
		eventHandler.handleFileEvent(event)
	case processMonitorTag:
		eventHandler.handleProcessEvent()
	}
}

func GetContainerByPid(pid string) string {
	cgroupPath := fmt.Sprintf("/proc/%s/cgroup", pid)
	content, _ := ioutil.ReadFile(cgroupPath)

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		//panic(err)
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		//panic(err)
	}

	for _, container := range containers {
		json, _ := cli.ContainerInspect(ctx, container.ID)
		if strings.Compare(pid, fmt.Sprintf("%d", json.State.Pid)) == 0 {
			return container.Image
		} else if strings.Contains(string(content), container.ID) {
			return container.Image
		}
	}

	return ""
}

func getProgramChecksum(path string) (string, error) {

	f, err := os.Open(path)
	if err != nil {
		return err.Error(), err
	}
	defer f.Close()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return err.Error(), err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
