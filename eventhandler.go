package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"net"
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
	procMutex            sync.RWMutex
}

var classAPrivateSubnet, classBPrivateSubnet, classCPrivateSubnet, loopBackSubnet *net.IPNet

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
			tool := *eventHandler.GetToolChain(event.PPid, event.Exe)
			eventHandler.ApiClient.sendFileEvent(eventHandler.CorrelationId, eventHandler.Repo, fileType, event.Timestamp, tool)
			eventHandler.ProcessFileMap[event.Pid] = true
		}
	}

	eventHandler.fileMutex.Unlock()
}

func (eventHandler *EventHandler) handleProcessEvent(event *Event) {
	eventHandler.procMutex.Lock()

	_, found := eventHandler.ProcessMap[event.Pid]

	if !found {
		eventHandler.ProcessMap[event.Pid] = &Process{PID: event.Pid, PPid: event.PPid, Exe: event.Exe, Arguments: event.ProcessArguments}
	}

	eventHandler.procMutex.Unlock()
}

func (eventHandler *EventHandler) handleNetworkEvent(event *Event) {
	eventHandler.netMutex.Lock()

	if !isPrivateIPAddress(event.IPAddress) &&
		strings.Compare(event.IPAddress, "::1") != 0 &&
		strings.Compare(event.IPAddress, AzureIPAddress) != 0 &&
		strings.Compare(event.IPAddress, MetadataIPAddress) != 0 {

		cacheKey := fmt.Sprintf("%s%s%s", event.Pid, event.IPAddress, event.Port)

		_, found := eventHandler.ProcessConnectionMap[cacheKey]

		if !found {
			//writeLog(fmt.Sprintf("handleNetworkEvent %v", event))
			tool := Tool{}
			image := GetContainerByPid(event.Pid)
			if image == "" {
				if event.Exe != "" {
					tool = *eventHandler.GetToolChain(event.PPid, event.Exe)
				}

			} else {
				tool = Tool{Name: image, SHA256: image} // TODO: Set container image checksum
			}

			eventHandler.ApiClient.sendNetConnection(eventHandler.CorrelationId, eventHandler.Repo, event.IPAddress, event.Port, "", event.Timestamp, tool)
			eventHandler.ProcessConnectionMap[cacheKey] = true
		}
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
		eventHandler.handleProcessEvent(event)
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

func (eventHandler *EventHandler) GetToolChain(PPid, exe string) *Tool {
	checksum, _ := getProgramChecksum(exe)
	tool := Tool{Name: filepath.Base(exe), SHA256: checksum}

	parentProcessId, err := getParentProcessId(PPid)
	if err != nil {
		path, err := os.Readlink(fmt.Sprintf("/proc/%s/exe", PPid))
		if err == nil {
			tool.Parent = eventHandler.GetToolChain(fmt.Sprintf("%d", parentProcessId), path)
		}
	}

	return &tool
}

func isPrivateIPAddress(ipAddress string) bool {
	if classAPrivateSubnet == nil {
		_, classAPrivateSubnet, _ = net.ParseCIDR(classAPrivateAddressRange)
	}
	if classBPrivateSubnet == nil {
		_, classBPrivateSubnet, _ = net.ParseCIDR(classBPrivateAddressRange)
	}
	if classCPrivateSubnet == nil {
		_, classCPrivateSubnet, _ = net.ParseCIDR(classCPrivateAddressRange)
	}
	if loopBackSubnet == nil {
		_, loopBackSubnet, _ = net.ParseCIDR(loopBackAddressRange)
	}

	ip := net.ParseIP(ipAddress)

	if classAPrivateSubnet.Contains(ip) {
		return true
	}

	if classBPrivateSubnet.Contains(ip) {
		return true
	}

	if classCPrivateSubnet.Contains(ip) {
		return true
	}

	if loopBackSubnet.Contains(ip) {
		return true
	}

	return false
}
