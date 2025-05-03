package main

import (
	"context"
	"crypto/sha256"
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
	CorrelationId           string
	Repo                    string
	ApiClient               *ApiClient
	DNSProxy                *DNSProxy
	ProcessConnectionMap    map[string]bool
	ProcessFileMap          map[string]bool
	ProcessMap              map[string]*Process
	SourceCodeMap           map[string][]*Event
	FileOverwriteCounterMap map[string]int // to count file overwrites by an exe
	netMutex                sync.RWMutex
	fileMutex               sync.RWMutex
	procMutex               sync.RWMutex
}

var classAPrivateSubnet, classBPrivateSubnet, classCPrivateSubnet, loopBackSubnet, ipv6LinkLocalSubnet, ipv6LocalSubnet *net.IPNet

func (eventHandler *EventHandler) handleFileEvent(event *Event) {
	eventHandler.fileMutex.Lock()

	if !strings.HasPrefix(event.FileName, "/") {
		event.FileName = path.Join(event.Path, event.FileName)
	}

	if strings.Contains(event.FileName, "post_event.json") {
		WriteLog("\n")
		WriteLog("post_event called")

		// send done signal to post step
		writeDone()
	}

	if strings.Contains(event.FileName, "daemon.json") {
		WriteAnnotation(fmt.Sprintf("%s Overwrite detected for %s", StepSecurityAnnotationPrefix, dockerDaemonConfigPath))
	}

	if strings.Contains(event.FileName, "resolved.conf") {
		WriteAnnotation(fmt.Sprintf("%s Overwrite detected for %s", StepSecurityAnnotationPrefix, resolvedConfigPath))
	}

	// Uncomment to log file writes (only uncomment in INT env)
	// WriteLog(fmt.Sprintf("file write %s, syscall %s", event.FileName, event.Syscall))

	_, found := eventHandler.SourceCodeMap[event.FileName]
	if !found {
		eventHandler.SourceCodeMap[event.FileName] = append(eventHandler.SourceCodeMap[event.FileName], event)
	}
	if found {
		isFromDifferentProcess := false
		for _, writeEvent := range eventHandler.SourceCodeMap[event.FileName] {
			if writeEvent.Pid != event.Pid {
				isFromDifferentProcess = true
			}
		}

		if isFromDifferentProcess {
			eventHandler.SourceCodeMap[event.FileName] = append(eventHandler.SourceCodeMap[event.FileName], event)
			counter, found := eventHandler.FileOverwriteCounterMap[event.Exe]
			if !found || counter < 3 {
				checksum, err := getProgramChecksum(event.Exe)
				if err == nil {
					WriteLog(fmt.Sprintf("[Source code overwritten] file: %s syscall: %s by exe: %s [%s] Timestamp: %s", event.FileName, event.Syscall, event.Exe, checksum, event.Timestamp.Format("2006-01-02T15:04:05.999999999Z")))
					// WriteAnnotation(fmt.Sprintf("StepSecurity Harden Runner: Source code overwritten file: %s syscall: %s by exe: %s", event.FileName, event.Syscall, event.Exe))
				}

				eventHandler.FileOverwriteCounterMap[event.Exe]++
			}
		}
	}

	eventHandler.fileMutex.Unlock()
}

func (eventHandler *EventHandler) handleProcessEvent(event *Event) {
	eventHandler.procMutex.Lock()

	_, found := eventHandler.ProcessMap[event.Pid]

	if !found {
		eventHandler.ProcessMap[event.Pid] = &Process{PID: event.Pid, PPid: event.PPid, Exe: event.Exe, Arguments: event.ProcessArguments}
		eventHandler.procMutex.Unlock()

		if event.Euid == "0" {
			image := eventHandler.GetContainerByPid(event.Pid)
			if image == "" {
				if event.Exe != "" {
					if eventHandler.IsStartedByRunner(event.PPid, event.Exe) {
						WriteLog(fmt.Sprintf("sudo process started: Exe: %s, Arguments: %v", event.Exe, event.ProcessArguments))
					}
				}
			}
		}
	} else {
		eventHandler.procMutex.Unlock()
	}
}

/*
func printContainerInfo(pid, ppid string) {
	WriteLog(fmt.Sprintf("printContainerInfo pid:%s, ppid:%s", pid, ppid))
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
		WriteLog(fmt.Sprintf("printContainerInfo container:%s, pid:%d, containerid:%s", container.Image, json.State.Pid, container.ID))
		for _, mp := range container.Mounts {
			WriteLog(fmt.Sprintf("mount:%v", mp))
		}
	}

	images, _ := cli.ImageList(ctx, types.ImageListOptions{All: true})
	for _, image := range images {
		WriteLog(fmt.Sprintf("image: %v", image))
	}

	cgroupPath := fmt.Sprintf("/proc/%s/cgroup", pid)
	content, err := ioutil.ReadFile(cgroupPath)
	if err != nil {
		WriteLog(fmt.Sprintf("cgroup not found %v", err))
	} else {
		WriteLog("cgroup content:")
		WriteLog(string(content))
	}
}*/

func (eventHandler *EventHandler) handleNetworkEvent(event *Event) {
	eventHandler.netMutex.Lock()

	if !isPrivateIPAddress(event.IPAddress) &&
		// commenting out AzureIPAddress since it should not be called
		// strings.Compare(event.IPAddress, AzureIPAddress) != 0 &&
		strings.Compare(event.IPAddress, MetadataIPAddress) != 0 &&
		// Don't send IPs having v6 for insights
		!isIPv6(event.IPAddress) {

		cacheKey := fmt.Sprintf("%s%s%s", event.Pid, event.IPAddress, event.Port)

		_, found := eventHandler.ProcessConnectionMap[cacheKey]

		if !found {
			tool := Tool{}
			image := eventHandler.GetContainerByPid(event.Pid)
			if image == "" {
				if event.Exe != "" {
					tool = *eventHandler.GetToolChain(event.PPid, event.Exe)
				}

			} else {
				tool = Tool{Name: image, SHA256: image} // TODO: Set container image checksum
			}
			reverseLookUp := eventHandler.DNSProxy.GetReverseIPLookup(event.IPAddress)
			eventHandler.ApiClient.sendNetConnection(eventHandler.CorrelationId, eventHandler.Repo, event.IPAddress, event.Port, reverseLookUp, "", event.Timestamp, tool)
			process := ""
			if image == "" {
				process = tool.Name
			}
			WriteLog(fmt.Sprintf("endpoint called ip address:port %s:%s, domain: %s, pid: %s, process: %s", event.IPAddress, event.Port, reverseLookUp, event.Pid, process))
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

func GetContainerIdByPid(cgroupPath string) string {
	content, err := ioutil.ReadFile(cgroupPath)
	if err != nil {
		// WriteLog(fmt.Sprintf("error reading cgrouppath: %s : %v", cgroupPath, err))
		return ""
	}

	for _, line := range strings.Split(string(content), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) > 2 && parts[1] == "memory" {
			containerIdParts := strings.Split(parts[2], "/")
			if len(containerIdParts) > 2 {
				if containerIdParts[1] == "actions_job" {
					return containerIdParts[2]
				}
			}
			if len(containerIdParts) > 3 {
				if containerIdParts[1] == "docker" && containerIdParts[2] == "buildx" {
					return containerIdParts[3]
				}
			}
		}
	}

	return ""
}

func (eventHandler *EventHandler) SetContainerByPid(pid, container string) {
	eventHandler.procMutex.Lock()

	process, found := eventHandler.ProcessMap[pid]

	if found {
		process.Container = container
	}

	eventHandler.procMutex.Unlock()
}

func (eventHandler *EventHandler) GetContainerByPid(pid string) string {
	procContainer := ""

	// see if already calculated
	eventHandler.procMutex.Lock()
	process, found := eventHandler.ProcessMap[pid]
	if found {
		if process.Container != "" {
			eventHandler.procMutex.Unlock()
			return process.Container
		}
	}
	eventHandler.procMutex.Unlock()

	cgroupPath := fmt.Sprintf("/proc/%s/cgroup", pid)
	containerId := GetContainerIdByPid(cgroupPath)
	if containerId == "" {
		return ""
	}

	// docker prints first 12 characters in the log
	if len(containerId) > 12 {
		procContainer = containerId[:12]
	}

	// if container image found, use that
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return ""
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return ""
	}

	for _, container := range containers {
		json, _ := cli.ContainerInspect(ctx, container.ID)
		if strings.Compare(pid, fmt.Sprintf("%d", json.State.Pid)) == 0 {
			procContainer = container.Image
		} else if containerId == container.ID {
			// WriteLog(fmt.Sprintf("Found containerid: %s for pid: %s", container.ID, pid))
			procContainer = container.Image
		}
	}

	eventHandler.SetContainerByPid(pid, procContainer)
	return procContainer
}

func getProgramChecksum(path string) (string, error) {

	f, err := os.Open(path)
	if err != nil {
		return err.Error(), err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err.Error(), err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (eventHandler *EventHandler) IsStartedByRunner(ppid, exe string) bool {

	if strings.Contains(exe, "Runner.Worker") {
		return true
	}

	// In some cases the process has already exited, so get from map first
	eventHandler.procMutex.Lock()
	parentProcess, found := eventHandler.ProcessMap[ppid]
	eventHandler.procMutex.Unlock()

	if found {
		return eventHandler.IsStartedByRunner(parentProcess.PPid, parentProcess.Exe)
	}

	// If not in map, may be long running, so get from OS
	parentProcessId, err := getParentProcessId(ppid)
	if err != nil {
		return false
	}

	path, err := getProcessExe(ppid)
	if err != nil {
		return false
	}

	return eventHandler.IsStartedByRunner(fmt.Sprintf("%d", parentProcessId), path)

}

func (eventHandler *EventHandler) GetToolChain(ppid, exe string) *Tool {
	checksum, _ := getProgramChecksum(exe)
	tool := Tool{Name: filepath.Base(exe), SHA256: checksum}

	// In some cases the process has already exited, so get from map first
	eventHandler.procMutex.Lock()
	parentProcess, found := eventHandler.ProcessMap[ppid]
	eventHandler.procMutex.Unlock()

	if found {
		tool.Parent = eventHandler.GetToolChain(parentProcess.PPid, parentProcess.Exe)
		return &tool
	}

	// If not in map, may be long running, so get from OS
	parentProcessId, err := getParentProcessId(ppid)
	if err != nil {
		return &tool
	}

	path, err := getProcessExe(ppid)
	if err != nil {
		return &tool
	}

	tool.Parent = eventHandler.GetToolChain(fmt.Sprintf("%d", parentProcessId), path)

	return &tool
}

func isPrivateIPAddress(ipAddress string) bool {

	if ipAddress == AllZeros {
		return true
	}

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
	if ipv6LinkLocalSubnet == nil {
		_, ipv6LinkLocalSubnet, _ = net.ParseCIDR(ipv6LinkLocalAddressRange)
	}
	if ipv6LocalSubnet == nil {
		_, ipv6LocalSubnet, _ = net.ParseCIDR(ipv6LocalAddressRange)
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

	if ipv6LinkLocalSubnet.Contains(ip) {
		return true
	}

	if ipv6LocalSubnet.Contains(ip) {
		return true
	}

	// https://gist.github.com/nanmu42/9c8139e15542b3c4a1709cb9e9ac61eb
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	return false
}

func isIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}
