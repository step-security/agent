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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
	"github.com/pkg/errors"
	"github.com/step-security/agent/pkg/artifact"
)

type ProcessMonitor struct {
	CorrelationId    string
	Repo             string
	ApiClient        *ApiClient
	WorkingDirectory string
	Events           map[int]*Event
	PidIPAddressMap  map[string]bool
	PidFileMap       map[string]bool
	ProcessMap       map[string]*Process
	mutex            sync.RWMutex
	Artifacts        []artifact.Artifact
}

type Process struct {
	PID              string
	Exe              string
	WorkingDirectory string
	Arguments        []string
	Scenario         string // npm publish, dotnet push are scenarios
	Artifacts        []*artifact.Artifact
	Timestamp        string
}

type Event struct {
	FileName  string
	Path      string
	Syscall   string
	Exe       string
	IPAddress string
	Port      string
	Pid       string
	PPid      string
	Timestamp string
	EventType string
	Status    string
}

func (p *ProcessMonitor) MonitorProcesses(errc chan error) {

	client, err := libaudit.NewAuditClient(nil)
	if err != nil {
		errc <- errors.Wrap(err, "failed to new audit client")
	}
	defer client.Close()

	status, err := client.GetStatus()
	if err != nil {
		errc <- errors.Wrap(err, "failed to get audit client status")
	}

	if status.Enabled == 0 {
		if err = client.SetEnabled(true, libaudit.WaitForReply); err != nil {
			errc <- errors.Wrap(err, "failed to set audit client")
		}
	}

	if _, err = client.DeleteRules(); err != nil {
		errc <- errors.Wrap(err, "failed to delete audit rules")
	}

	// files modified in working directory
	r, _ := flags.Parse(fmt.Sprintf("-w %s -p wa -k modify-file", "/home/runner"))

	actualBytes, _ := rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		errc <- errors.Wrap(err, "failed to add audit rule")
	}

	r, _ = flags.Parse(fmt.Sprintf("-w %s -p wa -k modify-agent-folder", "/home/agent"))
	actualBytes, _ = rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		errc <- errors.Wrap(err, "failed to add audit rule")
	}

	// syscall connect
	r, _ = flags.Parse("-a exit,always -S connect -k netconn")

	actualBytes, _ = rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		errc <- errors.Wrap(err, "failed to add audit rule for syscall connect")
	}

	// syscall process start
	r, _ = flags.Parse("-a exit,always -S execve -k procmon")

	actualBytes, _ = rule.Build(r)

	if err = client.AddRule(actualBytes); err != nil {
		errc <- errors.Wrap(err, "failed to add audit rule for syscall execve")
	}

	/*if status.Enabled != 2 {
		writeToFile("setting kernel settings as immutable")
		if err = client.SetImmutable(libaudit.NoWait); err != nil {
			return err
		}
	}*/

	// sending message to kernel registering our PID
	if err = client.SetPID(libaudit.NoWait); err != nil {
		errc <- errors.Wrap(err, "failed to set audit PID")
	}

	p.receive(client)
}

func (p *ProcessMonitor) receive(r *libaudit.AuditClient) error {

	p.Events = make(map[int]*Event)
	p.PidIPAddressMap = make(map[string]bool)
	p.PidFileMap = make(map[string]bool)
	p.ProcessMap = make(map[string]*Process)

	for {
		rawEvent, err := r.Receive(false)
		if err != nil {
			return errors.Wrap(err, "receive failed")
		}

		// Messages from 1300-2999 are valid audit messages.
		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}

		//writeToFile(fmt.Sprintf("type=%v msg=%v\n", rawEvent.Type, string(rawEvent.Data)))
		message, err := auparse.Parse(rawEvent.Type, string(rawEvent.Data))
		if err != nil {
			return errors.Wrap(err, "parse failed.")
		}
		eventMap := message.ToMapStr()

		go p.ProcessEvent(int(message.Sequence), eventMap)

	}
}

func getValue(key string, eventMap map[string]interface{}) string {
	val, found := eventMap[key]
	if found {
		return fmt.Sprintf("%v", val)
	}

	return ""
}

func (p *ProcessMonitor) ProcessEvent(sequence int, eventMap map[string]interface{}) {
	p.mutex.Lock()
	_, found := p.Events[sequence]
	if !found {
		p.Events[sequence] = &Event{}

	}

	processMapKey := fmt.Sprintf("%d", sequence)
	value, found := eventMap["tags"]

	if found {
		tags := value.([]string)
		for _, v := range tags {
			if v == "modify-file" || v == "netconn" || v == "modify-agent-folder" || v == "procmon" {

				p.Events[sequence].EventType = v
				p.Events[sequence].Syscall = getValue("syscall", eventMap)
				p.Events[sequence].Exe = getValue("exe", eventMap)
				p.Events[sequence].Pid = getValue("pid", eventMap)
				p.Events[sequence].PPid = getValue("ppid", eventMap)
				p.Events[sequence].Timestamp = getValue("@timestamp", eventMap)
				p.Events[sequence].Status = getValue("result", eventMap)

				if p.Events[sequence].EventType == "procmon" {
					process, found := p.ProcessMap[processMapKey]
					if found {
						process.Exe = p.Events[sequence].Exe
						process.PID = p.Events[sequence].Pid
						process.Timestamp = p.Events[sequence].Timestamp
					} else {
						p.ProcessMap[processMapKey] = &Process{Exe: p.Events[sequence].Exe, PID: p.Events[sequence].Pid, Timestamp: p.Events[sequence].Timestamp}
					}
				}

				if p.Events[sequence].EventType == "modify-file" || p.Events[sequence].EventType == "modify-agent-folder" {
					p.trySendFileChange(sequence)
				} else {
					p.trySendNetConn(sequence)
				}
			}
		}
	}

	// cwd
	cwd, found := eventMap["cwd"]

	if found {

		p.Events[sequence].Path = fmt.Sprintf("%v", cwd)

		if p.Events[sequence].Pid != "" {
			key := fmt.Sprintf("%s-%d", p.Events[sequence].Pid, sequence)
			process, found := p.ProcessMap[key]
			if found {
				process.WorkingDirectory = p.Events[sequence].Path
			} else {
				p.ProcessMap[key] = &Process{WorkingDirectory: p.Events[sequence].Path}
			}
		}

		p.trySendFileChange(sequence)
	}

	// Connect
	addr, found := eventMap["addr"]

	if found {
		p.Events[sequence].IPAddress = fmt.Sprintf("%v", addr)
		port, found := eventMap["port"]

		if found {
			p.Events[sequence].Port = fmt.Sprintf("%v", port)
		}

		p.trySendNetConn(sequence)
	}

	// Process start
	argc, found := eventMap["argc"]

	if found {
		argCountStr := fmt.Sprintf("%v", argc)
		argCount, err := strconv.Atoi(argCountStr)
		if err != nil {
			writeLog(fmt.Sprintf("could not parse argc:%v", argc))
		} else if p.Events[sequence].Pid != "" {
			process, found := p.ProcessMap[processMapKey]
			if found {
				for i := 0; i < argCount; i++ {
					process.Arguments = append(process.Arguments, fmt.Sprintf("%v", eventMap[fmt.Sprintf("a%d", i)]))
				}
			} else {
				p.ProcessMap[processMapKey] = &Process{}
				for i := 0; i < argCount; i++ {
					p.ProcessMap[processMapKey].Arguments = append(p.ProcessMap[processMapKey].Arguments, fmt.Sprintf("%v", eventMap[fmt.Sprintf("a%d", i)]))
				}
			}
		}

	}

	// File operation
	nameType, found := eventMap["nametype"]

	if found {
		nameTypeStr := fmt.Sprintf("%v", nameType)
		if nameTypeStr == "DELETE" || nameTypeStr == "CREATE" || nameTypeStr == "NORMAL" {
			name, found := eventMap["name"]
			if found {
				fileName := fmt.Sprintf("%v", name)
				p.Events[sequence].FileName = fileName
				p.trySendFileChange(sequence)
			}
		}
	}

	p.mutex.Unlock()
}

func (p *ProcessMonitor) trySendFileChange(sequence int) {

	if p.Events[sequence].Pid != "" && p.Events[sequence].FileName != "" && p.Events[sequence].Exe != "" && p.Events[sequence].Path != "" {

		timestamp := time.Now().UTC()
		var err error
		if p.Events[sequence].Timestamp != "" {
			timestamp, err = time.Parse("2006-01-02 15:04:05.999999999 +0000 UTC", p.Events[sequence].Timestamp)
			if err != nil {
				timestamp = time.Now().UTC()
			}
		}

		if !strings.HasPrefix(p.Events[sequence].FileName, "/") {
			p.Events[sequence].FileName = path.Join(p.Events[sequence].Path, p.Events[sequence].FileName)
		}

		// If this is a signal to send info about artifacts
		if strings.Contains(p.Events[sequence].FileName, "post_event.json") {
			for key, process := range p.ProcessMap {

				if len(process.Arguments) > 2 && strings.HasSuffix(process.Arguments[1], "npm") &&
					strings.HasSuffix(process.Arguments[2], "publish") {
					writeLog(fmt.Sprintf("proc:%s:%v", key, process))
					artfct := &artifact.Artifact{}
					if process.WorkingDirectory == "" {
						process.WorkingDirectory = p.WorkingDirectory
					}
					packageJsonFolderPath := process.WorkingDirectory
					// if the next argument does not start with --, it means folder is specified
					if len(process.Arguments) > 3 && !strings.HasPrefix(process.Arguments[3], "--") {
						packageJsonFolderPath = process.Arguments[3]
					}

					timestamp := time.Now().UTC()
					var err error
					if process.Timestamp != "" {
						timestamp, err = time.Parse("2006-01-02 15:04:05.999999999 +0000 UTC", process.Timestamp) //2006-01-02 15:04:05.999999999 -0700 MST
						if err != nil {
							writeLog(fmt.Sprintf("%v,%s", err, process.Timestamp))
							timestamp = time.Now().UTC()
						}
					}

					artfct.TimeStamp = timestamp
					artfct.GitPath = path.Join(p.WorkingDirectory, ".git")

					writeLog(fmt.Sprintf("GetMetadata: %s, %s", process.WorkingDirectory, packageJsonFolderPath))
					artfct.AddMetadata(process.WorkingDirectory, packageJsonFolderPath)
					checksum, _ := getProgramChecksum(process.Exe)
					exe := filepath.Base(process.Exe)
					artfct.Tool = artifact.Tool{Name: exe, SHA256: checksum}
					p.ApiClient.sendArtifact(p.CorrelationId, p.Repo, *artfct)
				}
			}

			writeLog("post_event called")
			// send done signal to post step
			writeDone()
		}

		_, found := p.PidFileMap[p.Events[sequence].Pid]

		if !found {
			fileType := ""
			if strings.Contains(p.Events[sequence].FileName, "/node_modules/") && strings.HasSuffix(p.Events[sequence].FileName, ".js") {
				fileType = "Dependencies"

			} else if strings.Contains(p.Events[sequence].FileName, ".git/objects") {
				fileType = "Source Code"
			} else {
				return
			}
			p.PidFileMap[p.Events[sequence].Pid] = true

			toolChecksum, _ := getProgramChecksum(p.Events[sequence].Exe)
			exe := filepath.Base(p.Events[sequence].Exe)
			p.ApiClient.sendFileEvent(p.CorrelationId, p.Repo, fileType, timestamp, exe, toolChecksum)
		}

	}
}

func (p *ProcessMonitor) trySendNetConn(sequence int) {

	if p.Events[sequence].Pid != "" && p.Events[sequence].IPAddress != "" && strings.Compare(p.Events[sequence].IPAddress, "127.0.0.53") != 0 && strings.Compare(p.Events[sequence].IPAddress, "127.0.0.1") != 0 && strings.Compare(p.Events[sequence].IPAddress, "::1") != 0 {
		cacheKey := fmt.Sprintf("%s%s%s", p.Events[sequence].Pid, p.Events[sequence].IPAddress, p.Events[sequence].Port)

		_, found := p.PidIPAddressMap[cacheKey]

		if !found {
			timestamp := time.Now().UTC()
			var err error
			if p.Events[sequence].Timestamp != "" {
				timestamp, err = time.Parse("2006-01-02 15:04:05.999999999 +0000 UTC", p.Events[sequence].Timestamp)
				if err != nil {
					writeLog(fmt.Sprintf("%v,%s", err, p.Events[sequence].Timestamp))
					timestamp = time.Now().UTC()
				}
			}

			image := GetContainerByPid(p.Events[sequence].Pid)
			checksum := ""
			exe := ""
			if image == "" {

				if p.Events[sequence].Exe != "" {
					checksum, err = getProgramChecksum(p.Events[sequence].Exe)
					if err != nil {
						printContainerInfo(p.Events[sequence].Pid, p.Events[sequence].PPid)

					}
				}
				exe = filepath.Base(p.Events[sequence].Exe)
			} else {
				p.Events[sequence].Exe = image
				checksum = image
				exe = image
			}

			p.ApiClient.sendNetConnection(p.CorrelationId, p.Repo, p.Events[sequence].IPAddress, p.Events[sequence].Port, "", timestamp, exe, checksum)
			p.PidIPAddressMap[cacheKey] = true
		}
	}
}

func printContainerInfo(pid, ppid string) {
	writeLog(fmt.Sprintf("printContainerInfo pid:%s, ppid:%s", pid, ppid))
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
		writeLog(fmt.Sprintf("printContainerInfo container:%s, pid:%d, containerid:%s", container.Image, json.State.Pid, container.ID))
		for _, mp := range container.Mounts {
			writeLog(fmt.Sprintf("mount:%v", mp))
		}
	}

	images, _ := cli.ImageList(ctx, types.ImageListOptions{All: true})
	for _, image := range images {
		writeLog(fmt.Sprintf("image: %v", image))
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
