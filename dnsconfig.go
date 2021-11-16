package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/pkg/errors"
)

const (
	dockerDaemonConfigPath = "/etc/docker/daemon.json"
	resolvedConfigPath     = "/etc/systemd/resolved.conf"
	dockerDnsServer        = "172.17.0.1"
	localDnsServer         = "[Resolve]\nDNS=127.0.0.1\n"
)

func updateDockerConfig(configPath string) error {

	data, err := ioutil.ReadFile(configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Wrap(err, "failed to read config file")
	}

	if err != nil {
		data = []byte("{}")
	}

	var m map[string]interface{}

	err = json.Unmarshal(data, &m)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal config file")
	}

	m["dns"] = []string{dockerDnsServer}

	config, err := json.Marshal(m)
	if err != nil {
		return errors.Wrap(err, "failed to marshal config file")
	}

	f, err := os.OpenFile(configPath,
		os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		return errors.Wrap(err, "failed to open config file for writing")
	}

	defer f.Close()
	f.Truncate(0)
	f.Seek(0, 0)
	_, err = f.WriteString(string(config))
	if err != nil {
		return errors.Wrap(err, "failed to write to config file")
	}

	return nil
}

func writeResolveConfig(configPath string) error {
	f, err := os.OpenFile(configPath,
		os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		return errors.Wrap(err, "failed to open resolved config file")
	}

	defer f.Close()

	_, err = f.WriteString(localDnsServer)
	if err != nil {
		return errors.Wrap(err, "failed to write to resolved config file")
	}

	return nil
}

func setDNSServer(cmd Command, resolvdConfigPath string) error {
	mock := cmd != nil
	if !mock {
		cmd = exec.Command("/bin/sh", "-c", "sudo systemctl stop systemd-resolved")
	}

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("error stopping systemd-resolved: %v", err))
	}

	err = writeResolveConfig(resolvdConfigPath)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("error writing to resolve config: %v", err))
	}

	if !mock {
		cmd = exec.Command("/bin/sh", "-c", "sudo systemctl restart systemd-resolved")
	}

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("error restarting systemd-resolved: %v", err))
	}

	return nil
}

func setDockerDNSServer(cmd Command, configPath string) error {
	err := updateDockerConfig(configPath)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("error updating to docker daemon config: %v", err))
	}

	if cmd == nil {
		cmd = exec.Command("/bin/sh", "-c", "sudo systemctl daemon-reload && sudo systemctl restart docker")
	}

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("error re-starting docker: %v", err))
	}

	return nil
}
