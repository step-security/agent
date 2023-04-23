package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"

	"github.com/pkg/errors"
)

type DnsConfig struct {
	ResolveConfigBackUpPath  string
	DockerConfigBackUpPath   string
	ShouldDeleteDockerConfig bool
}

const (
	dockerDaemonConfigPath = "/etc/docker/daemon.json"
	resolvedConfigPath     = "/etc/systemd/resolved.conf"
	dockerDnsServer        = "172.17.0.1"
	// https://unix.stackexchange.com/questions/508397/what-is-the-recommended-way-to-set-a-global-dns-server-override-on-a-system-usin
	// Domains=~. instructs systemd-resolved to always use the global nameservers
	// and to never query any DHCP-supplied nameservers
	localDnsServer = "[Resolve]\nDNS=127.0.0.1\nDomains=~.\n"
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
	m["live-restore"] = true
	m["userns-remap"] = "runner:runner" // Checkout: https://docs.docker.com/engine/security/userns-remap/#enable-userns-remap-on-the-daemon

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

func (d *DnsConfig) SetDNSServer(cmd Command, resolvdConfigPath, tempDir string) error {
	mock := cmd != nil
	if !mock {
		cmd = exec.Command("/bin/sh", "-c", "sudo systemctl stop systemd-resolved")
	}

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("error stopping systemd-resolved: %v", err))
	}

	d.ResolveConfigBackUpPath = path.Join(tempDir, "resolved.conf")
	err = copy(resolvdConfigPath, d.ResolveConfigBackUpPath)

	if err != nil {
		return fmt.Errorf(fmt.Sprintf("error backing up resolve config: %v", err))
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

	// flush DNS cache
	// https: //github.com/systemd/systemd/issues/940
	if !mock {
		cmd = exec.Command("/bin/sh", "-c", "sudo resolvectl flush-caches")
	}

	err = cmd.Run()
	if err != nil {
		WriteLog(fmt.Sprintf("error flushing cache: %v", err))
	}

	return nil
}

func copy(src, dst string) error {
	fin, err := os.Open(src)
	if err != nil {
		return err
	}
	defer fin.Close()

	fout, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer fout.Close()

	_, err = io.Copy(fout, fin)

	if err != nil {
		return err
	}

	return nil
}

func (d *DnsConfig) SetDockerDNSServer(cmd Command, configPath, tempDir string) error {
	if _, err := os.Stat(configPath); err == nil {
		d.DockerConfigBackUpPath = path.Join(tempDir, "daemon.json")
		err := copy(configPath, d.DockerConfigBackUpPath)
		if err != nil {
			return fmt.Errorf(fmt.Sprintf("error backing up docker config: %v", err))
		}
	} else {
		d.ShouldDeleteDockerConfig = true
	}

	mock := cmd != nil
	err := updateDockerConfig(configPath)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("error updating to docker daemon config: %v", err))
	}

	// reload will apply the live-restore config so running containers restart after docker is restarted
	if !mock {
		cmd = exec.Command("/bin/sh", "-c", "sudo systemctl reload docker")
	}

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("error reloading docker: %v", err))
	}

	if !mock {
		cmd = exec.Command("/bin/sh", "-c", "sudo systemctl daemon-reload && sudo systemctl restart docker")
	}

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("error restarting docker: %v", err))
	}

	return nil
}

func (d *DnsConfig) RevertDockerDNSServer(cmd Command, configPath string) error {
	if len(d.DockerConfigBackUpPath) > 0 || d.ShouldDeleteDockerConfig {
		if len(d.DockerConfigBackUpPath) > 0 {
			err := copy(d.DockerConfigBackUpPath, configPath)
			if err != nil {
				return fmt.Errorf(fmt.Sprintf("error recovering docker config: %v", err))
			}
		} else if d.ShouldDeleteDockerConfig {
			err := os.Remove(configPath)
			if err != nil {
				return fmt.Errorf(fmt.Sprintf("error deleting docker config: %v", err))
			}
		}

		if cmd == nil {
			cmd = exec.Command("/bin/sh", "-c", "sudo systemctl daemon-reload && sudo systemctl restart docker")
		}

		err := cmd.Run()
		if err != nil {
			return fmt.Errorf(fmt.Sprintf("error restarting docker: %v", err))
		}
	}
	return nil
}

func (d *DnsConfig) RevertDNSServer(cmd Command, resolvdConfigPath string) error {
	if len(d.ResolveConfigBackUpPath) > 0 {
		mock := cmd != nil
		if !mock {
			cmd = exec.Command("/bin/sh", "-c", "sudo systemctl stop systemd-resolved")
		}

		err := cmd.Run()
		if err != nil {
			return fmt.Errorf(fmt.Sprintf("error stopping systemd-resolved: %v", err))
		}

		err = copy(d.ResolveConfigBackUpPath, resolvdConfigPath)

		if err != nil {
			return fmt.Errorf(fmt.Sprintf("error recovering resolve config: %v", err))
		}

		if !mock {
			cmd = exec.Command("/bin/sh", "-c", "sudo systemctl restart systemd-resolved")
		}

		err = cmd.Run()
		if err != nil {
			return fmt.Errorf(fmt.Sprintf("error restarting systemd-resolved: %v", err))
		}
	}

	return nil
}
