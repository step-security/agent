package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// GitHub is experimenting with a DNS resolver and an outbound proxy on hosted runners,
// which bypasses the agent's DNS server and results in allowed connections being dropped.
// ref: https://github.com/step-security/harden-runner/issues/708
const (
	githubDNSResolverAddress = "127.0.0.100"
	etcResolvConfPath        = "/etc/resolv.conf"
	stubResolvConfPath       = "/run/systemd/resolve/stub-resolv.conf"
)

var githubDNSExperimentServices = []string{"egress-dns-resolver.service", "egress-outbound-proxy.service"}

// systemd-resolved reads drop-ins from both /etc and /run
var githubDNSDropInPaths = []string{"/etc/systemd/resolved.conf.d/90-egress-proxy.conf", "/run/systemd/resolved.conf.d/90-egress-proxy.conf"}

// RevertGithubDNSExperiment reverts github's dns experiment, if it is present on the runner
func RevertGithubDNSExperiment() {
	if !isGithubDNSExperimentPresent() {
		WriteLog("[github-dns-experiment] not detected")
		return
	}

	WriteLog("[github-dns-experiment] detected, reverting")
	if err := revertGithubDNSExperiment(); err != nil {
		WriteLog(fmt.Sprintf("[github-dns-experiment] error reverting: %v", err))
		return
	}
	WriteLog("[github-dns-experiment] reverted")
}

func isGithubDNSExperimentPresent() bool {
	for _, dropInPath := range githubDNSDropInPaths {
		if _, err := os.Stat(dropInPath); err == nil {
			return true
		}
	}

	for _, service := range githubDNSExperimentServices {
		if isServiceActive(service) {
			return true
		}
	}

	resolvConf, err := os.ReadFile(etcResolvConfPath)
	return err == nil && strings.Contains(string(resolvConf), githubDNSResolverAddress)
}

func revertGithubDNSExperiment() error {
	// repoint dns away from github's resolver before stopping it, so a failure at any step leaves dns working
	for _, dropInPath := range githubDNSDropInPaths {
		if err := os.Remove(dropInPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("error removing %s: %v", dropInPath, err)
		}
	}

	if err := exec.Command("sudo", "systemctl", "restart", "systemd-resolved").Run(); err != nil {
		return fmt.Errorf("error restarting systemd-resolved: %v", err)
	}

	if err := linkResolvConfToStub(); err != nil {
		return err
	}

	// github's services are no longer in the dns path, so failing to stop them is not fatal
	for _, service := range githubDNSExperimentServices {
		if !isServiceActive(service) {
			continue
		}
		if err := exec.Command("sudo", "systemctl", "stop", service).Run(); err != nil {
			WriteLog(fmt.Sprintf("[github-dns-experiment] error stopping %s: %v", service, err))
		}
	}

	if err := exec.Command("sudo", "resolvectl", "flush-caches").Run(); err != nil {
		WriteLog(fmt.Sprintf("[github-dns-experiment] error flushing dns caches: %v", err))
	}

	return nil
}

// linkResolvConfToStub atomically points /etc/resolv.conf to systemd-resolved's stub resolver
func linkResolvConfToStub() error {
	if _, err := os.Stat(stubResolvConfPath); err != nil {
		return fmt.Errorf("error finding %s: %v", stubResolvConfPath, err)
	}

	tmpPath := etcResolvConfPath + ".tmp"
	os.Remove(tmpPath)
	if err := os.Symlink(stubResolvConfPath, tmpPath); err != nil {
		return fmt.Errorf("error creating %s: %v", tmpPath, err)
	}

	if err := os.Rename(tmpPath, etcResolvConfPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("error linking %s to %s: %v", etcResolvConfPath, stubResolvConfPath, err)
	}

	return nil
}

func isServiceActive(service string) bool {
	output, _ := exec.Command("systemctl", "is-active", service).Output()
	return strings.TrimSpace(string(output)) == "active"
}
