package main

import (
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSudoersContent = "runner ALL=(ALL) NOPASSWD:ALL\n"

// newTestSudo returns a Sudo wired to a fake sudoers file and non-existent
// socket paths so tests never touch the machine's real sudoers or sockets.
// All seams are per-instance fields: the background container-cleanup
// goroutine may outlive the test, so it must never read package-level state
// that a test cleanup restores.
func newTestSudo(t *testing.T, runCmd func(cmd string, args ...string)) (*Sudo, string) {
	t.Helper()
	dir := t.TempDir()
	sudoersPath := path.Join(dir, "runner")
	// 0640 rather than the real file's 0440: the agent truncates as root
	// (which bypasses permission checks), but tests run unprivileged.
	if err := os.WriteFile(sudoersPath, []byte(testSudoersContent), 0640); err != nil {
		t.Fatalf("failed to create fake sudoers file: %v", err)
	}
	return &Sudo{
		sudoersFilePathOverride: sudoersPath,
		dockerSockPathOverride:  path.Join(dir, "no-such-docker.sock"),
		containerdSockOverride:  path.Join(dir, "no-such-containerd.sock"),
		runCmd:                  runCmd,
	}, sudoersPath
}

func Test_disableSudoAndContainers_RevokesSudoBeforeContainerCleanup(t *testing.T) {
	type observed struct {
		command     string
		sudoersSize int64
	}

	firstCmd := make(chan observed, 1)
	release := make(chan struct{})
	var mu sync.Mutex
	var commands []string

	sudo, sudoersPath := newTestSudo(t, nil)
	sudo.runCmd = func(cmd string, args ...string) {
		full := strings.Join(append([]string{cmd}, args...), " ")
		var size int64 = -1
		if fi, err := os.Stat(sudoersPath); err == nil {
			size = fi.Size()
		}
		mu.Lock()
		commands = append(commands, full)
		mu.Unlock()
		select {
		case firstCmd <- observed{command: full, sudoersSize: size}:
		default:
		}
		<-release
	}
	t.Cleanup(func() { close(release) })

	done := make(chan error, 1)
	go func() {
		done <- sudo.disableSudoAndContainers(t.TempDir())
	}()

	// Sudo revocation must not wait on container teardown, which is
	// simulated here by a command runner that blocks forever.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("disableSudoAndContainers returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disableSudoAndContainers blocked on container teardown; sudo revocation must complete first")
	}

	fi, err := os.Stat(sudoersPath)
	if err != nil {
		t.Fatalf("failed to stat sudoers file: %v", err)
	}
	if fi.Size() != 0 {
		t.Fatalf("sudoers file not truncated after disableSudoAndContainers returned; size = %d", fi.Size())
	}

	// The first container-cleanup command must observe an already-truncated
	// sudoers file, and must be the package purge (daemon stop) rather than
	// a directory delete.
	select {
	case obs := <-firstCmd:
		if obs.sudoersSize != 0 {
			t.Fatalf("first container-cleanup command %q ran before sudoers truncate; observed size = %d", obs.command, obs.sudoersSize)
		}
		if !strings.HasPrefix(obs.command, "apt-get purge") {
			t.Fatalf("first container-cleanup command = %q, want package purge before directory deletion", obs.command)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no container-cleanup command observed")
	}
}

func Test_disableSudoAndContainers_ErrorSurfacesWhenSudoersMissing(t *testing.T) {
	dir := t.TempDir()
	sudo := &Sudo{
		sudoersFilePathOverride: path.Join(dir, "does-not-exist"),
		dockerSockPathOverride:  path.Join(dir, "no-such-docker.sock"),
		containerdSockOverride:  path.Join(dir, "no-such-containerd.sock"),
		runCmd:                  func(cmd string, args ...string) {},
	}

	err := sudo.disableSudoAndContainers(t.TempDir())
	if err == nil {
		t.Fatal("expected error when sudoers backup fails, got nil")
	}
	if !strings.Contains(err.Error(), "error disabling sudo and containers") {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), "error disabling sudo and containers")
	}
}

// Socket permissions must be revoked synchronously (before return), via chmod.
func Test_disableSudoAndContainers_RemovesSocketPermissions(t *testing.T) {
	sudo, _ := newTestSudo(t, func(cmd string, args ...string) {})

	sockDir := t.TempDir()
	sudo.dockerSockPathOverride = path.Join(sockDir, "docker.sock")
	sudo.containerdSockOverride = path.Join(sockDir, "containerd.sock")

	for _, p := range []string{sudo.dockerSockPathOverride, sudo.containerdSockOverride} {
		if err := os.WriteFile(p, nil, 0660); err != nil {
			t.Fatalf("failed to create fake socket %s: %v", p, err)
		}
	}

	if err := sudo.disableSudoAndContainers(t.TempDir()); err != nil {
		t.Fatalf("disableSudoAndContainers returned error: %v", err)
	}

	for _, p := range []string{sudo.dockerSockPathOverride, sudo.containerdSockOverride} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("failed to stat %s: %v", p, err)
		}
		if fi.Mode().Perm() != 0 {
			t.Fatalf("%s permissions not removed: %v", p, fi.Mode().Perm())
		}
	}
}

func Test_disableSudo_BackupAndRevert(t *testing.T) {
	sudo, sudoersPath := newTestSudo(t, func(cmd string, args ...string) {})

	tempDir := t.TempDir()
	if err := sudo.disableSudo(tempDir); err != nil {
		t.Fatalf("disableSudo returned error: %v", err)
	}

	backup, err := os.ReadFile(sudo.SudoersBackUpPath)
	if err != nil {
		t.Fatalf("failed to read backup: %v", err)
	}
	if string(backup) != testSudoersContent {
		t.Fatalf("backup content = %q, want %q", string(backup), testSudoersContent)
	}

	fi, err := os.Stat(sudoersPath)
	if err != nil {
		t.Fatalf("failed to stat sudoers file: %v", err)
	}
	if fi.Size() != 0 {
		t.Fatalf("sudoers file not truncated; size = %d", fi.Size())
	}

	if err := sudo.revertDisableSudo(); err != nil {
		t.Fatalf("revertDisableSudo returned error: %v", err)
	}
	restored, err := os.ReadFile(sudoersPath)
	if err != nil {
		t.Fatalf("failed to read restored sudoers file: %v", err)
	}
	if string(restored) != testSudoersContent {
		t.Fatalf("restored content = %q, want %q", string(restored), testSudoersContent)
	}
}
