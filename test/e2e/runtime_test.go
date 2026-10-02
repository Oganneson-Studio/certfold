//go:build e2e || e2e_cloud

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type containerRuntime struct {
	path string
	name string
}

// serverDataDir is server.data_dir in a server container. It is not in the
// bind mount: certfolds refuses a data_dir whose mode lets other users in,
// and WSLC reports 0777. certfolds creates it private in /var/lib/certfolds,
// which the image makes writable to the user of the container.
const serverDataDir = "/var/lib/certfolds/data"

// certState is the part of an entry of `certfolds --json cert list` that the
// tests read.
type certState struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	State       string    `json:"state"`
	LastError   string    `json:"last_error"`
	NotAfter    time.Time `json:"not_after"`
	RenewAt     time.Time `json:"renew_at"`
	RenewSource string    `json:"renew_source"`
	IssuedAt    time.Time `json:"issued_at"`
}

func detectContainerRuntime() (containerRuntime, error) {
	if configured := strings.TrimSpace(os.Getenv("CERTFOLD_CONTAINER_CLI")); configured != "" {
		path, err := exec.LookPath(configured)
		if err != nil {
			return containerRuntime{}, fmt.Errorf("find %s: %w", configured, err)
		}
		name := runtimeName(path)
		if runtime.GOOS == "windows" && name != "wslc" {
			return containerRuntime{}, fmt.Errorf("Windows e2e requires WSLC, got %s", name)
		}
		return containerRuntime{path: path, name: name}, nil
	}
	if path, err := exec.LookPath("wslc"); err == nil {
		return containerRuntime{path: path, name: "wslc"}, nil
	}
	if runtime.GOOS == "windows" {
		programFiles := os.Getenv("ProgramFiles")
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		path := filepath.Join(programFiles, "WSL", "wslc.exe")
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return containerRuntime{path: path, name: "wslc"}, nil
		}
	}
	if runtime.GOOS != "windows" {
		if path, err := exec.LookPath("docker"); err == nil {
			return containerRuntime{path: path, name: "docker"}, nil
		}
	}
	return containerRuntime{}, fmt.Errorf("WSLC is required on Windows; set CERTFOLD_CONTAINER_CLI explicitly on other platforms")
}

func runtimeName(path string) string {
	name := strings.TrimSuffix(strings.ToLower(filepath.Base(path)), filepath.Ext(path))
	if strings.Contains(name, "wslc") {
		return "wslc"
	}
	return name
}

// newRunDir creates the directory of one run in mountDir, the host directory
// every container mounts at /e2e. mountDir is the same in every run, because
// a WSLC session can mount only 15 distinct host paths.
func newRunDir() (mountDir, runDir string, err error) {
	mountDir = filepath.Join(os.TempDir(), "certfold-wslc-e2e")
	if err := os.MkdirAll(mountDir, 0o700); err != nil {
		return "", "", err
	}
	runDir, err = os.MkdirTemp(mountDir, "run-")
	if err != nil {
		return "", "", err
	}
	return mountDir, runDir, nil
}

func bindMount(source, destination string, readOnly bool) string {
	mount := filepath.Clean(source) + ":" + destination
	if readOnly {
		mount += ":ro"
	}
	return mount
}

func (r containerRuntime) run(dir string, args ...string) (string, error) {
	cmd := exec.Command(r.path, args...)
	cmd.Dir = dir
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return output.String(), err
}

func (r containerRuntime) removeContainer(dir, name string) (string, error) {
	if r.name == "wslc" {
		return r.run(dir, "remove", "-f", name)
	}
	return r.run(dir, "rm", "-f", name)
}
