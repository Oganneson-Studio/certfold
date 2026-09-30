package config

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// relativePaths are not absolute on the OS running the test. Neither ~ nor,
// on Windows, a leading \ makes a path absolute: nothing expands ~, and \dir
// is on the current drive, which that of a service need not be.
func relativePaths() []string {
	paths := []string{"var/lib/sigil", "./sigil", "~/sigil"}
	if runtime.GOOS == "windows" {
		paths = append(paths, `\var\lib\sigil`, `C:sigil`)
	}
	return paths
}

// absolutePaths are absolute on the OS running the test. On Windows the
// endpoint of the IPC is a named pipe, whose path is a UNC path.
func absolutePaths() []string {
	if runtime.GOOS == "windows" {
		return []string{`C:\ProgramData\Sigil`, `\\.\pipe\sigil-custom`, `\\fileserver\share\sigil`}
	}
	return []string{"/var/lib/sigil", "/run/sigil/custom.sock"}
}

// pathFields are the fields of server.yaml and client.yaml that name a file,
// a directory, a socket or a pipe, each with the configuration that sets it
// to PATH. The YAML single-quotes PATH, which takes backslashes as they are.
var pathFields = []struct {
	field  string
	server bool // the field is in server.yaml, else in client.yaml
	yaml   string
}{
	{"server.data_dir", true, withServerSection(`data_dir: 'PATH'`)},
	{"server.tls_cert_file", true, withServerSection(validDataDirLine + "\n  tls_cert_file: 'PATH'\n  tls_key_file: '" + absPath("/etc/sigil/tls.key") + "'")},
	{"server.tls_key_file", true, withServerSection(validDataDirLine + "\n  tls_cert_file: '" + absPath("/etc/sigil/tls.crt") + "'\n  tls_key_file: 'PATH'")},
	{"server.ipc_socket", true, withServerSection(validDataDirLine + "\n  ipc_socket: 'PATH'")},
	{"dns_providers.p1.service_account_file", true, dnsServerYAML("dns_providers:\n  p1:\n    type: gcloud\n    service_account_file: 'PATH'\n")},
	{"client.data_dir", false, validClientYAML + "  data_dir: 'PATH'\n"},
	{"client.ipc_socket", false, validClientYAML + "  ipc_socket: 'PATH'\n"},
	{"certificates.web.outputs[0].path", false, validClientYAML + "certificates:\n  web:\n    outputs:\n      - format: pem-cert\n        path: 'PATH'\n"},
}

// parse parses raw as server.yaml or as client.yaml.
func parse(server bool, raw string) error {
	if server {
		_, err := ParseServer([]byte(raw))
		return err
	}
	_, err := ParseClient([]byte(raw))
	return err
}

// A relative path would be resolved against the working directory of the
// service, or of the CLI, neither of which is the directory of the
// configuration.
func TestPathFieldsMustBeAbsolute(t *testing.T) {
	for _, f := range pathFields {
		for _, path := range relativePaths() {
			err := parse(f.server, strings.Replace(f.yaml, "PATH", path, 1))
			if want := fmt.Sprintf("%s: must be an absolute path, got %q", f.field, path); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s = %q: error = %v, want one containing %s", f.field, path, err, want)
			}
		}
		for _, path := range absolutePaths() {
			if err := parse(f.server, strings.Replace(f.yaml, "PATH", path, 1)); err != nil {
				t.Errorf("%s = %q: %v", f.field, path, err)
			}
		}
	}
}

// A path is checked once ${VAR} is expanded: the value of the variable
// decides, whether the variable or its default gives it.
func TestPathFieldsAreCheckedAfterExpansion(t *testing.T) {
	t.Setenv("SIGIL_TEST_RELATIVE", "sigil")
	t.Setenv("SIGIL_TEST_ROOT", absPath(""))
	for _, tt := range []struct {
		value string
		want  string // the expanded path, if it is relative
	}{
		{value: "${SIGIL_TEST_RELATIVE}/data", want: "sigil/data"},
		{value: "${SIGIL_TEST_UNSET:-data}", want: "data"},
		{value: "${SIGIL_TEST_ROOT}/var/lib/${SIGIL_TEST_RELATIVE}"},
		{value: "${SIGIL_TEST_UNSET:-" + absPath("/var/lib/sigil") + "}"},
	} {
		err := parse(true, withServerSection(`data_dir: "`+tt.value+`"`))
		if tt.want == "" {
			if err != nil {
				t.Errorf("data_dir %s: %v", tt.value, err)
			}
			continue
		}
		if want := fmt.Sprintf("server.data_dir: must be an absolute path, got %q", tt.want); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("data_dir %s: error = %v, want one containing %s", tt.value, err, want)
		}
	}
}

// ReadServerPaths and ReadClientField refuse the relative paths that
// LoadServer and LoadClient refuse, with the same error, and return the
// absolute ones they take.
func TestLenientReadersRefuseRelativePaths(t *testing.T) {
	readers := map[string]func(file string) (string, error){
		"server.data_dir": func(file string) (string, error) {
			dataDir, _, err := ReadServerPaths(file)
			return dataDir, err
		},
		"server.ipc_socket": func(file string) (string, error) {
			_, ipcSocket, err := ReadServerPaths(file)
			return ipcSocket, err
		},
		"client.ipc_socket": func(file string) (string, error) {
			return ReadClientField(file, "ipc_socket")
		},
	}
	for _, f := range pathFields {
		read, ok := readers[f.field]
		if !ok {
			continue
		}
		write := writeClientYAML
		if f.server {
			write = writeServerYAML
		}
		for _, path := range relativePaths() {
			file := write(t, strings.Replace(f.yaml, "PATH", path, 1))
			want := fmt.Sprintf("%s: must be an absolute path, got %q", f.field, path)
			if _, err := read(file); err == nil || err.Error() != want {
				t.Errorf("%s = %q: error = %v, want %s", f.field, path, err, want)
			}
		}
		for _, path := range absolutePaths() {
			file := write(t, strings.Replace(f.yaml, "PATH", path, 1))
			if got, err := read(file); err != nil || got != path {
				t.Errorf("%s = %q: read %q, %v", f.field, path, got, err)
			}
		}
	}
}
