package output

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// reconcileErrorTwice runs Reconcile twice on the same failure and returns
// the error, which must read the same both times and name no temporary file:
// sigilc logs its last error again whenever the text changes, so a random
// temporary file name in it would log the failure on every round.
func reconcileErrorTwice(t *testing.T, b *CertBundle, spec config.OutputSpec) string {
	t.Helper()
	var texts [2]string
	for i := range texts {
		changed, err := Reconcile(b, []config.OutputSpec{spec})
		if err == nil || changed {
			t.Fatalf("Reconcile %d = %v, %v; want an error and no change", i+1, changed, err)
		}
		texts[i] = err.Error()
	}
	if texts[0] != texts[1] {
		t.Fatalf("the same failure reads differently:\n%s\n%s", texts[0], texts[1])
	}
	if strings.Contains(texts[0], ".sigil-tmp-") {
		t.Fatalf("error names a temporary file: %s", texts[0])
	}
	return texts[0]
}

// TestReconcileErrorOfFailedReplaceIsStable covers an output that cannot be
// replaced, here because a directory is in its place: the error names the
// output and the cause.
func TestReconcileErrorOfFailedReplaceIsStable(t *testing.T) {
	spec := config.OutputSpec{Format: "pem-cert", Path: filepath.Join(t.TempDir(), "cert.pem")}
	// No file can be renamed over a directory that is not empty.
	if err := os.MkdirAll(filepath.Join(spec.Path, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if text := reconcileErrorTwice(t, makeBundle(t), spec); !strings.HasPrefix(text, "replace "+spec.Path+": ") {
		t.Fatalf("error = %s, want it to name the output it could not replace", text)
	}
	checkNoTemps(t, filepath.Dir(spec.Path))
}

// TestWithoutTempName covers the errors of operations on a temporary file:
// the *os.PathError or *os.LinkError that names the file is left out, and
// its cause kept; other errors are kept whole.
func TestWithoutTempName(t *testing.T) {
	cause := syscall.ENOSPC
	other := errors.New("lookup user \"svc\": unknown user svc")
	for _, tc := range []struct {
		err  error
		want error
	}{
		{&os.PathError{Op: "write", Path: "/etc/ssl/.sigil-tmp-1", Err: cause}, cause},
		{&os.LinkError{Op: "rename", Old: "/etc/ssl/.sigil-tmp-1", New: "/etc/ssl/cert.pem", Err: cause}, cause},
		{other, other},
	} {
		if got := withoutTempName(tc.err); got != tc.want {
			t.Errorf("withoutTempName(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
