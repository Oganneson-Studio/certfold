package service

import (
	"errors"
	"strings"
	"testing"

	ksvc "github.com/kardianos/service"
)

// fakeService is a kardianos service whose Install fails with installErr and
// whose Status answers status and statusErr.
type fakeService struct {
	ksvc.Service
	installErr error
	status     ksvc.Status
	statusErr  error
}

func (s fakeService) Install() error               { return s.installErr }
func (s fakeService) Status() (ksvc.Status, error) { return s.status, s.statusErr }

// TestInstallOverExistingServiceSaysHowToGoOn covers `service install` run
// again, which kardianos refuses: the error says to uninstall first, but only
// when the service exists.
func TestInstallOverExistingServiceSaysHowToGoOn(t *testing.T) {
	failed := errors.New("service certfoldc already exists")
	for _, tc := range []struct {
		name      string
		svc       fakeService
		wantHint  bool
		wantError bool
	}{
		{name: "installed", svc: fakeService{installErr: failed, status: ksvc.StatusStopped}, wantHint: true, wantError: true},
		{name: "failed unit", svc: fakeService{installErr: failed, statusErr: errors.New("service in failed state")}, wantHint: true, wantError: true},
		{name: "not installed", svc: fakeService{installErr: errors.New("access denied"), statusErr: ksvc.ErrNotInstalled}, wantError: true},
		{name: "installs", svc: fakeService{statusErr: ksvc.ErrNotInstalled}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := install(tc.svc, RoleClient)
			if (err != nil) != tc.wantError {
				t.Fatalf("install: error = %v, want error %t", err, tc.wantError)
			}
			if err == nil {
				return
			}
			if !errors.Is(err, tc.svc.installErr) {
				t.Errorf("install error = %v, want it to wrap %v", err, tc.svc.installErr)
			}
			if hint := strings.Contains(err.Error(), "run `certfoldc service uninstall` first"); hint != tc.wantHint {
				t.Errorf("install error = %v; uninstall hint %t, want %t", err, hint, tc.wantHint)
			}
		})
	}
}
