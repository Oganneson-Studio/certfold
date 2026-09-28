package server

import (
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

// The Certificates tab says what set Renew At, in the table and in the
// details of the selected certificate.
func TestCertificatesShowRenewSource(t *testing.T) {
	renew := time.Now().Add(30 * 24 * time.Hour)
	fake := newFake(3)
	fake.certs = []*ipc.CertificateInfo{
		{Name: "api-prod", State: ipc.CertStateValid, RenewAt: renew, RenewSource: "ari"},
		{Name: "mail", State: ipc.CertStateValid, RenewAt: renew, RenewSource: "ratio"},
		{Name: "new-cert", State: ipc.CertStatePending},
	}
	m := onTab(t, fake, tabCertificates)

	date := renew.Local().Format("2006-01-02")
	for i, want := range []string{date + " (ari)", date + " (ratio)", "-"} {
		if got := m.certsTable.Rows()[i][3]; got != want {
			t.Errorf("Renew At of %s = %q, want %q", m.certs[i].Name, got, want)
		}
	}
	// onTab selects the second row, mail.
	if want := "Renew At " + renew.Local().Format("2006-01-02 15:04 MST") + " (ratio)"; !shows(m, want) {
		t.Errorf("the details of mail lack %q: %q", want, m.View())
	}
}
