package client

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Oganneson-Studio/certfold/internal/ipc"
)

// TestViewFitsTheScreen covers more certificates than fit on the screen, with
// and without the full help: the view keeps to the height of the screen, the
// title and the column titles stay on top, and one line says how many
// certificates it leaves out. With a few certificates it lists them all.
func TestViewFitsTheScreen(t *testing.T) {
	for _, n := range []int{2, 25} {
		f := newTestBackend()
		f.state.Certs = nil
		for i := range n {
			f.state.Certs = append(f.state.Certs, ipc.ClientCertState{
				Name: fmt.Sprintf("cert-%02d", i), NotAfter: time.Now().Add(60 * 24 * time.Hour), Outputs: 1,
			})
		}
		f.emit(30, "event")
		for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 24}, {Width: 120, Height: 40}} {
			for _, keys := range [][]string{nil, {"?"}} {
				m, _ := step(t, newModel(t, f), size)
				for _, k := range keys {
					m = press(t, m, k)
				}
				view := plain(m)
				name := fmt.Sprintf("%d certificates at %dx%d with keys %q", n, size.Width, size.Height, keys)

				lines := strings.Split(view, "\n")
				if len(lines) > size.Height || !strings.Contains(lines[0], "certfoldc  web-1") {
					t.Errorf("%s: view of %d lines, the first %q", name, len(lines), lines[0])
				}
				if !strings.Contains(view, "Name     Not After") {
					t.Errorf("%s: view lacks the column titles:\n%s", name, view)
				}
				shown := strings.Count(view, "cert-")
				more := fmt.Sprintf("+%d more; certfoldc status --json lists them all", n-shown)
				if n > shown && !strings.Contains(view, more) || n == shown && strings.Contains(view, "more;") {
					t.Errorf("%s: view shows %d certificates, and lacks %q or says more:\n%s", name, shown, more, view)
				}
				if size.Height == 24 && n > 20 && shown == n {
					t.Errorf("%s: view shows all %d certificates", name, n)
				}
			}
		}
	}
}
