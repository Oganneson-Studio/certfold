package ipc

import (
	"net/http"
	"strconv"
)

// listEvents serves GET /ipc/v1/events?after=<seq>: the events with a Seq
// greater than after, which defaults to 0, and when the daemon started.
func (h *ipcHandlers) listEvents(w http.ResponseWriter, r *http.Request) {
	var after uint64
	if raw := r.URL.Query().Get("after"); raw != "" {
		var err error
		if after, err = strconv.ParseUint(raw, 10, 64); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
	}
	writeJSON(w, http.StatusOK, EventsPage{
		Started: h.deps.Events.Started(),
		Events:  h.deps.Events.Since(after),
	})
}
