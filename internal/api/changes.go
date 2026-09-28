package api

import "sync"

// Changes wakes the GET /v1/sync requests that wait for their client's view to
// change. It broadcasts by closing a channel and replacing it: every request
// waiting on the closed channel wakes, and requests that start waiting later
// get the new one. The daemon notifies after a certificate is stored and after
// a reload is published.
type Changes struct {
	mu sync.Mutex
	ch chan struct{}
}

// NewChanges returns a Changes ready for use.
func NewChanges() *Changes {
	return &Changes{ch: make(chan struct{})}
}

// Notify wakes every request waiting for a change. It does not wait for them
// and may be called concurrently.
func (c *Changes) Notify() {
	c.mu.Lock()
	defer c.mu.Unlock()
	close(c.ch)
	c.ch = make(chan struct{})
}

// wait returns a channel that the next Notify closes. A handler must take it
// before it reads the configuration and the store to compute the view (a
// reload changes the configuration, not the store): a Notify that lands between
// the read and the wait would otherwise be lost, and the request would sit out
// the rest of its wait despite the change.
func (c *Changes) wait() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ch
}
