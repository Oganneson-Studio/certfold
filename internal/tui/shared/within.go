package shared

import (
	"context"
	"time"
)

// Within calls f with a context that ends after timeout. The TUIs bound each
// IPC call of a refresh with it, so that a daemon that does not answer shows
// on the status line rather than holding the refresh until the IPC client
// gives up after five minutes.
func Within[T any](timeout time.Duration, f func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return f(ctx)
}
