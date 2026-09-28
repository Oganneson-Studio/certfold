package server

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"time"
)

// maxErrorLinesPerMinute bounds the lines the HTTPS server logs per minute.
// Anyone who reaches its port can make it log a line per failed TLS
// handshake, and a Windows service writes every line to the Application log,
// where a flood would push out the events of other programs.
const maxErrorLinesPerMinute = 10

// limitedWriter passes at most maxErrorLinesPerMinute lines a minute to w and
// drops the others. The first line it passes after dropping some says how
// many it dropped. Each Write is one line, as a log.Logger writes them.
type limitedWriter struct {
	w     io.Writer
	clock func() time.Time

	mu      sync.Mutex
	start   time.Time // when the current minute began
	passed  int       // lines passed since start
	dropped int       // lines dropped since the last line passed
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := l.clock(); now.Sub(l.start) >= time.Minute {
		l.start, l.passed = now, 0
	}
	if l.passed == maxErrorLinesPerMinute {
		l.dropped++
		return len(p), nil
	}
	l.passed++
	line := p
	if l.dropped > 0 {
		line = fmt.Appendf(nil, "%s (%d earlier lines dropped)\n", bytes.TrimSuffix(p, []byte("\n")), l.dropped)
		l.dropped = 0
	}
	if _, err := l.w.Write(line); err != nil {
		return 0, err
	}
	return len(p), nil
}
