package server

import (
	"context"
	"log/slog"
	"strings"
)

// legoLog is the writer of the logger of lego, which marks a line "[INFO] "
// or "[WARN] ". It logs each line through the default logger, with the
// attribute component=lego: at WARN, without the mark, when it is marked
// "[WARN] ", and at INFO otherwise.
type legoLog struct{}

func (legoLog) Write(p []byte) (int, error) {
	line := strings.TrimSuffix(string(p), "\n")
	level := slog.LevelInfo
	if rest, ok := strings.CutPrefix(line, "[WARN] "); ok {
		level, line = slog.LevelWarn, rest
	} else {
		line = strings.TrimPrefix(line, "[INFO] ")
	}
	slog.Default().Log(context.Background(), level, line, "component", "lego")
	return len(p), nil
}
