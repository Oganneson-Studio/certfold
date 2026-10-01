package enroll

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCreateRejectsInvalidClientName(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	srv := NewServer(db, mustBootstrapCA(t))

	for _, name := range []string{"", "Web-1", "web_1", "-web", strings.Repeat("a", 64)} {
		_, err := srv.Create(ctx, "https://certfold.example.com", name, time.Hour)
		if err == nil || !strings.Contains(err.Error(), "invalid client name") {
			t.Errorf("Create(%q) error = %v, want an invalid client name error", name, err)
		}
	}
	tokens, err := db.Tokens.List(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 0 {
		t.Fatalf("rejected names stored %d tokens", len(tokens))
	}
}
