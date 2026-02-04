package main

import (
	"strings"
	"testing"

	"github.com/wg-keeper/wg-keeper-node/internal/config"
)

func TestHandleInit_NoArgs(t *testing.T) {
	cfg := config.Config{}
	handled, err := handleInit(cfg, []string{"wg-keeper-node"})
	if err != nil {
		t.Fatalf("handleInit: unexpected error: %v", err)
	}
	if handled {
		t.Fatal("handleInit: expected not handled (run server), got handled")
	}
}

func TestHandleInit_UnknownCommand(t *testing.T) {
	cfg := config.Config{}
	handled, err := handleInit(cfg, []string{"wg-keeper-node", "foo"})
	if !handled {
		t.Fatal("handleInit: expected handled (exit with error), got not handled")
	}
	if err == nil {
		t.Fatal("handleInit: expected error for unknown command, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown command") {
		t.Errorf("handleInit: error should mention unknown command, got: %s", msg)
	}
	if !strings.Contains(msg, "foo") {
		t.Errorf("handleInit: error should mention command name, got: %s", msg)
	}
	if !strings.Contains(msg, "init") {
		t.Errorf("handleInit: error should hint at valid usage (init), got: %s", msg)
	}
}
