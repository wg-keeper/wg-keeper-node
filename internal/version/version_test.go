package version

import (
	"testing"
)

func TestName(t *testing.T) {
	if Name != "wg-keeper-node" {
		t.Errorf("Name = %q, want wg-keeper-node", Name)
	}
}

func TestVersionNonEmpty(t *testing.T) {
	if Version == "" {
		t.Error("Version must not be empty")
	}
}
