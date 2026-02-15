package main

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/wg-keeper/wg-keeper-node/internal/config"
)

const (
	testSubnet4     = "10.0.0.0/24"
	testSubnet6     = "fd00::/64"
	testBinName     = "wg-keeper-node"
	testWGInterface = "wg0"
	testWGServerIP  = "10.0.0.1"
	testWGConfBody  = "[Interface]\nPrivateKey = x\n"
	testErrGotFmt   = "got %q"
	testErrGotMsg   = "got: %s"
	testDirWG       = "wireguard"
	testWGConfFile  = "wg0.conf"
)

func TestFormatSubnetsLog(t *testing.T) {
	if got := formatSubnetsLog(config.Config{WGSubnet: testSubnet4}); got != testSubnet4 {
		t.Errorf(testErrGotFmt, got)
	}
	if got := formatSubnetsLog(config.Config{WGSubnet6: testSubnet6}); got != testSubnet6 {
		t.Errorf(testErrGotFmt, got)
	}
	if got := formatSubnetsLog(config.Config{WGSubnet: testSubnet4, WGSubnet6: testSubnet6}); got != testSubnet4+","+testSubnet6 {
		t.Errorf(testErrGotFmt, got)
	}
}

func TestProtocolFromConfig(t *testing.T) {
	if got := protocolFromConfig(config.Config{}); got != "http" {
		t.Errorf(testErrGotFmt, got)
	}
	if got := protocolFromConfig(config.Config{TLSCertFile: "a", TLSKeyFile: "b"}); got != "https" {
		t.Errorf(testErrGotFmt, got)
	}
}

func TestIsFatalServerError(t *testing.T) {
	if isFatalServerError(nil) {
		t.Error("nil should not be fatal")
	}
	if isFatalServerError(http.ErrServerClosed) {
		t.Error("ErrServerClosed should not be fatal")
	}
	if !isFatalServerError(os.ErrNotExist) {
		t.Error("other errors should be fatal")
	}
}

func TestIsDebugEnabled(t *testing.T) {
	orig := os.Getenv("DEBUG")
	defer os.Setenv("DEBUG", orig)
	os.Unsetenv("DEBUG")
	if isDebugEnabled() {
		t.Error("unset should be false")
	}
	os.Setenv("DEBUG", "true")
	if !isDebugEnabled() {
		t.Error("true should be true")
	}
	os.Setenv("DEBUG", "1")
	if !isDebugEnabled() {
		t.Error("1 should be true")
	}
}

func TestHandleInitNoArgs(t *testing.T) {
	cfg := config.Config{}
	handled, err := handleInit(cfg, []string{testBinName})
	if err != nil {
		t.Fatalf("handleInit: unexpected error: %v", err)
	}
	if handled {
		t.Fatal("handleInit: expected not handled (run server), got handled")
	}
}

func TestHandleInitUnknownCommand(t *testing.T) {
	cfg := config.Config{}
	handled, err := handleInit(cfg, []string{testBinName, "foo"})
	if !handled {
		t.Fatal("handleInit: expected handled (exit with error), got not handled")
	}
	if err == nil {
		t.Fatal("handleInit: expected error for unknown command, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown command") {
		t.Errorf("handleInit: error should mention unknown command, "+testErrGotMsg, msg)
	}
	if !strings.Contains(msg, "foo") {
		t.Errorf("handleInit: error should mention command name, "+testErrGotMsg, msg)
	}
	if !strings.Contains(msg, "init") {
		t.Errorf("handleInit: error should hint at valid usage (init), "+testErrGotMsg, msg)
	}
}

func TestHandleInitInit(t *testing.T) {
	dir := t.TempDir()
	wgDir := dir + "/" + testDirWG
	if err := os.MkdirAll(wgDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(wgDir+"/"+testWGConfFile, []byte(testWGConfBody), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(cwd) }()

	cfg := config.Config{
		WGInterface:  testWGInterface,
		WGSubnet:     testSubnet4,
		WGServerIP:   testWGServerIP,
		WGListenPort: 51820,
	}
	handled, err := handleInit(cfg, []string{testBinName, "init"})
	if err != nil {
		t.Fatalf("handleInit init: %v", err)
	}
	if !handled {
		t.Fatal("expected handled")
	}
}

func TestHandleInitInitPrintPath(t *testing.T) {
	dir := t.TempDir()
	wgDir := dir + "/" + testDirWG
	if err := os.MkdirAll(wgDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(wgDir+"/"+testWGConfFile, []byte(testWGConfBody), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(cwd) }()

	cfg := config.Config{
		WGInterface:  testWGInterface,
		WGSubnet:     testSubnet4,
		WGServerIP:   testWGServerIP,
		WGListenPort: 51820,
	}
	handled, err := handleInit(cfg, []string{testBinName, "init", "--print-path"})
	if err != nil {
		t.Fatalf("handleInit init --print-path: %v", err)
	}
	if !handled {
		t.Fatal("expected handled")
	}
}
