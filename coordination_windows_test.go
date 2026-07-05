//go:build windows

package winsandbox

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWindowsRootLockNamesAreSortedAndDeduped(t *testing.T) {
	names := windowsRootLockNames([]string{
		`C:\work\b`,
		`C:\work\a`,
		`C:\WORK\A`, // same as a, different case
		"",
		".",
	})
	if len(names) != 2 {
		t.Fatalf("lock names = %v, want 2 distinct roots", names)
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("lock names must be sorted for deadlock-free acquisition: %v", names)
	}
	for _, n := range names {
		if !strings.HasPrefix(n, `Local\windows-sandbox.`) {
			t.Fatalf("unexpected lock name %q", n)
		}
	}
	// Case-insensitive dedup: A and a must collapse to one name.
	same := windowsRootLockNames([]string{`C:\work\a`})
	if len(same) != 1 || !contains(names, same[0]) {
		t.Fatalf("case-insensitive dedup broken: %v vs %v", names, same)
	}
}

func TestWindowsRootLockSerializesSameRoot(t *testing.T) {
	root := t.TempDir()
	// The two locks target the same root, so the second acquire must block until
	// the first releases. Use a short timeout so a regression fails fast.
	t.Setenv("WINDOWS_SANDBOX_LOCK_MS", "2000")

	first, err := lockWindowsRoots([]string{root})
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}

	acquired := make(chan *windowsRootLock, 1)
	go func() {
		second, err := lockWindowsRoots([]string{root})
		if err != nil {
			acquired <- nil
			return
		}
		acquired <- second
	}()

	select {
	case <-acquired:
		t.Fatal("second lock acquired while first was held; roots not serialized")
	case <-time.After(300 * time.Millisecond):
		// Expected: still blocked.
	}

	first.release()
	select {
	case second := <-acquired:
		if second == nil {
			t.Fatal("second lock failed to acquire after first released")
		}
		second.release()
	case <-time.After(3 * time.Second):
		t.Fatal("second lock never acquired after first released")
	}
}

func TestWindowsRootLockTimesOutWhenHeld(t *testing.T) {
	root := t.TempDir()
	t.Setenv("WINDOWS_SANDBOX_LOCK_MS", "300")
	held, err := lockWindowsRoots([]string{root})
	if err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	defer held.release()

	start := time.Now()
	if _, err := lockWindowsRoots([]string{root}); err == nil {
		t.Fatal("expected timeout acquiring a held lock")
	} else if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %v, want timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("lock timeout took too long: %s", elapsed)
	}
}

func TestWindowsRootLockMultiRootNoSelfDeadlock(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	t.Setenv("WINDOWS_SANDBOX_LOCK_MS", "2000")
	// Acquiring multiple roots in one call must not deadlock regardless of the
	// order the caller passes them, because names are sorted internally.
	lock, err := lockWindowsRoots([]string{b, a, b})
	if err != nil {
		t.Fatalf("multi-root lock: %v", err)
	}
	lock.release()
}

func TestWindowsDenyResidueRoundTrip(t *testing.T) {
	// Redirect the marker dir into a temp dir so the test never touches the real
	// %TEMP%. windowsDenyMarkerDir derives from os.TempDir, so overriding TMP is
	// enough on Windows.
	tmp := t.TempDir()
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)

	paths := []string{`C:\Users\me\.ssh`, `C:\Users\me\.netrc`}
	recordWindowsDenyResidue(paths)

	marker := windowsDenyMarkerPath()
	if !pathExists(marker) {
		t.Fatalf("marker not written at %s", marker)
	}
	got := readWindowsDenyMarker(marker)
	if len(got) != len(paths) {
		t.Fatalf("marker round-trip = %v, want %v", got, paths)
	}
	for i := range paths {
		if got[i] != paths[i] {
			t.Fatalf("marker[%d] = %q, want %q", i, got[i], paths[i])
		}
	}

	clearWindowsDenyResidueMarker()
	if pathExists(marker) {
		t.Fatal("marker not cleared")
	}
}

func TestWindowsProcessAliveDetectsSelfAndDead(t *testing.T) {
	if !windowsProcessAlive(strconv.Itoa(os.Getpid())) {
		t.Fatal("current process should be reported alive")
	}
	// PID 0 and garbage never map to a live user process.
	for _, dead := range []string{"0", "not-a-pid", ""} {
		if windowsProcessAlive(dead) {
			t.Fatalf("%q should not be reported alive", dead)
		}
	}
}

func TestWindowsMutatedRootsIncludesForbidReadThatExists(t *testing.T) {
	workspace := t.TempDir()
	secret := filepath.Join(workspace, "secret")
	if err := os.Mkdir(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(workspace, "does-not-exist")
	got := windowsMutatedRoots(Spec{
		WritableRoots:   []string{workspace},
		ForbidReadRoots: []string{secret, missing},
		Writable:        true,
	})
	if !containsWindowsPath(got, workspace) || !containsWindowsPath(got, secret) {
		t.Fatalf("mutated roots = %v, want workspace and existing secret", got)
	}
	if containsWindowsPath(got, missing) {
		t.Fatalf("mutated roots must skip missing forbid_read paths: %v", got)
	}
}

func TestWindowsICACLSTimeoutRecursiveVsFlat(t *testing.T) {
	os.Unsetenv("WINDOWS_SANDBOX_ICACLS_TIMEOUT_MS")
	if got := icaclsTimeoutForArgs([]string{"/setintegritylevel", "L", "/T", "/C"}); got != defaultICACLSRecursiveTimeout {
		t.Fatalf("recursive timeout = %s, want %s", got, defaultICACLSRecursiveTimeout)
	}
	if got := icaclsTimeoutForArgs([]string{"/setintegritylevel", "M", "/C"}); got != defaultICACLSTimeout {
		t.Fatalf("flat timeout = %s, want %s", got, defaultICACLSTimeout)
	}
	t.Setenv("WINDOWS_SANDBOX_ICACLS_TIMEOUT_MS", "1234")
	if got := icaclsTimeoutForArgs([]string{"/T"}); got != 1234*time.Millisecond {
		t.Fatalf("env override = %s, want 1.234s", got)
	}
}

func TestSystemRootToolResolvesUnderSystem32(t *testing.T) {
	got := systemRootTool("icacls.exe")
	// On any real Windows host this resolves to an absolute System32 path; the
	// fallback (bare name) only happens if the file is genuinely missing.
	if got == "icacls.exe" {
		t.Skip("icacls.exe not found under System32 on this host")
	}
	if !filepath.IsAbs(got) || !strings.EqualFold(filepath.Base(got), "icacls.exe") {
		t.Fatalf("resolved tool = %q, want absolute System32 icacls.exe", got)
	}
	if !strings.Contains(strings.ToLower(got), `system32`) {
		t.Fatalf("resolved tool = %q, want a System32 path", got)
	}
}

// TestWindowsSandboxConcurrentWritesToSharedWorkspace exercises the concurrency
// fix end-to-end: several sandboxed writable commands run at once against the
// same non-empty workspace with nested directories. Before the root lock, their
// ACL/label mutations and snapshot restores would interleave and one command's
// cleanup could revoke another's write grant mid-run, surfacing as a spurious
// failure. With serialization every command must succeed and its file must be
// written. The empty-temp-dir CI coverage that shipped originally could not
// catch this.
func TestWindowsSandboxConcurrentWritesToSharedWorkspace(t *testing.T) {
	if !Available() {
		t.Skip("windows sandbox APIs unavailable")
	}
	sh := powershellArgvForTest(t, "")
	if sh == nil {
		t.Skip("PowerShell unavailable")
	}
	workspace := t.TempDir()
	// Pre-populate with nested content so the writable relabel actually walks a
	// subtree (the empty-dir case hid #1/#2/#3).
	nested := filepath.Join(workspace, "pkg", "sub")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"a.txt", filepath.Join("pkg", "b.txt"), filepath.Join("pkg", "sub", "c.txt")} {
		if err := os.WriteFile(filepath.Join(workspace, f), []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	const n = 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			target := filepath.Join(workspace, "out"+strconv.Itoa(idx)+".txt")
			script := "$ErrorActionPreference='Stop'; Set-Content -LiteralPath " + psQuote(target) + " -Value ok"
			result, err := Run(
				Spec{WritableRoots: []string{workspace}, Network: true, Writable: true, TempPrefix: "windows-sandbox-test-"},
				append(sh, script),
				RunOptions{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr},
			)
			if err != nil {
				errs[idx] = err
				return
			}
			if result.ExitCode != 0 {
				errs[idx] = errExitf(idx, result.ExitCode)
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("concurrent command %d failed: %v", i, errs[i])
		}
		target := filepath.Join(workspace, "out"+strconv.Itoa(i)+".txt")
		if got, err := os.ReadFile(target); err != nil || !strings.Contains(string(got), "ok") {
			t.Fatalf("concurrent command %d output missing: %q err=%v", i, got, err)
		}
	}
	// After all runs the workspace must carry no leftover Low integrity label or
	// sandbox deny ACE.
	assertNoWindowsSandboxACEForTest(t, workspace)
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func containsWindowsPath(haystack []string, needle string) bool {
	for _, h := range haystack {
		if sameWindowsPath(h, needle) {
			return true
		}
	}
	return false
}

func errExitf(idx, code int) error {
	return &exitError{idx: idx, code: code}
}

type exitError struct {
	idx  int
	code int
}

func (e *exitError) Error() string {
	return "command " + strconv.Itoa(e.idx) + " exit code " + strconv.Itoa(e.code)
}
