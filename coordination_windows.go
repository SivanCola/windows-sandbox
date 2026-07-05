//go:build windows

package winsandbox

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// Reasonix launches every sandboxed command as its own helper process, so two
// commands running against the same workspace are separate OS processes. This
// sandbox enforces its boundary by temporarily mutating a path's ACLs and
// integrity label and restoring them from a snapshot afterward. If two
// processes did that on the same root concurrently, their grant/deny edits and
// snapshot restores would interleave: one command's cleanup would tear down the
// boundary the other still relies on, producing either a false permission
// failure or — worse — a lapse in the forbid_read / writable boundary. A shared
// path has no per-process ACL view, so short of re-architecting the isolation
// primitive the only safe option is to serialize whole runs that touch the same
// root.
//
// windowsRootLock takes a per-root named mutex for the lifetime of a run. The
// mutex lives in the session-local namespace and the OS releases it
// automatically if the holder dies, so a crashed command never deadlocks the
// next one (WAIT_ABANDONED is treated as ownership). Multiple roots are locked
// in a stable sorted order so two processes cannot deadlock by acquiring them
// in opposite orders.
//
// Trade-off: a long-running sandboxed command (including a background job)
// holds its root's lock for its whole lifetime, so other sandboxed commands on
// the same root queue behind it. That is the price of a mutation-based sandbox;
// the alternative is boundary corruption. The wait is bounded
// (WINDOWS_SANDBOX_LOCK_MS) so a stuck holder surfaces as a clear error instead
// of an indefinite hang.
const defaultWindowsRootLockTimeout = 10 * time.Minute

// stillActiveExitCode is STILL_ACTIVE: GetExitCodeProcess reports it while a
// process is running. Used to tell a live marker-owner from a dead one.
const stillActiveExitCode = 259

// Windows mutexes have thread affinity: the thread that acquires a mutex is the
// only one that can release it (ReleaseMutex from another thread fails with
// ERROR_NOT_OWNER), and the owning thread re-acquiring is a no-op that would
// break serialization within a process. A Go goroutine can migrate across OS
// threads between the acquire and the deferred release, so the lock pins itself
// to one OS thread for its whole lifetime with runtime.LockOSThread and unpins
// on release. This keeps ReleaseMutex on the owning thread and prevents a
// concurrent goroutine that happens to land on the owner thread from re-entering
// the mutex.
type windowsRootLock struct {
	handles []windows.Handle
	pinned  bool
}

func windowsRootLockTimeout() time.Duration {
	if raw := os.Getenv("WINDOWS_SANDBOX_LOCK_MS"); raw != "" {
		if ms, err := strconv.ParseUint(raw, 10, 63); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return defaultWindowsRootLockTimeout
}

// lockWindowsRoots serializes access to every distinct root in roots. The
// returned lock must be released once the run's grants have been cleaned up.
func lockWindowsRoots(roots []string) (*windowsRootLock, error) {
	names := windowsRootLockNames(roots)
	if len(names) == 0 {
		return &windowsRootLock{}, nil
	}
	lock := &windowsRootLock{}
	// Pin before acquiring the first mutex and stay pinned until release so every
	// mutex is owned by, and released from, the same OS thread.
	runtime.LockOSThread()
	lock.pinned = true
	timeout := windowsRootLockTimeout()
	for _, name := range names {
		h, err := acquireNamedMutex(name, timeout)
		if err != nil {
			lock.release()
			return nil, err
		}
		lock.handles = append(lock.handles, h)
	}
	return lock, nil
}

func (l *windowsRootLock) release() {
	if l == nil {
		return
	}
	for i := len(l.handles) - 1; i >= 0; i-- {
		h := l.handles[i]
		if h == 0 {
			continue
		}
		_ = windows.ReleaseMutex(h)
		_ = windows.CloseHandle(h)
	}
	l.handles = nil
	if l.pinned {
		runtime.UnlockOSThread()
		l.pinned = false
	}
}

// windowsRootLockNames maps roots to a deduplicated, sorted list of mutex
// names. Sorting guarantees a global acquisition order across processes so a
// multi-root run cannot deadlock against another acquiring the same roots in a
// different order.
func windowsRootLockNames(roots []string) []string {
	seen := map[string]bool{}
	var names []string
	for _, root := range roots {
		key := strings.ToLower(filepath.Clean(root))
		if key == "" || key == "." || seen[key] {
			continue
		}
		seen[key] = true
		sum := sha1.Sum([]byte(key))
		names = append(names, `Local\windows-sandbox.`+hex.EncodeToString(sum[:16]))
	}
	sort.Strings(names)
	return names
}

func acquireNamedMutex(name string, timeout time.Duration) (windows.Handle, error) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	// CreateMutex returns a valid handle even when the named mutex already
	// exists (err == ERROR_ALREADY_EXISTS); only a zero handle is a real error.
	h, err := windows.CreateMutex(nil, false, name16)
	if h == 0 {
		return 0, fmt.Errorf("create sandbox mutex %q: %w", name, err)
	}
	ms := uint32(windows.INFINITE)
	if timeout > 0 {
		ms = uint32(timeout / time.Millisecond)
	}
	event, werr := windows.WaitForSingleObject(h, ms)
	switch event {
	case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
		// WAIT_ABANDONED means the previous holder died without releasing. We now
		// own the mutex; any filesystem residue that run left behind is cleared by
		// sweepWindowsDenyResidue before we re-apply, and the integrity-label reset
		// on cleanup returns the tree to Medium.
		return h, nil
	case uint32(windows.WAIT_TIMEOUT):
		_ = windows.CloseHandle(h)
		return 0, fmt.Errorf("timed out waiting for sandbox lock %q after %s", name, timeout)
	default:
		_ = windows.CloseHandle(h)
		if werr != nil {
			return 0, fmt.Errorf("wait for sandbox lock %q: %w", name, werr)
		}
		return 0, fmt.Errorf("wait for sandbox lock %q returned %#x", name, event)
	}
}

// windowsMutatedRoots is the set of paths a run edits ACLs on: its writable
// roots plus any forbid_read roots that exist. These are the paths that must be
// serialized against concurrent runs and tracked for crash-residue cleanup.
func windowsMutatedRoots(spec Spec) []string {
	roots := append([]string(nil), windowsWritableRoots(spec)...)
	for _, r := range normalizedWindowsRoots(spec.ForbidReadRoots) {
		if pathExists(r) {
			roots = append(roots, r)
		}
	}
	return roots
}

// forbid_read applies a deny ACE for the current user SID so a same-user
// low-integrity child cannot bypass the deny through normal file ACLs. That ACE
// is removed on normal cleanup, but a crash (or force-kill) skips cleanup and
// leaves the user denied read on, e.g., ~/.ssh — locking their editor and git
// out until they repair the ACL by hand. The deny-residue tracker records which
// paths a run denied in a per-PID marker file; the next run sweeps markers whose
// owning process is gone and removes the lingering deny ACEs. Only deny ACEs for
// the stable, sandbox-applied trustees are removed, so legitimate ACLs are left
// untouched.

func windowsDenyMarkerDir() string {
	return filepath.Join(os.TempDir(), "windows-sandbox-denylocks")
}

func windowsDenyMarkerPath() string {
	return filepath.Join(windowsDenyMarkerDir(), strconv.Itoa(os.Getpid())+".txt")
}

// recordWindowsDenyResidue notes that this process applied deny ACEs to paths so
// a later run can clean them up if this process dies before its own cleanup.
func recordWindowsDenyResidue(paths []string) {
	if len(paths) == 0 {
		return
	}
	dir := windowsDenyMarkerDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	var b strings.Builder
	for _, p := range paths {
		b.WriteString(p)
		b.WriteByte('\n')
	}
	_ = os.WriteFile(windowsDenyMarkerPath(), []byte(b.String()), 0o600)
}

// clearWindowsDenyResidueMarker drops this process's marker after its own
// cleanup has removed the deny ACEs.
func clearWindowsDenyResidueMarker() {
	_ = os.Remove(windowsDenyMarkerPath())
}

// sweepWindowsDenyResidue removes deny ACEs left by crashed runs. It only acts
// on markers whose owning PID is no longer alive, and only removes the stable
// sandbox-applied deny trustees, so it never disturbs a live run or a
// legitimate ACL. Best-effort: any error is ignored so it can never block a run.
func sweepWindowsDenyResidue() {
	dir := windowsDenyMarkerDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	userSID, _ := currentProcessUserSIDString()
	denySIDs := dedupeSIDStrings([]string{
		allApplicationPackagesSID,
		allRestrictedApplicationPackagesSID,
		userSID,
	})
	self := strconv.Itoa(os.Getpid())
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		pid := strings.TrimSuffix(entry.Name(), ".txt")
		if pid == self || windowsProcessAlive(pid) {
			continue
		}
		markerPath := filepath.Join(dir, entry.Name())
		for _, path := range readWindowsDenyMarker(markerPath) {
			if pathExists(path) {
				removeDeniedAppContainerSIDs(path, denySIDs)
			}
		}
		_ = os.Remove(markerPath)
	}
}

func readWindowsDenyMarker(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// windowsProcessAlive reports whether the given PID is still running. A parse
// failure or a process that cannot be opened is treated as not-alive so stale
// markers get cleaned; PID reuse can only delay cleanup, never corrupt a live
// run (a live run holds the root lock and re-records its own marker).
func windowsProcessAlive(pidStr string) bool {
	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil || pid == 0 {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var code uint32
	if err := windows.GetExitCodeProcess(handle, &code); err != nil {
		return false
	}
	return code == stillActiveExitCode
}
