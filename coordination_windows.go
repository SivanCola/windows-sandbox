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
	"sync/atomic"
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

// windowsMutatedRootsForRun extends windowsMutatedRoots with the executable
// directories the run will actually mutate ACLs on: the non-system ones. A run
// snapshots/grants/restores argv[0]'s directory (and a Git install root), so two
// runs in different workspaces that share one tool directory would otherwise
// interleave their ACL snapshots and corrupt each other. System tool directories
// (System32, Program Files) are never mutated (grantAppContainerExecutable skips
// them), so they must stay out of the lock too — both sets draw from the same
// windowsMutableExecutableGrantRoots so the locked paths and the mutated paths
// cannot drift apart, and every command sharing the system shell is spared a
// needless serialization.
func windowsMutatedRootsForRun(spec Spec, exe string) []string {
	roots := windowsMutatedRoots(spec)
	return append(roots, windowsMutableExecutableGrantRoots(exe)...)
}

// isWindowsSystemRoot reports whether path is inside a Windows system location
// (%SystemRoot%, the Program Files variants). Determined by path membership, not
// by attempting a write, so the result is stable regardless of the process's
// integrity level or admin rights. Backs windowsMutableExecutableGrantRoots,
// which keeps shared system directories out of both the per-root lock set and
// the executable grant/residue set.
func isWindowsSystemRoot(path string) bool {
	clean := strings.ToLower(filepath.Clean(path))
	for _, envVar := range []string{"SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
		root := os.Getenv(envVar)
		if root == "" {
			continue
		}
		root = strings.ToLower(filepath.Clean(root))
		if clean == root || strings.HasPrefix(clean, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// forbid_read applies a deny ACE for the current user SID so a same-user
// low-integrity child cannot bypass the deny through normal file ACLs, and
// writable runs grant AppContainer/user read+execute on the tool executable's
// directory. Both are removed on normal cleanup, but a crash (or force-kill)
// skips cleanup and leaves residue: a deny ACE locks the user out of, e.g.,
// ~/.ssh until they repair the ACL by hand; a stale grant silently widens read
// access to a tool directory. The residue tracker records each mutated path in a
// per-PID marker *before* the ACE is applied, so any crash point leaves a marker
// the next run can sweep; the next run removes the residue for markers whose
// owning process is gone. Only the stable, sandbox-applied trustees are removed,
// so legitimate ACLs are left untouched.
//
// Each marker line is "<kind> <path>", where kind is "deny" or "grant". Lines
// are appended and fsync'd one at a time, and a write failure aborts the run
// before the corresponding ACE is applied, so the marker can never lag behind
// the on-disk ACLs.

type residueKind string

const (
	residueDeny  residueKind = "deny"
	residueGrant residueKind = "grant"
)

type residueEntry struct {
	kind residueKind
	path string
}

func windowsDenyMarkerDir() string {
	return filepath.Join(os.TempDir(), "windows-sandbox-denylocks")
}

func windowsDenyMarkerPath() string {
	return filepath.Join(windowsDenyMarkerDir(), strconv.Itoa(os.Getpid())+".txt")
}

// residueMarkerOwned reports whether this process has written its own residue
// marker. The marker path is keyed by PID alone, and Windows reuses PIDs, so a
// file at our path is not necessarily ours: a crashed predecessor that held
// this PID may have left it behind. Ownership is what separates "our live
// marker" from "a dead run's residue record that happens to share our PID" —
// without it, cleanup would delete the predecessor's record while its ACEs are
// still on disk, orphaning them beyond any future sweep's reach. One sandboxed
// command runs per helper process, so a process-wide flag is sufficient.
var residueMarkerOwned atomic.Bool

// recordResidueBeforeApply appends one "<kind>\t<path>" line to this process's
// marker and flushes it to disk. It is called immediately before the matching
// ACE is applied; a failure here must abort the run before the ACE is applied so
// the marker never lags the on-disk ACLs. Returns an error so the caller can
// fail closed. A tab separates the fields because Windows paths never contain
// one, so the path is recovered unambiguously regardless of spaces in it.
func recordResidueBeforeApply(kind residueKind, path string) error {
	dir := windowsDenyMarkerDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create residue marker dir: %w", err)
	}
	marker := windowsDenyMarkerPath()
	if !residueMarkerOwned.Load() && pathExists(marker) {
		// A marker at our path that we did not write belongs to a dead
		// predecessor that used this PID before us (PIDs are unique among live
		// processes). Consume its residue now, before our first line lands in
		// the same file — appending to it would mix the two runs' records, and
		// our cleanup would then delete both while only our own ACEs had been
		// removed. The run-start sweep normally consumes it first; this covers
		// callers that record without sweeping.
		sweepResidueMarkerFile(marker, sandboxResidueSIDs())
	}
	// Claim ownership before creating the file, not after: once the file can
	// exist at our path, nothing may mistake it for a dead predecessor's. A
	// failed open leaves the flag set with no file, which is harmless — clear
	// becomes a no-op remove.
	residueMarkerOwned.Store(true)
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open residue marker: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(string(kind) + "\t" + path + "\n"); err != nil {
		return fmt.Errorf("write residue marker: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync residue marker: %w", err)
	}
	return nil
}

// clearWindowsDenyResidueMarker drops this process's marker after its own
// cleanup has removed every recorded ACE. It only removes a marker this
// process actually wrote: a file at our path that we never touched records a
// dead PID-reuse predecessor's residue, and deleting it would orphan that
// residue — the ACEs would stay on disk with nothing left for a sweep to find.
func clearWindowsDenyResidueMarker() {
	if !residueMarkerOwned.Load() {
		return
	}
	_ = os.Remove(windowsDenyMarkerPath())
	residueMarkerOwned.Store(false)
}

// sweepWindowsDenyResidue removes ACEs left by crashed runs. It only acts on
// markers whose owning process is provably gone: a PID that is no longer
// alive, or a file at this process's own path that this process never wrote —
// Windows reuses PIDs, so such a file records a dead predecessor's residue,
// and skipping it here (while cleanup deleted it blindly) is how that residue
// used to leak forever. Only the stable sandbox-applied trustees are removed,
// so it never disturbs a live run or a legitimate ACL. Best-effort: any error
// is ignored so it can never block a run.
func sweepWindowsDenyResidue() {
	dir := windowsDenyMarkerDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	sandboxSIDs := sandboxResidueSIDs()
	self := strconv.Itoa(os.Getpid())
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		pid := strings.TrimSuffix(entry.Name(), ".txt")
		if pid == self {
			// Our own path is live only if this process wrote it; otherwise it
			// was left by a dead predecessor that held this PID before us
			// (PIDs are unique among live processes), so fall through and
			// consume it like any other crash residue.
			if residueMarkerOwned.Load() {
				continue
			}
		} else if windowsProcessAlive(pid) {
			continue
		}
		sweepResidueMarkerFile(filepath.Join(dir, entry.Name()), sandboxSIDs)
	}
}

// sandboxResidueSIDs is the trustee set the sweep removes. The sandbox only
// ever applies these trustees, for both grants and denies, so removing exactly
// them cannot disturb a legitimate ACL.
func sandboxResidueSIDs() []string {
	userSID, _ := currentProcessUserSIDString()
	return dedupeSIDStrings([]string{
		allApplicationPackagesSID,
		allRestrictedApplicationPackagesSID,
		userSID,
	})
}

// sweepResidueMarkerFile removes the ACEs recorded in one dead run's marker,
// then the marker itself.
func sweepResidueMarkerFile(markerPath string, sandboxSIDs []string) {
	for _, e := range readResidueMarker(markerPath) {
		if !pathExists(e.path) || !sweepableResidue(e) {
			continue
		}
		switch e.kind {
		case residueDeny:
			removeDeniedAppContainerSIDs(e.path, sandboxSIDs)
		case residueGrant:
			removeGrantedAppContainerSIDs(e.path, sandboxSIDs)
		}
	}
	_ = os.Remove(markerPath)
}

// sweepableResidue reports whether a marker entry names a path the sandbox
// could actually have mutated. The current code never records a system
// directory (windowsMutableExecutableGrantRoots filters them before any
// snapshot, grant, or marker line), but the marker file itself is untrusted
// input: an older sandbox binary may have written one before that filter
// existed, and the marker directory lives under the user's %TEMP%, writable to
// anything running as the same user. Removing the broad built-in package SIDs
// (ALL APPLICATION PACKAGES / ALL RESTRICTED APPLICATION PACKAGES) from
// System32 or Program Files would strip factory ACEs the OS itself relies on,
// so the sweep re-checks the invariant instead of trusting the marker.
func sweepableResidue(e residueEntry) bool {
	return !isWindowsSystemRoot(e.path)
}

// readResidueMarker parses "<kind>\t<path>" lines. A tab splits the fields so a
// path containing spaces is preserved intact. An unrecognized line is skipped
// rather than guessed at, so a corrupt marker cannot cause a wrong ACE removal.
func readResidueMarker(path string) []residueEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []residueEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if line == "" {
			continue
		}
		kindStr, p, ok := strings.Cut(line, "\t")
		if !ok || p == "" {
			continue
		}
		switch residueKind(kindStr) {
		case residueDeny:
			out = append(out, residueEntry{kind: residueDeny, path: p})
		case residueGrant:
			out = append(out, residueEntry{kind: residueGrant, path: p})
		}
	}
	return out
}

// windowsProcessAlive reports whether the given PID is still running. A parse
// failure or a process that cannot be opened is treated as not-alive so stale
// markers get cleaned; PID reuse can only delay cleanup, never corrupt a live
// run or lose residue: a live run's own marker is protected by ownership
// (residueMarkerOwned), and a stale marker whose PID is reused by an unrelated
// process merely waits until that process exits — unless the reuser is a
// sandbox helper itself, which consumes the stale file at run start.
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
