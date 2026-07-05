//go:build windows

package winsandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestMain(m *testing.M) {
	waitMS := uint32((15 * time.Second).Milliseconds())
	windowsSandboxWaitMilliseconds = waitMS
	os.Setenv("WINDOWS_SANDBOX_WAIT_MS", strconv.FormatUint(uint64(waitMS), 10))
	os.Exit(m.Run())
}

func TestWindowsAppContainerNameSeparatesForbidReadPolicies(t *testing.T) {
	base := Spec{WritableRoots: []string{`C:\work`}, Network: true}
	baseName := windowsAppContainerName(base)
	forbidName := windowsAppContainerName(Spec{WritableRoots: []string{`C:\work`}, ForbidReadRoots: []string{`C:\work\secret`}, Network: true})
	if baseName == forbidName {
		t.Fatal("different forbid_read roots must not share an AppContainer profile")
	}
	for _, name := range []string{baseName, forbidName} {
		if !strings.HasPrefix(name, "WinSandbox.") || len(name) > 64 {
			t.Fatalf("unexpected AppContainer profile name: %q", name)
		}
	}
}

func TestWindowsAppContainerNetworkCapabilities(t *testing.T) {
	withNetwork, err := prepareAppContainer(Spec{WritableRoots: []string{`C:\work`}, Network: true})
	if err != nil {
		t.Fatalf("prepare AppContainer with network: %v", err)
	}
	defer withNetwork.close()
	if len(withNetwork.capabilities) == 0 {
		t.Fatal("network-enabled AppContainer should include network capabilities")
	}

	withoutNetwork, err := prepareAppContainer(Spec{WritableRoots: []string{`C:\work`}, Network: false})
	if err != nil {
		t.Fatalf("prepare AppContainer without network: %v", err)
	}
	defer withoutNetwork.close()
	if len(withoutNetwork.capabilities) != 0 {
		t.Fatalf("network-disabled AppContainer capabilities = %d, want 0", len(withoutNetwork.capabilities))
	}
}

func TestWindowsCleanupPathSecurityRemovesACEsBeforeRestore(t *testing.T) {
	var calls []string
	cleanup := cleanupPathSecurity(
		func() { calls = append(calls, "restore") },
		func() { calls = append(calls, "remove") },
		func() { calls = append(calls, "after") },
	)
	cleanup()
	if got := strings.Join(calls, ","); got != "remove,restore,after" {
		t.Fatalf("cleanup order = %s, want remove,restore,after", got)
	}
}

func TestWindowsUniqueNonZeroHandles(t *testing.T) {
	got := uniqueNonZeroHandles([]windows.Handle{0, 10, 10, 0, 11, 10})
	want := []windows.Handle{10, 11}
	if len(got) != len(want) {
		t.Fatalf("handles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("handles = %v, want %v", got, want)
		}
	}
}

func TestWindowsSandboxAvailableOnCI(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("only require AppContainer sandbox availability on CI")
	}
	if !Available() {
		t.Fatal("windows sandbox APIs unavailable on CI")
	}
}

func TestWindowsExecutableGrantDirResolvesPathTools(t *testing.T) {
	dir := t.TempDir()
	toolPath := filepath.Join(dir, "windows-sandbox-path-tool.exe")
	if err := os.WriteFile(toolPath, []byte("not really an exe"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if got := windowsExecutableGrantDir("windows-sandbox-path-tool.exe"); !sameWindowsPath(got, dir) {
		t.Fatalf("grant dir = %q, want %q", got, dir)
	}
}

func TestWindowsExecutableGrantRootsIncludeGitInstallRoot(t *testing.T) {
	installRoot := filepath.Join(t.TempDir(), "Git")
	bin := filepath.Join(installRoot, "usr", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	bashPath := filepath.Join(bin, "bash.exe")
	if err := os.WriteFile(bashPath, []byte("not really an exe"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := windowsExecutableGrantRoots(bashPath)
	if len(got) != 2 {
		t.Fatalf("grant roots = %v, want executable dir and Git install root", got)
	}
	if !sameWindowsPath(got[0], bin) || !sameWindowsPath(got[1], installRoot) {
		t.Fatalf("grant roots = %v, want [%s %s]", got, bin, installRoot)
	}
}

func TestWindowsWritableRootsIncludeCommandTempWithoutGlobalTemp(t *testing.T) {
	workspace := t.TempDir()
	commandTemp := t.TempDir()
	got := windowsWritableRoots(Spec{WritableRoots: []string{workspace}}, commandTemp)
	if len(got) != 2 {
		t.Fatalf("writable roots = %v, want workspace and command temp only", got)
	}
	if !sameWindowsPath(got[0], workspace) || !sameWindowsPath(got[1], commandTemp) {
		t.Fatalf("writable roots = %v, want [%s %s]", got, workspace, commandTemp)
	}
	if globalTemp := os.TempDir(); sameWindowsPath(globalTemp, workspace) || sameWindowsPath(globalTemp, commandTemp) {
		t.Skip("test temp dirs are the global temp root")
	}
	for _, root := range got {
		if sameWindowsPath(root, os.TempDir()) {
			t.Fatalf("global temp root should not be auto-granted: %v", got)
		}
	}
}

func TestWindowsSandboxEnvRedirectsTemp(t *testing.T) {
	env := setWindowsEnv([]string{"Path=C:\\Tools", "temp=C:\\old-temp", "TMP=C:\\old-tmp"}, map[string]string{
		"TEMP":   `C:\sandbox-temp`,
		"TMP":    `C:\sandbox-temp`,
		"TMPDIR": `C:\sandbox-temp`,
	})
	joined := "\n" + strings.Join(env, "\n") + "\n"
	for _, want := range []string{"\ntemp=C:\\sandbox-temp\n", "\nTMP=C:\\sandbox-temp\n", "\nTMPDIR=C:\\sandbox-temp\n"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("env %q missing %q", joined, want)
		}
	}
}

func TestWindowsSandboxAllowsWorkspaceWriteAndDeniesOutside(t *testing.T) {
	if !Available() {
		t.Skip("windows sandbox APIs unavailable")
	}
	sh := powershellArgvForTest(t, "")
	if sh == nil {
		t.Skip("PowerShell unavailable")
	}
	workspace := t.TempDir()
	outside := t.TempDir()
	insideFile := filepath.Join(workspace, "inside.txt")
	existingFile := filepath.Join(workspace, "existing.txt")
	nestedDir := filepath.Join(workspace, "nested")
	if err := os.Mkdir(nestedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	nestedExistingFile := filepath.Join(nestedDir, "existing.txt")
	if err := os.WriteFile(existingFile, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nestedExistingFile, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "outside.txt")
	t.Chdir(workspace)

	script := "$ErrorActionPreference='Stop'; " +
		psSandboxDiagnostics(workspace) +
		psTrySetContent(insideFile, "ok") +
		psTrySetContent(existingFile, "updated") +
		psTrySetContent(nestedExistingFile, "nested") +
		"if ((Split-Path -Leaf $env:TEMP) -notlike 'windows-sandbox-test-*') { exit 8 }; " +
		"try { Set-Content -LiteralPath (Join-Path $env:TEMP 'sandbox-temp.txt') -Value temp } catch { Write-Host $_; __winsandbox_dump_diag; exit 1 }; " +
		"try { Set-Content -LiteralPath " + psQuote(outsideFile) + " -Value nope; exit 9 } catch { exit 0 }"
	result, err := Run(Spec{WritableRoots: []string{workspace}, Network: true, Writable: true, TempPrefix: "windows-sandbox-test-"}, append(sh, script), RunOptions{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
	if err != nil {
		t.Fatalf("sandbox run failed: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("sandbox exit code = %d, want 0", result.ExitCode)
	}
	if got, err := os.ReadFile(insideFile); err != nil || !strings.Contains(string(got), "ok") {
		t.Fatalf("inside write missing: %q err=%v", got, err)
	}
	if got, err := os.ReadFile(existingFile); err != nil || !strings.Contains(string(got), "updated") {
		t.Fatalf("existing file write missing: %q err=%v", got, err)
	}
	if got, err := os.ReadFile(nestedExistingFile); err != nil || !strings.Contains(string(got), "nested") {
		t.Fatalf("nested existing file write missing: %q err=%v", got, err)
	}
	if _, err := os.Stat(outsideFile); err == nil {
		t.Fatalf("outside write unexpectedly succeeded: %s", outsideFile)
	}
}

func TestWindowsSandboxDeniesForbidRead(t *testing.T) {
	if !Available() {
		t.Skip("windows sandbox APIs unavailable")
	}
	sh := powershellArgvForTest(t, "")
	if sh == nil {
		t.Skip("PowerShell unavailable")
	}
	workspace := t.TempDir()
	secretDir := filepath.Join(workspace, "secret")
	if err := os.Mkdir(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(secretDir, "token.txt")
	if err := os.WriteFile(secretFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(workspace)

	script := "$ErrorActionPreference='Stop'; " +
		"try { Get-Content -LiteralPath " + psQuote(secretFile) + "; exit 9 } catch { exit 0 }"
	result, err := Run(Spec{WritableRoots: []string{workspace}, ForbidReadRoots: []string{secretDir}, Network: true, Writable: true, TempPrefix: "windows-sandbox-test-"}, append(sh, script), RunOptions{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
	if err != nil {
		t.Fatalf("sandbox run failed: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("forbid_read was not enforced, exit code = %d", result.ExitCode)
	}
}

func TestWindowsSandboxCleansTouchedSecurityDescriptors(t *testing.T) {
	if !Available() {
		t.Skip("windows sandbox APIs unavailable")
	}
	sh := powershellArgvForTest(t, "")
	if sh == nil {
		t.Skip("PowerShell unavailable")
	}
	workspace := t.TempDir()
	secretDir := filepath.Join(workspace, "secret")
	if err := os.Mkdir(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(secretDir, "token.txt")
	if err := os.WriteFile(secretFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(workspace)

	script := "$ErrorActionPreference='Stop'; " +
		psSandboxDiagnostics(workspace) +
		psTrySetContent(filepath.Join(workspace, "inside.txt"), "ok") +
		"try { Get-Content -LiteralPath " + psQuote(secretFile) + "; exit 9 } catch { exit 0 }"
	result, err := Run(Spec{WritableRoots: []string{workspace}, ForbidReadRoots: []string{secretDir}, Network: true, Writable: true, TempPrefix: "windows-sandbox-test-"}, append(sh, script), RunOptions{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
	if err != nil {
		t.Fatalf("sandbox run failed: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("sandbox exit code = %d, want 0", result.ExitCode)
	}
	assertNoWindowsSandboxACEForTest(t, workspace)
	assertNoWindowsSandboxACEForTest(t, secretDir)
}

func TestWindowsSandboxRejectsWritableNetworkDisabled(t *testing.T) {
	if !Available() {
		t.Skip("windows sandbox APIs unavailable")
	}
	sh := powershellArgvForTest(t, "")
	if sh == nil {
		t.Skip("PowerShell unavailable")
	}
	workspace := t.TempDir()
	t.Chdir(workspace)
	script := "$ErrorActionPreference='Stop'; Set-Content -LiteralPath " + psQuote(filepath.Join(workspace, "inside.txt")) + " -Value ok"
	result, err := Run(Spec{WritableRoots: []string{workspace}, Network: false, Writable: true, TempPrefix: "windows-sandbox-test-"}, append(sh, script), RunOptions{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
	if err == nil {
		t.Fatalf("network=false writable sandbox should fail closed, code=%d", result.ExitCode)
	}
	if !strings.Contains(err.Error(), "network=false") {
		t.Fatalf("error = %v, want network=false unsupported", err)
	}
}

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func powershellArgvForTest(t *testing.T, command string) []string {
	t.Helper()
	for _, name := range []string{"pwsh", "powershell"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		args := []string{path, "-NoProfile", "-NonInteractive", "-Command"}
		if command != "" {
			args = append(args, command)
		}
		return args
	}
	return nil
}

func psTrySetContent(path, value string) string {
	return "try { Set-Content -LiteralPath " + psQuote(path) + " -Value " + psQuote(value) + " } catch { Write-Host $_; __winsandbox_dump_diag; exit 1 }; "
}

func psSandboxDiagnostics(root string) string {
	return "$__winsandboxDiagRoot = " + psQuote(root) + "; " +
		"function __winsandbox_dump_diag { " +
		"Write-Host '--- windows sandbox diagnostics ---'; " +
		"try { Write-Host ('USER=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name) } catch {}; " +
		"try { Write-Host ('SID=' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) } catch {}; " +
		"Write-Host ('TEMP=' + $env:TEMP); " +
		"try { whoami /all } catch {}; " +
		"try { icacls $__winsandboxDiagRoot } catch {}; " +
		"try { icacls (Split-Path -Parent $__winsandboxDiagRoot) } catch {}; " +
		"try { icacls $env:TEMP } catch {}; " +
		"} "
}

func pathDACLSDDLForTest(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	if sd == nil {
		return ""
	}
	return sd.String()
}

func assertNoWindowsSandboxACEForTest(t *testing.T, path string) {
	t.Helper()
	sddl := pathDACLSDDLForTest(t, path)
	for _, forbidden := range []string{
		allApplicationPackagesSID,
		allRestrictedApplicationPackagesSID,
	} {
		if strings.Contains(sddl, forbidden) {
			t.Fatalf("%s still contains sandbox SID %s: %s", path, forbidden, sddl)
		}
	}
	userSID, err := currentProcessUserSIDString()
	if err != nil {
		t.Fatalf("current user SID: %v", err)
	}
	if strings.Contains(sddl, "(D") && strings.Contains(sddl, userSID) {
		t.Fatalf("%s still contains current-user deny ACE: %s", path, sddl)
	}
}

func sameWindowsPath(a, b string) bool {
	if real, err := filepath.EvalSymlinks(a); err == nil {
		a = real
	}
	if real, err := filepath.EvalSymlinks(b); err == nil {
		b = real
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
