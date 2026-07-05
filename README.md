# windows-sandbox

Native Windows process sandbox helpers for Go.

This module provides a small Windows-only sandbox runner built from platform
primitives:

- AppContainer for read-only launches.
- Low-integrity primary tokens for writable launches.
- Temporary ACL grants for writable roots, command temp roots, and executable
  roots.
- Temporary deny ACEs for forbid-read roots.
- Per-command temp directory redirection.
- Kill-on-close Job Objects for process-tree cleanup.

The package intentionally exposes a narrow API. It does not implement product
policy, prompting, or shell parsing; callers pass an already-resolved argv and a
small filesystem/network policy.

## Usage

```go
result, err := winsandbox.Run(winsandbox.Spec{
    WritableRoots:   []string{workspace},
    ForbidReadRoots: []string{secretDir},
    Network:         true,
    Writable:        true,
    TempPrefix:      "myapp-sandbox-",
}, []string{"powershell", "-NoProfile", "-NonInteractive", "-Command", script}, winsandbox.RunOptions{
    Stdin:  os.Stdin,
    Stdout: os.Stdout,
    Stderr: os.Stderr,
})
```

## Network Semantics

Read-only launches use AppContainer. When `Network` is false, network
capabilities are omitted.

Writable launches use a low-integrity token so normal developer workspaces can
be written without requiring an elevated helper. Low-integrity tokens do not
provide reliable per-process network blocking without elevated firewall or WFP
setup, so writable launches with `Network: false` fail closed.

## Platform Support

`Available` and `Run` return unavailable on non-Windows hosts. The module still
builds on non-Windows platforms so callers can depend on it unconditionally.

## Verification Matrix

The Windows CI tests exercise both sandbox launch modes:

- writable low-integrity commands can write inside configured roots and command
  temp, but not outside configured roots;
- read-only AppContainer commands can read allowed roots but cannot write them;
- `ForbidReadRoots` are denied in both writable and read-only launches;
- `Network: false` AppContainer launches cannot connect to a loopback listener;
- stdin, stdout, stderr, environment overrides, working directory, paths with
  spaces, and child exit codes are preserved;
- kill-on-close Job Objects clean up child process trees;
- temporary ACL grants/denies are removed after the command exits.
