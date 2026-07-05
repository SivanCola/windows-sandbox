package winsandbox

import (
	"errors"
	"os"
)

// ErrUnsupported is returned when the package is used on a non-Windows host or
// when required native Windows sandbox APIs are unavailable.
var ErrUnsupported = errors.New("windows sandbox is unavailable")

// Spec describes one native Windows sandbox launch.
//
// Read-only launches use AppContainer. Writable launches use a low-integrity
// token plus temporary ACL grants for WritableRoots and the per-command temp
// root. ForbidReadRoots are denied with temporary deny ACEs. Network=false is
// supported for read-only AppContainer launches; writable launches fail closed
// because low-integrity tokens do not provide reliable per-process network
// blocking without elevated firewall or WFP setup.
type Spec struct {
	WritableRoots   []string
	ForbidReadRoots []string
	Network         bool
	Writable        bool
	TempPrefix      string
}

// RunOptions carries process IO and environment overrides.
type RunOptions struct {
	Stdin  *os.File
	Stdout *os.File
	Stderr *os.File
	Env    []string
	Dir    string
}

// Result is the completed sandboxed process result.
type Result struct {
	ExitCode int
}
