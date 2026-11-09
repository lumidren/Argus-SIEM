//go:build !windows

package tail

import "os"

// openShared opens a file for reading; POSIX already allows rename and
// unlink of open files.
func openShared(path string) (*os.File, error) { return os.Open(path) }
