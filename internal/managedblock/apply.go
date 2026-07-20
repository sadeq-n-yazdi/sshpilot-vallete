package managedblock

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// File and directory modes. authorized_keys is owner-only; sshd refuses a
// group- or world-writable key file, and ~/.ssh is owner-only for the same
// reason.
const (
	fileMode fs.FileMode = 0o600
	dirMode  fs.FileMode = 0o700
)

// Errors returned by Apply. Each leaves the target file untouched.
var (
	// ErrNotRegularFile indicates the target path exists but is not a regular
	// file (a directory, a symlink, a device). Replacing it could redirect the
	// write or destroy something unrelated, so the operation refuses.
	ErrNotRegularFile = errors.New("managedblock: target is not a regular file; refusing to replace it")
	// ErrTooLarge indicates the existing file exceeds MaxFileBytes.
	ErrTooLarge = errors.New("managedblock: existing file exceeds the maximum permitted size")
	// ErrBadPath indicates the target path has no usable file name component.
	ErrBadPath = errors.New("managedblock: target path must name a file")
)

// hooks holds the filesystem primitives the write path uses. They are indirect
// so tests can inject the syscall failures (fsync refusing, rename refusing, a
// short write) that cannot be provoked through a real filesystem, and so the
// crash-safety test can fail at an exact point in the sequence. Production code
// never reassigns them.
type hooks struct {
	chmodPath func(string, fs.FileMode) error
	chmodFile func(*os.File, fs.FileMode) error
	write     func(*os.File, []byte) (int, error)
	sync      func(*os.File) error
	closeFile func(*os.File) error
	readAll   func(io.Reader) ([]byte, error)
	rename    func(*os.Root, string, string) error
	syncDir   func(string) error
	randRead  func([]byte) (int, error)
}

var fsx = hooks{
	chmodPath: os.Chmod,
	chmodFile: (*os.File).Chmod,
	write:     (*os.File).Write,
	sync:      (*os.File).Sync,
	closeFile: (*os.File).Close,
	readAll:   io.ReadAll,
	rename:    (*os.Root).Rename,
	syncDir:   defaultSyncDir,
	randRead:  rand.Read,
}

// Options controls a single Apply.
type Options struct {
	// Path is the authorized_keys file to maintain.
	Path string
	// DryRun reports what would change and writes nothing.
	DryRun bool
}

// Report describes the outcome of an Apply.
type Report struct {
	// Path is the target file.
	Path string
	// Existed reports whether the target file was present beforehand.
	Existed bool
	// Changed reports whether the contents differ from what was on disk. In a
	// dry run it reports whether a write would have happened.
	Changed bool
	// Mode is the permission bits the file has, or would have, afterwards.
	Mode fs.FileMode
	// Size is the length in bytes of the resulting file contents.
	Size int
}

// Apply renders pubkeys into a managed block and installs it in opts.Path.
//
// The sequence is fail-closed: the key set is validated and canonicalized
// before anything is opened, the marker state is resolved before anything is
// written, and the write itself is a temp file in the target's own directory,
// fsynced, then renamed over the target. A crash leaves either the old file or
// the new one, never a truncated one.
//
// Permissions never widen. A new file is created 0600; an existing file keeps
// any bits narrower than that (0400 stays 0400) and is narrowed to 0600 if it
// was wider. The temp file is created at its final mode and then fchmod'd to
// it, so the result does not depend on the caller's umask and there is no
// window in which the file is readable by anyone else.
//
// Directory access goes through os.Root, so a path component that resolves
// outside the target directory fails instead of being followed, and the rename
// is a renameat within that directory.
func Apply(pubkeys []string, opts Options) (Report, error) {
	block, err := Render(pubkeys)
	if err != nil {
		return Report{}, err
	}

	path := filepath.Clean(opts.Path)
	dir, base := filepath.Split(path)
	if base == "" || base == "." || base == ".." {
		return Report{}, ErrBadPath
	}
	if dir == "" {
		dir = "."
	}
	rep := Report{Path: path}

	if opts.DryRun {
		// A dry run must work before ~/.ssh exists, and must not create it.
		if _, statErr := os.Stat(dir); errors.Is(statErr, fs.ErrNotExist) {
			rep.Mode, rep.Size, rep.Changed = fileMode, len(block), true
			return rep, nil
		}
	} else if err := ensureDir(dir); err != nil {
		return rep, err
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return rep, fmt.Errorf("managedblock: open directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	existing, mode, existed, err := readExisting(root, base)
	if err != nil {
		return rep, err
	}
	rep.Existed = existed
	rep.Mode = finalMode(mode, existed)

	merged, err := Merge(existing, block)
	if err != nil {
		return rep, err
	}
	rep.Size = len(merged)
	rep.Changed = !existed || !bytes.Equal(existing, merged)

	if opts.DryRun || !rep.Changed {
		return rep, nil
	}
	if err := writeAtomic(root, base, merged, rep.Mode, dir); err != nil {
		return rep, err
	}
	return rep, nil
}

// ensureDir creates the target directory owner-only when it is missing. The
// explicit chmod defeats the process umask, which would otherwise leave the
// directory group- or world-readable and make sshd reject the key file.
func ensureDir(dir string) error {
	switch _, err := os.Stat(dir); {
	case err == nil:
		return nil
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("managedblock: stat directory: %w", err)
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("managedblock: create directory: %w", err)
	}
	if err := fsx.chmodPath(dir, dirMode); err != nil {
		return fmt.Errorf("managedblock: set directory mode: %w", err)
	}
	return nil
}

// readExisting reads the current file through the directory root. A missing
// file is not an error; anything that is not a regular file is, because
// replacing it would be either a redirected write or a destructive surprise.
func readExisting(root *os.Root, base string) (content []byte, mode fs.FileMode, existed bool, err error) {
	info, err := root.Lstat(base)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, 0, false, nil
	case err != nil:
		return nil, 0, false, fmt.Errorf("managedblock: stat target: %w", err)
	case !info.Mode().IsRegular():
		return nil, 0, false, ErrNotRegularFile
	}

	f, err := root.OpenFile(base, os.O_RDONLY, 0)
	if err != nil {
		return nil, 0, false, fmt.Errorf("managedblock: open target: %w", err)
	}
	defer func() { _ = f.Close() }()

	content, err = fsx.readAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, 0, false, fmt.Errorf("managedblock: read target: %w", err)
	}
	if len(content) > MaxFileBytes {
		return nil, 0, false, ErrTooLarge
	}
	return content, info.Mode().Perm(), true, nil
}

// finalMode picks the permission bits of the result: 0600 for a new file, and
// for an existing one the intersection with 0600, which narrows a too-wide
// file without ever widening one the user deliberately locked down.
func finalMode(mode fs.FileMode, existed bool) fs.FileMode {
	if !existed {
		return fileMode
	}
	return mode & fileMode
}

// writeAtomic installs content at base via a temp file in the same directory.
//
// The temp file is created O_EXCL at the final mode (so it is never briefly
// world-readable, and creation cannot follow a symlink), written, fsynced, and
// renamed over the target; the directory is then fsynced so the rename itself
// is durable. Every failure before the rename removes the temp file and leaves
// the target exactly as it was.
func writeAtomic(root *os.Root, base string, content []byte, mode fs.FileMode, dir string) error {
	tmp, err := tempName(base)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("managedblock: create temp file: %w", err)
	}
	abandon := func(cause error) error {
		_ = f.Close()
		_ = root.Remove(tmp)
		return cause
	}

	// Chmod after create: the O_CREATE mode is masked by the umask, so this is
	// what actually guarantees the final bits.
	if err := fsx.chmodFile(f, mode); err != nil {
		return abandon(fmt.Errorf("managedblock: set temp file mode: %w", err))
	}
	if _, err := fsx.write(f, content); err != nil {
		return abandon(fmt.Errorf("managedblock: write temp file: %w", err))
	}
	if err := fsx.sync(f); err != nil {
		return abandon(fmt.Errorf("managedblock: sync temp file: %w", err))
	}
	if err := fsx.closeFile(f); err != nil {
		return abandon(fmt.Errorf("managedblock: close temp file: %w", err))
	}
	if err := fsx.rename(root, tmp, base); err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("managedblock: rename temp file: %w", err)
	}
	if err := fsx.syncDir(dir); err != nil {
		return fmt.Errorf("managedblock: sync directory: %w", err)
	}
	return nil
}

// tempName derives an unpredictable temp file name that sits beside the target
// in the same directory, which keeps the rename within one filesystem. The
// leading dot keeps the transient file out of ordinary listings.
func tempName(base string) (string, error) {
	var b [8]byte
	if _, err := fsx.randRead(b[:]); err != nil {
		return "", fmt.Errorf("managedblock: generate temp name: %w", err)
	}
	return "." + base + "." + hex.EncodeToString(b[:]) + ".tmp", nil
}

// defaultSyncDir fsyncs the directory so a completed rename survives a crash.
// Opening the directory by name here is a small, deliberate TOCTOU window: it
// affects durability only, never which file was written, because the rename
// already happened through the root handle.
func defaultSyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
