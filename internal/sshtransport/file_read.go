package sshtransport

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/pkg/sftp"
)

const (
	// DefaultFileReadBytes is the default response budget for one constrained
	// remote file inspection. It is separate from command-output defaults.
	DefaultFileReadBytes = 16 * 1024

	// MaxFileReadBytes is the hard byte ceiling for one constrained remote file
	// inspection. Callers must choose a positive value no larger than this.
	MaxFileReadBytes = 64 * 1024
)

var (
	ErrInvalidFileRead        = errors.New("invalid SSH file read")
	ErrFileSymlink            = errors.New("SSH file read rejects symbolic links")
	ErrFileNotRegular         = errors.New("SSH file read requires a regular file")
	ErrFileOffsetOutOfRange   = errors.New("SSH file read offset is outside the file")
	ErrFileChanged            = errors.New("SSH file changed during inspection")
	ErrFileNotFound           = errors.New("SSH file was not found")
	ErrFilePermissionDenied   = errors.New("SSH file read permission denied")
	ErrFileReadFailed         = errors.New("SSH file read failed")
	ErrFileReadOutcomeUnknown = errors.New("SSH file read outcome is unknown")
)

type FileEncoding string

const (
	FileEncodingUTF8   FileEncoding = "utf-8"
	FileEncodingBase64 FileEncoding = "base64"
)

// FileReadResult is bounded, untrusted remote content. Content is UTF-8 text
// when valid UTF-8; otherwise it is standard base64-encoded bytes.
type FileReadResult struct {
	Content   string       `json:"content"`
	Encoding  FileEncoding `json:"encoding"`
	BytesRead int          `json:"bytes_read"`
	FileSize  int64        `json:"file_size"`
	EOF       bool         `json:"eof"`
	Truncated bool         `json:"truncated"`
}

// readOnlySFTP intentionally exposes only the protocol methods needed for a
// constrained file read. The production adapter never exposes write methods.
type readOnlySFTP interface {
	Lstat(string) (os.FileInfo, error)
	Open(string) (readOnlySFTPFile, error)
	Close() error
}

type readOnlySFTPFile interface {
	ReadAt([]byte, int64) (int, error)
	Stat() (os.FileInfo, error)
	Close() error
}

type nativeReadOnlySFTP struct {
	client *sftp.Client
}

func (c *nativeReadOnlySFTP) Lstat(remotePath string) (os.FileInfo, error) {
	return c.client.Lstat(remotePath)
}

func (c *nativeReadOnlySFTP) Open(remotePath string) (readOnlySFTPFile, error) {
	return c.client.Open(remotePath)
}

func (c *nativeReadOnlySFTP) Close() error {
	return c.client.Close()
}

func (c *Client) newReadOnlySFTP() (readOnlySFTP, error) {
	if c.fileFactory != nil {
		return c.fileFactory()
	}
	if c == nil || c.client == nil {
		return nil, ErrInvalidEndpoint
	}
	client, err := sftp.NewClient(
		c.client,
		sftp.UseConcurrentReads(false),
		sftp.MaxConcurrentRequestsPerFile(1),
	)
	if err != nil {
		return nil, err
	}
	return &nativeReadOnlySFTP{client: client}, nil
}

// ReadFile reads at most maxBytes from one canonical absolute remote path
// through SFTP. It never invokes a remote shell command. The caller remains
// responsible for target capability authorization.
func (c *Client) ReadFile(ctx context.Context, remotePath string, offset int64, maxBytes int) (FileReadResult, error) {
	if err := ctx.Err(); err != nil {
		return FileReadResult{}, notDispatchedFileRead(err)
	}
	if err := validateFileReadRequest(remotePath, offset, maxBytes); err != nil {
		return FileReadResult{}, err
	}
	if c == nil || (c.client == nil && c.fileFactory == nil) {
		return FileReadResult{}, ErrInvalidEndpoint
	}
	if err := ctx.Err(); err != nil {
		return FileReadResult{}, notDispatchedFileRead(err)
	}

	// Starting the SFTP subsystem can reach the remote server. Once this point
	// is crossed, cancellation and transport failure cannot be reported as
	// zero-dispatch outcomes.
	fileSystem, err := c.newReadOnlySFTP()
	if err != nil {
		return FileReadResult{}, fileReadOutcomeUnknown(ctx, err)
	}
	var closeOnce sync.Once
	closeFileSystem := func() {
		closeOnce.Do(func() { _ = fileSystem.Close() })
	}
	defer closeFileSystem()

	initialInfo, err := callFileRead(ctx, closeFileSystem, func() (os.FileInfo, error) {
		return fileSystem.Lstat(remotePath)
	})
	if err != nil {
		return FileReadResult{}, classifyFileReadError(ctx, err)
	}
	if err := validateRegularRemoteFile(initialInfo); err != nil {
		return FileReadResult{}, err
	}
	if offset > initialInfo.Size() {
		return FileReadResult{}, ErrFileOffsetOutOfRange
	}
	if offset == initialInfo.Size() {
		return FileReadResult{Encoding: FileEncodingUTF8, FileSize: initialInfo.Size(), EOF: true}, nil
	}

	file, err := callFileRead(ctx, closeFileSystem, func() (readOnlySFTPFile, error) {
		return fileSystem.Open(remotePath)
	})
	if err != nil {
		return FileReadResult{}, classifyFileReadError(ctx, err)
	}
	defer file.Close()

	openedInfo, err := callFileRead(ctx, closeFileSystem, file.Stat)
	if err != nil {
		return FileReadResult{}, classifyFileReadError(ctx, err)
	}
	if err := validateRegularRemoteFile(openedInfo); err != nil {
		return FileReadResult{}, err
	}
	currentInfo, err := callFileRead(ctx, closeFileSystem, func() (os.FileInfo, error) {
		return fileSystem.Lstat(remotePath)
	})
	if err != nil {
		return FileReadResult{}, classifyFileReadError(ctx, err)
	}
	if err := validateRegularRemoteFile(currentInfo); err != nil {
		return FileReadResult{}, err
	}
	if !sameFileReadSnapshot(initialInfo, openedInfo) || !sameFileReadSnapshot(initialInfo, currentInfo) {
		return FileReadResult{}, ErrFileChanged
	}

	readLength := maxBytes
	if remaining := initialInfo.Size() - offset; remaining < int64(readLength) {
		readLength = int(remaining)
	}
	contents := make([]byte, readLength)
	read, readErr := callFileRead(ctx, closeFileSystem, func() (int, error) {
		return file.ReadAt(contents, offset)
	})
	if read < 0 || read > len(contents) {
		return FileReadResult{}, ErrFileReadOutcomeUnknown
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return FileReadResult{}, classifyFileDataError(ctx, readErr)
	}
	if err := ctx.Err(); err != nil {
		return FileReadResult{}, fileReadOutcomeUnknown(ctx, err)
	}
	if read == 0 && readLength > 0 {
		return FileReadResult{}, ErrFileReadOutcomeUnknown
	}
	return fileReadResult(contents[:read], initialInfo.Size(), offset, readErr), nil
}

func validateFileReadRequest(remotePath string, offset int64, maxBytes int) error {
	if !isCanonicalAbsoluteRemotePath(remotePath) || offset < 0 || maxBytes <= 0 || maxBytes > MaxFileReadBytes {
		return ErrInvalidFileRead
	}
	return nil
}

func isCanonicalAbsoluteRemotePath(remotePath string) bool {
	if len(remotePath) == 0 || remotePath[0] != '/' || strings.ContainsRune(remotePath, '\x00') {
		return false
	}
	if remotePath != "/" && strings.HasSuffix(remotePath, "/") {
		return false
	}
	for index, component := range strings.Split(remotePath, "/") {
		if component == "." || component == ".." || (index > 0 && component == "") {
			return false
		}
	}
	return true
}

func validateRegularRemoteFile(info os.FileInfo) error {
	if info == nil {
		return ErrFileReadOutcomeUnknown
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return ErrFileSymlink
	}
	if !mode.IsRegular() || info.Size() < 0 {
		return ErrFileNotRegular
	}
	return nil
}

func sameFileReadSnapshot(before, after os.FileInfo) bool {
	return before.Size() == after.Size() && before.Mode().Type() == after.Mode().Type()
}

func fileReadResult(contents []byte, fileSize, offset int64, readErr error) FileReadResult {
	result := FileReadResult{
		BytesRead: len(contents),
		FileSize:  fileSize,
		EOF:       errors.Is(readErr, io.EOF) || offset+int64(len(contents)) >= fileSize,
		Truncated: !errors.Is(readErr, io.EOF) && offset+int64(len(contents)) < fileSize,
	}
	if utf8.Valid(contents) {
		result.Content = string(contents)
		result.Encoding = FileEncodingUTF8
		return result
	}
	result.Content = base64.StdEncoding.EncodeToString(contents)
	result.Encoding = FileEncodingBase64
	return result
}

func notDispatchedFileRead(err error) error {
	return fmt.Errorf("%w: %w", ErrNotDispatched, err)
}

func fileReadOutcomeUnknown(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return fmt.Errorf("%w: %w", ErrFileReadOutcomeUnknown, contextErr)
	}
	if err == nil {
		return ErrFileReadOutcomeUnknown
	}
	return ErrFileReadOutcomeUnknown
}

func classifyFileReadError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return fileReadOutcomeUnknown(ctx, contextErr)
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		return ErrFileNotFound
	case errors.Is(err, os.ErrPermission):
		return ErrFilePermissionDenied
	default:
		return ErrFileReadOutcomeUnknown
	}
}

func classifyFileDataError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return fileReadOutcomeUnknown(ctx, contextErr)
	}
	if errors.Is(err, os.ErrPermission) {
		return ErrFilePermissionDenied
	}
	return ErrFileReadFailed
}

type fileReadCallResult[T any] struct {
	value T
	err   error
}

// callFileRead aborts only this SFTP subsystem when the request context ends.
// Its result channel is buffered because a remote response may race cancellation.
func callFileRead[T any](ctx context.Context, closeFileSystem func(), operation func() (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	result := make(chan fileReadCallResult[T], 1)
	go func() {
		value, err := operation()
		result <- fileReadCallResult[T]{value: value, err: err}
	}()
	select {
	case <-ctx.Done():
		closeFileSystem()
		return zero, ctx.Err()
	case call := <-result:
		if err := ctx.Err(); err != nil {
			closeFileSystem()
			return zero, err
		}
		return call.value, call.err
	}
}
