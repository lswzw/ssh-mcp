package sshtransport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/pkg/sftp"
)

const (
	// DefaultBinaryDeploymentBytes is the default source and wire budget for a
	// single deployment. It is intentionally independent from command and file
	// inspection budgets.
	DefaultBinaryDeploymentBytes int64 = 64 << 20

	// MaxBinaryDeploymentBytes is the hard upper bound for one source file. The
	// caller must still provide a finite per-request MaxBytes value.
	MaxBinaryDeploymentBytes int64 = 256 << 20
	deploymentChunkBytes           = 32 << 10
)

var (
	ErrInvalidBinaryDeployment    = errors.New("invalid SSH binary deployment")
	ErrDeploymentTargetNotFound   = errors.New("SSH deployment target file was not found")
	ErrDeploymentTargetSymlink    = errors.New("SSH deployment target rejects symbolic links")
	ErrDeploymentTargetNotRegular = errors.New("SSH deployment target requires a regular file")
	ErrDeploymentTargetChanged    = errors.New("SSH deployment target changed during deployment")
	ErrDeploymentSourceTooLarge   = errors.New("SSH deployment source exceeds its byte budget")
	ErrDeploymentIntegrity        = errors.New("SSH deployment source integrity check failed")
	ErrDeploymentBackupExists     = errors.New("SSH deployment backup path already exists")
	ErrDeploymentActivationFailed = errors.New("SSH deployment activation failed and was rolled back")
	ErrDeploymentFailed           = errors.New("SSH binary deployment failed")
	ErrDeploymentOutcomeUnknown   = errors.New("SSH binary deployment outcome is unknown")
)

// BinaryDeploymentRequest carries the validated remote destination and source
// metadata for one direct deployment. Temporary and backup paths are generated
// by the transport, and no arbitrary remote command is accepted here.
type BinaryDeploymentRequest struct {
	RemotePath     string `json:"remote_path"`
	ExpectedSize   int64  `json:"expected_size"`
	ExpectedSHA256 string `json:"expected_sha256"`
	MaxBytes       int64  `json:"max_bytes,omitempty"`
}

// BinaryDeploymentResult contains metadata only; it never contains source
// bytes or remote command output.
type BinaryDeploymentResult struct {
	RemotePath    string `json:"remote_path"`
	BackupPath    string `json:"backup_path"`
	BytesUploaded int64  `json:"bytes_uploaded"`
	SHA256        string `json:"sha256"`
	Activated     bool   `json:"activated"`
}

// deploymentProtocol is the deliberately tiny write boundary used by the
// high-level deployment transaction. In particular, it has no overwrite,
// recursive, permission-management, or arbitrary command operation.
type deploymentProtocol interface {
	Lstat(string) (os.FileInfo, error)
	OpenFile(string, int, os.FileMode) (io.WriteCloser, error)
	Open(string) (io.ReadCloser, error)
	Rename(string, string) error
	Remove(string) error
	Close() error
}

type nativeDeploymentProtocol struct {
	client *sftp.Client
}

func (p *nativeDeploymentProtocol) Lstat(remotePath string) (os.FileInfo, error) {
	return p.client.Lstat(remotePath)
}

func (p *nativeDeploymentProtocol) OpenFile(remotePath string, flags int, _ os.FileMode) (io.WriteCloser, error) {
	return p.client.OpenFile(remotePath, flags)
}

func (p *nativeDeploymentProtocol) Open(remotePath string) (io.ReadCloser, error) {
	return p.client.Open(remotePath)
}

func (p *nativeDeploymentProtocol) Rename(oldPath, newPath string) error {
	// Deliberately use ordinary SSH_FXP_RENAME. PosixRename is explicitly not
	// allowed because its contract permits replacing an existing destination.
	return p.client.Rename(oldPath, newPath)
}

func (p *nativeDeploymentProtocol) Remove(remotePath string) error {
	return p.client.Remove(remotePath)
}

func (p *nativeDeploymentProtocol) Close() error {
	return p.client.Close()
}

func (c *Client) newDeploymentProtocol() (deploymentProtocol, error) {
	if c != nil && c.deploymentFactory != nil {
		return c.deploymentFactory()
	}
	if c == nil || c.client == nil {
		return nil, ErrInvalidEndpoint
	}
	client, err := sftp.NewClient(
		c.client,
		sftp.UseConcurrentReads(false),
		sftp.UseConcurrentWrites(false),
		sftp.MaxConcurrentRequestsPerFile(1),
	)
	if err != nil {
		return nil, err
	}
	return &nativeDeploymentProtocol{client: client}, nil
}

// DeployBinary uploads one bounded source file to an exclusive remote temporary
// file, verifies it, moves the existing target to a sibling backup, and only
// then activates the temporary file. The live target is never opened for
// writing and PosixRename is never used.
func (c *Client) DeployBinary(ctx context.Context, source io.Reader, request BinaryDeploymentRequest) (BinaryDeploymentResult, error) {
	if err := ctx.Err(); err != nil {
		return BinaryDeploymentResult{}, fmtNotDispatchedDeployment(err)
	}
	expectedSHA, err := validateBinaryDeploymentRequest(source, &request)
	if err != nil {
		return BinaryDeploymentResult{}, err
	}
	if c == nil || (c.client == nil && c.deploymentFactory == nil) {
		return BinaryDeploymentResult{}, ErrInvalidEndpoint
	}
	if err := ctx.Err(); err != nil {
		return BinaryDeploymentResult{}, fmtNotDispatchedDeployment(err)
	}

	// Creating the protocol can start an SSH subsystem. From this point on a
	// cancellation or transport error is never represented as not dispatched.
	protocol, err := c.newDeploymentProtocol()
	if err != nil || protocol == nil {
		return BinaryDeploymentResult{}, ErrDeploymentOutcomeUnknown
	}
	var closeOnce sync.Once
	closeProtocol := func() { closeOnce.Do(func() { _ = protocol.Close() }) }
	defer closeProtocol()

	targetInfo, err := callDeployment(ctx, closeProtocol, func() (os.FileInfo, error) {
		return protocol.Lstat(request.RemotePath)
	})
	if err != nil {
		return BinaryDeploymentResult{}, classifyDeploymentPreparationError(ctx, err, true)
	}
	if err := validateDeploymentTargetInfo(targetInfo); err != nil {
		return BinaryDeploymentResult{}, err
	}

	tempPath, err := deploymentSiblingPath(request.RemotePath, "ssh-mcp-temp")
	if err != nil {
		return BinaryDeploymentResult{}, ErrDeploymentFailed
	}
	backupPath, err := deploymentSiblingPath(request.RemotePath, "ssh-mcp-backup")
	if err != nil {
		return BinaryDeploymentResult{}, ErrDeploymentFailed
	}
	tempCreated := false
	activated := false
	// preserveTemporary becomes true immediately before the first live-file
	// mutation is dispatched. From then on a lost response may leave either
	// rename in effect, so cleanup must not make manual recovery harder.
	preserveTemporary := false
	defer func() {
		if !preserveTemporary && !activated && tempCreated {
			// The name is daemon-generated and exclusive. Cleanup is best effort;
			// this is safe only before a live-file mutation has been dispatched.
			_ = protocol.Remove(tempPath)
		}
	}()

	writer, err := callDeployment(ctx, closeProtocol, func() (io.WriteCloser, error) {
		return protocol.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
	})
	if err != nil {
		return BinaryDeploymentResult{}, classifyDeploymentPreparationError(ctx, err, false)
	}
	tempCreated = true
	writerClosed := false
	defer func() {
		if !writerClosed {
			_ = writer.Close()
		}
	}()
	if err := uploadDeploymentSource(ctx, closeProtocol, writer, source, request.ExpectedSize, request.MaxBytes, expectedSHA); err != nil {
		if ctx.Err() != nil {
			return BinaryDeploymentResult{}, ErrDeploymentOutcomeUnknown
		}
		return BinaryDeploymentResult{}, err
	}
	closeErr := callDeploymentClose(ctx, closeProtocol, writer)
	writerClosed = closeErr == nil
	if closeErr != nil {
		return BinaryDeploymentResult{}, closeErr
	}
	if err := verifyDeploymentTemporary(ctx, closeProtocol, protocol, tempPath, request.ExpectedSize, expectedSHA); err != nil {
		return BinaryDeploymentResult{}, err
	}

	// Re-read the live target immediately before the first mutating operation.
	// This does not claim to defeat a malicious remote filesystem, but prevents
	// ordinary replacement races from silently moving a different file.
	currentInfo, err := callDeployment(ctx, closeProtocol, func() (os.FileInfo, error) {
		return protocol.Lstat(request.RemotePath)
	})
	if err != nil {
		return BinaryDeploymentResult{}, classifyDeploymentPreparationError(ctx, err, true)
	}
	if err := validateDeploymentTargetInfo(currentInfo); err != nil {
		return BinaryDeploymentResult{}, err
	}
	if !sameDeploymentSnapshot(targetInfo, currentInfo) {
		return BinaryDeploymentResult{}, ErrDeploymentTargetChanged
	}

	// An existing backup is a hard stop. Ordinary Rename is expected to reject
	// an existing destination as well, but checking first makes the invariant
	// visible and testable before any live-file mutation is attempted.
	backupInfo, backupErr := callDeployment(ctx, closeProtocol, func() (os.FileInfo, error) {
		return protocol.Lstat(backupPath)
	})
	if backupErr == nil {
		if backupInfo == nil {
			return BinaryDeploymentResult{}, ErrDeploymentOutcomeUnknown
		}
		return BinaryDeploymentResult{}, ErrDeploymentBackupExists
	}
	if backupErr != nil && !errors.Is(backupErr, os.ErrNotExist) {
		return BinaryDeploymentResult{}, classifyDeploymentPreparationError(ctx, backupErr, false)
	}

	partial := BinaryDeploymentResult{
		RemotePath:    request.RemotePath,
		BackupPath:    backupPath,
		BytesUploaded: request.ExpectedSize,
		SHA256:        expectedSHA,
	}
	// This is the mandatory backup gate. Never activate the temporary file
	// before this server-side rename has been dispatched successfully.
	preserveTemporary = true
	if err := callDeploymentError(ctx, closeProtocol, func() error {
		return protocol.Rename(request.RemotePath, backupPath)
	}); err != nil {
		if ctx.Err() == nil && errors.Is(err, os.ErrExist) {
			// A no-replace rename reporting EEXIST proves that the backup gate
			// did not mutate the live target. It is therefore safe to remove the
			// daemon-owned temporary file before returning the known failure.
			preserveTemporary = false
			return partial, ErrDeploymentBackupExists
		}
		return partial, classifyDeploymentMutationError(ctx, err)
	}

	// Confirm that the backup exists and still looks like the exact target that
	// was inspected before the move. Any uncertainty now is an unknown outcome.
	verifiedBackup, err := callDeployment(ctx, closeProtocol, func() (os.FileInfo, error) {
		return protocol.Lstat(backupPath)
	})
	if err != nil || validateDeploymentTargetInfo(verifiedBackup) != nil || !sameDeploymentSnapshot(targetInfo, verifiedBackup) {
		return partial, ErrDeploymentOutcomeUnknown
	}
	_, err = callDeployment(ctx, closeProtocol, func() (os.FileInfo, error) {
		return protocol.Lstat(request.RemotePath)
	})
	if err == nil {
		return partial, ErrDeploymentOutcomeUnknown
	} else if !errors.Is(err, os.ErrNotExist) {
		return partial, ErrDeploymentOutcomeUnknown
	}

	activationErr := callDeploymentError(ctx, closeProtocol, func() error {
		return protocol.Rename(tempPath, request.RemotePath)
	})
	if activationErr != nil || ctx.Err() != nil {
		if ctx.Err() != nil {
			return partial, ErrDeploymentOutcomeUnknown
		}
		if rollbackDeployment(ctx, closeProtocol, protocol, request.RemotePath, backupPath, targetInfo) == nil {
			// The backup has been restored and activation is known not to have
			// happened, so the temporary file can be removed.
			preserveTemporary = false
			return partial, ErrDeploymentActivationFailed
		}
		return partial, ErrDeploymentOutcomeUnknown
	}
	activated = true
	partial.Activated = true
	return partial, nil
}

func validateBinaryDeploymentRequest(source io.Reader, request *BinaryDeploymentRequest) (string, error) {
	if source == nil || request == nil || request.RemotePath == "/" || !isCanonicalDeploymentPath(request.RemotePath) {
		return "", ErrInvalidBinaryDeployment
	}
	if request.ExpectedSize < 0 {
		return "", ErrInvalidBinaryDeployment
	}
	if request.MaxBytes == 0 {
		request.MaxBytes = DefaultBinaryDeploymentBytes
	}
	if request.MaxBytes <= 0 || request.MaxBytes > MaxBinaryDeploymentBytes || request.ExpectedSize > request.MaxBytes {
		return "", ErrDeploymentSourceTooLarge
	}
	encoded := strings.TrimSpace(request.ExpectedSHA256)
	if len(encoded) != sha256.Size*2 {
		return "", ErrInvalidBinaryDeployment
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size {
		return "", ErrInvalidBinaryDeployment
	}
	return strings.ToLower(encoded), nil
}

func isCanonicalDeploymentPath(remotePath string) bool {
	if remotePath == "" || remotePath[0] != '/' || strings.ContainsRune(remotePath, '\x00') || (remotePath != "/" && strings.HasSuffix(remotePath, "/")) {
		return false
	}
	for index, component := range strings.Split(remotePath, "/") {
		if component == "." || component == ".." || (index > 0 && component == "") {
			return false
		}
	}
	return true
}

func validateDeploymentTargetInfo(info os.FileInfo) error {
	if info == nil {
		return ErrDeploymentTargetNotFound
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return ErrDeploymentTargetSymlink
	}
	if !mode.IsRegular() || info.Size() < 0 {
		return ErrDeploymentTargetNotRegular
	}
	return nil
}

func sameDeploymentSnapshot(before, after os.FileInfo) bool {
	if before == nil || after == nil {
		return false
	}
	// A server-side rename preserves the file's identity and contents, but
	// SFTP implementations may normalize permission bits while reporting
	// metadata. Size, type, and modification time give this narrow protocol a
	// conservative replacement check without reading the live target.
	return before.Size() == after.Size() && before.Mode().Type() == after.Mode().Type() && before.ModTime().Equal(after.ModTime())
}

func deploymentSiblingPath(remotePath, marker string) (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return path.Join(path.Dir(remotePath), "."+marker+"-"+hex.EncodeToString(entropy[:])), nil
}

func uploadDeploymentSource(ctx context.Context, closeProtocol func(), writer io.Writer, source io.Reader, expectedSize, maxBytes int64, expectedSHA string) error {
	hash := sha256.New()
	buffer := make([]byte, deploymentChunkBytes)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return ErrDeploymentOutcomeUnknown
		}
		read, readErr := readDeploymentSource(ctx, source, buffer)
		if read < 0 || read > len(buffer) {
			return ErrDeploymentFailed
		}
		if read > 0 {
			if int64(read) > maxBytes-total {
				return ErrDeploymentSourceTooLarge
			}
			written, writeErr := callDeployment(ctx, closeProtocol, func() (int, error) {
				return writer.Write(buffer[:read])
			})
			if writeErr != nil || written != read {
				if ctx.Err() != nil {
					return ErrDeploymentOutcomeUnknown
				}
				return ErrDeploymentFailed
			}
			_, _ = hash.Write(buffer[:read])
			total += int64(read)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil || read == 0 {
			return ErrDeploymentFailed
		}
	}
	if total != expectedSize {
		return ErrDeploymentIntegrity
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expectedSHA)) != 1 {
		return ErrDeploymentIntegrity
	}
	return nil
}

func readDeploymentSource(ctx context.Context, source io.Reader, buffer []byte) (int, error) {
	type result struct {
		read int
		err  error
	}
	completed := make(chan result, 1)
	go func() {
		read, err := source.Read(buffer)
		completed <- result{read: read, err: err}
	}()
	select {
	case <-ctx.Done():
		if closer, ok := source.(io.Closer); ok {
			_ = closer.Close()
		}
		return 0, ctx.Err()
	case value := <-completed:
		return value.read, value.err
	}
}

func verifyDeploymentTemporary(ctx context.Context, closeProtocol func(), protocol deploymentProtocol, tempPath string, expectedSize int64, expectedSHA string) error {
	info, err := callDeployment(ctx, closeProtocol, func() (os.FileInfo, error) {
		return protocol.Lstat(tempPath)
	})
	if err != nil {
		return classifyDeploymentPreparationError(ctx, err, false)
	}
	if err := validateDeploymentTargetInfo(info); err != nil || info.Size() != expectedSize {
		return ErrDeploymentIntegrity
	}
	file, err := callDeployment(ctx, closeProtocol, func() (io.ReadCloser, error) {
		return protocol.Open(tempPath)
	})
	if err != nil {
		return classifyDeploymentPreparationError(ctx, err, false)
	}
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, deploymentChunkBytes)
	var total int64
	for {
		if total == expectedSize {
			break
		}
		remaining := expectedSize - total
		chunk := buffer
		if int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		read, readErr := callDeployment(ctx, closeProtocol, func() (int, error) {
			return file.Read(chunk)
		})
		if read < 0 || read > len(chunk) {
			return ErrDeploymentIntegrity
		}
		if read > 0 {
			if int64(read) > remaining {
				return ErrDeploymentIntegrity
			}
			_, _ = hash.Write(chunk[:read])
			total += int64(read)
		}
		if readErr != nil && readErr != io.EOF {
			if ctx.Err() != nil {
				return ErrDeploymentOutcomeUnknown
			}
			return ErrDeploymentIntegrity
		}
		if readErr == io.EOF && total < expectedSize {
			return ErrDeploymentIntegrity
		}
		if read == 0 && readErr == nil {
			return ErrDeploymentIntegrity
		}
	}
	// Detect a remote file longer than the declared size without retaining the
	// extra bytes. A one-byte read is enough to fail closed.
	var extra [1]byte
	read, readErr := callDeployment(ctx, closeProtocol, func() (int, error) {
		return file.Read(extra[:])
	})
	if read < 0 || read > len(extra) || read > 0 || (readErr != nil && readErr != io.EOF) {
		return ErrDeploymentIntegrity
	}
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash.Sum(nil))), []byte(expectedSHA)) != 1 {
		return ErrDeploymentIntegrity
	}
	return nil
}

func rollbackDeployment(ctx context.Context, closeProtocol func(), protocol deploymentProtocol, targetPath, backupPath string, expected os.FileInfo) error {
	if ctx.Err() != nil {
		return ErrDeploymentOutcomeUnknown
	}
	_, err := callDeployment(ctx, closeProtocol, func() (os.FileInfo, error) {
		return protocol.Lstat(targetPath)
	})
	if err == nil {
		return ErrDeploymentOutcomeUnknown
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrDeploymentOutcomeUnknown
	}
	backupInfo, err := callDeployment(ctx, closeProtocol, func() (os.FileInfo, error) {
		return protocol.Lstat(backupPath)
	})
	if err != nil || validateDeploymentTargetInfo(backupInfo) != nil || !sameDeploymentSnapshot(expected, backupInfo) {
		return ErrDeploymentOutcomeUnknown
	}
	if err := callDeploymentError(ctx, closeProtocol, func() error {
		return protocol.Rename(backupPath, targetPath)
	}); err != nil {
		return ErrDeploymentOutcomeUnknown
	}
	return nil
}

func classifyDeploymentPreparationError(ctx context.Context, err error, target bool) error {
	if ctx.Err() != nil {
		return ErrDeploymentOutcomeUnknown
	}
	if target && errors.Is(err, os.ErrNotExist) {
		return ErrDeploymentTargetNotFound
	}
	if errors.Is(err, os.ErrExist) {
		return ErrDeploymentBackupExists
	}
	return ErrDeploymentFailed
}

func classifyDeploymentMutationError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ErrDeploymentOutcomeUnknown
	}
	if errors.Is(err, os.ErrExist) {
		return ErrDeploymentBackupExists
	}
	return ErrDeploymentOutcomeUnknown
}

func callDeployment[T any](ctx context.Context, closeProtocol func(), operation func() (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	result := make(chan deploymentCallResult[T], 1)
	go func() {
		value, err := operation()
		result <- deploymentCallResult[T]{value: value, err: err}
	}()
	select {
	case <-ctx.Done():
		closeProtocol()
		return zero, ctx.Err()
	case call := <-result:
		if err := ctx.Err(); err != nil {
			closeProtocol()
			return zero, err
		}
		return call.value, call.err
	}
}

type deploymentCallResult[T any] struct {
	value T
	err   error
}

func callDeploymentError(ctx context.Context, closeProtocol func(), operation func() error) error {
	_, err := callDeployment(ctx, closeProtocol, func() (struct{}, error) {
		return struct{}{}, operation()
	})
	return err
}

func callDeploymentClose(ctx context.Context, closeProtocol func(), writer io.Closer) error {
	if err := callDeploymentError(ctx, closeProtocol, writer.Close); err != nil {
		if ctx.Err() != nil {
			return ErrDeploymentOutcomeUnknown
		}
		return ErrDeploymentFailed
	}
	return nil
}

func fmtNotDispatchedDeployment(err error) error {
	return errors.Join(ErrNotDispatched, err)
}
