package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	envelopeVersion = 1
	fieldVersion    = 1
	dataKeySize     = 32
	saltSize        = 16
	kdfTime         = 3
	kdfMemoryKiB    = 64 * 1024
	kdfThreads      = 4
)

var (
	errInvalidEnvelope = errors.New("invalid credential envelope")
	errInvalidCipher   = errors.New("invalid encrypted credential")
)

type Envelope struct {
	Version    uint8
	Salt       []byte
	Nonce      []byte
	Ciphertext []byte
}

func NewEnvelope(masterPassword []byte) (Envelope, []byte, error) {
	dataKey := make([]byte, dataKeySize)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return Envelope{}, nil, fmt.Errorf("generate data key: %w", err)
	}

	envelope, err := wrap(masterPassword, dataKey)
	if err != nil {
		Zero(dataKey)
		return Envelope{}, nil, err
	}

	return envelope, dataKey, nil
}

func Unlock(masterPassword []byte, envelope Envelope) ([]byte, error) {
	if envelope.Version != envelopeVersion || len(envelope.Salt) != saltSize {
		return nil, errInvalidEnvelope
	}

	kek, err := deriveKey(masterPassword, envelope.Salt)
	if err != nil {
		return nil, errInvalidEnvelope
	}
	defer Zero(kek)

	plain, err := open(kek, envelope.Nonce, envelope.Ciphertext, []byte("ssh-mcp:dek:v1"))
	if err != nil || len(plain) != dataKeySize {
		Zero(plain)
		return nil, errInvalidEnvelope
	}

	return plain, nil
}

func Rewrap(oldMasterPassword, newMasterPassword []byte, envelope Envelope) (Envelope, error) {
	dataKey, err := Unlock(oldMasterPassword, envelope)
	if err != nil {
		return Envelope{}, err
	}
	defer Zero(dataKey)

	return wrap(newMasterPassword, dataKey)
}

func Encrypt(dataKey, plaintext, associatedData []byte) ([]byte, error) {
	if len(dataKey) != dataKeySize {
		return nil, errInvalidCipher
	}

	gcm, err := newGCM(dataKey)
	if err != nil {
		return nil, errInvalidCipher
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate credential nonce: %w", err)
	}

	ciphertext := make([]byte, 1+len(nonce))
	ciphertext[0] = fieldVersion
	copy(ciphertext[1:], nonce)
	ciphertext = gcm.Seal(ciphertext, nonce, plaintext, associatedData)
	return ciphertext, nil
}

func Decrypt(dataKey, ciphertext, associatedData []byte) ([]byte, error) {
	if len(dataKey) != dataKeySize || len(ciphertext) < 2 || ciphertext[0] != fieldVersion {
		return nil, errInvalidCipher
	}

	gcm, err := newGCM(dataKey)
	if err != nil || len(ciphertext) < 1+gcm.NonceSize()+gcm.Overhead() {
		return nil, errInvalidCipher
	}

	plain, err := gcm.Open(nil, ciphertext[1:1+gcm.NonceSize()], ciphertext[1+gcm.NonceSize():], associatedData)
	if err != nil {
		return nil, errInvalidCipher
	}
	return plain, nil
}

func Zero(bytes []byte) {
	clear(bytes)
}

func wrap(masterPassword, dataKey []byte) (Envelope, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return Envelope{}, fmt.Errorf("generate key salt: %w", err)
	}

	kek, err := deriveKey(masterPassword, salt)
	if err != nil {
		return Envelope{}, err
	}
	defer Zero(kek)

	gcm, err := newGCM(kek)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate envelope nonce: %w", err)
	}

	return Envelope{
		Version:    envelopeVersion,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: gcm.Seal(nil, nonce, dataKey, []byte("ssh-mcp:dek:v1")),
	}, nil
}

func deriveKey(masterPassword, salt []byte) ([]byte, error) {
	if len(masterPassword) == 0 || len(salt) != saltSize {
		return nil, errInvalidEnvelope
	}
	return argon2.IDKey(masterPassword, salt, kdfTime, kdfMemoryKiB, kdfThreads, dataKeySize), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func open(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, errInvalidEnvelope
	}
	return gcm.Open(nil, nonce, ciphertext, associatedData)
}
