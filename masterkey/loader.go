// Package masterkey loads the file-backed trust root used by the Secrets
// Service. It deliberately accepts only exact, raw 256-bit keys and never
// exposes key bytes after constructing envelope keys.
package masterkey

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Niftel/praetor-secrets/envelope"
)

const keySize = 32

var (
	ErrKeyFile        = errors.New("master key file unavailable")
	ErrKeyPermissions = errors.New("master key file permissions are too broad")
	ErrKeyLength      = errors.New("master key must contain exactly 32 bytes")
	ErrDuplicateKey   = errors.New("current and previous master keys are identical")
)

// Config names the read-only files mounted into the Secrets Service. The
// previous file is optional and exists only for a bounded rotation window.
type Config struct {
	CurrentPath  string
	PreviousPath string
}

// Set contains the only key allowed for new encryption and the bounded keyring
// accepted for decryption. Previous is nil outside a rotation window.
type Set struct {
	Current  envelope.MasterKey
	Previous *envelope.MasterKey
	keyring  map[string]envelope.MasterKey
}

// Keyring returns a copy so callers cannot alter the loader's rotation state.
func (s Set) Keyring() map[string]envelope.MasterKey {
	out := make(map[string]envelope.MasterKey, len(s.keyring))
	for id, key := range s.keyring {
		out[id] = key
	}
	return out
}

// Load validates both files before returning any usable key set. It fails
// closed and intentionally excludes paths and underlying file contents from
// errors because configuration values may reveal deployment details.
func Load(config Config) (Set, error) {
	current, err := loadOne("current", config.CurrentPath)
	if err != nil {
		return Set{}, err
	}

	set := Set{
		Current: current,
		keyring: map[string]envelope.MasterKey{current.ID(): current},
	}
	if config.PreviousPath == "" {
		return set, nil
	}

	previous, err := loadOne("previous", config.PreviousPath)
	if err != nil {
		return Set{}, err
	}
	if previous.ID() == current.ID() {
		return Set{}, ErrDuplicateKey
	}
	set.Previous = &previous
	set.keyring[previous.ID()] = previous
	return set, nil
}

func loadOne(label, path string) (envelope.MasterKey, error) {
	if path == "" {
		return envelope.MasterKey{}, fmt.Errorf("%s master key: %w", label, ErrKeyFile)
	}

	file, err := os.Open(path)
	if err != nil {
		return envelope.MasterKey{}, fmt.Errorf("%s master key: %w", label, ErrKeyFile)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return envelope.MasterKey{}, fmt.Errorf("%s master key: %w", label, ErrKeyFile)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return envelope.MasterKey{}, fmt.Errorf("%s master key: %w", label, ErrKeyPermissions)
	}

	raw := make([]byte, keySize+1)
	n, err := io.ReadFull(file, raw)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		wipe(raw)
		return envelope.MasterKey{}, fmt.Errorf("%s master key: %w", label, ErrKeyFile)
	}
	if n != keySize {
		wipe(raw)
		return envelope.MasterKey{}, fmt.Errorf("%s master key: %w", label, ErrKeyLength)
	}
	if _, err := file.Read(raw[keySize:]); err != io.EOF {
		wipe(raw)
		if err != nil {
			return envelope.MasterKey{}, fmt.Errorf("%s master key: %w", label, ErrKeyFile)
		}
		return envelope.MasterKey{}, fmt.Errorf("%s master key: %w", label, ErrKeyLength)
	}

	digest := sha256.Sum256(raw[:keySize])
	id := "sha256:" + hex.EncodeToString(digest[:16])
	key, err := envelope.NewMasterKey(id, raw[:keySize])
	wipe(raw)
	if err != nil {
		return envelope.MasterKey{}, fmt.Errorf("%s master key: %w", label, ErrKeyLength)
	}
	return key, nil
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
