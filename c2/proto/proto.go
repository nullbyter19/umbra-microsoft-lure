// Package proto defines the umbra C2 wire format: an authenticated, encrypted
// envelope (AES-256-GCM) carrying JSON messages. It has no external dependency
// and is shared by the server, the beacon and the config packer, so all three
// can never disagree about the framing.
package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// magic prefixes every envelope. It lets a peer reject a wrong body shape before
// touching the crypto, and makes the traffic trivially distinguishable on the
// wire from any other POST body.
var magic = []byte("UMB1")

// Key derives the 32-byte AES key from a shared passphrase.
func Key(passphrase string) []byte {
	s := sha256.Sum256([]byte(passphrase))
	return s[:]
}

// Seal encrypts plain with AES-256-GCM and returns magic||nonce||ciphertext.
func Seal(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	out := make([]byte, 0, len(magic)+len(nonce)+len(ct))
	out = append(out, magic...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open reverses Seal. It fails on a bad magic, a truncated body or a failed
// authentication tag, so a forged or replayed-modified message is rejected.
func Open(key, env []byte) ([]byte, error) {
	if len(env) < len(magic) || string(env[:len(magic)]) != string(magic) {
		return nil, errors.New("proto: bad envelope magic")
	}
	body := env[len(magic):]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(body) < ns {
		return nil, errors.New("proto: envelope truncated")
	}
	pt, err := gcm.Open(nil, body[:ns], body[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("proto: decrypt failed: %w", err)
	}
	return pt, nil
}

// SealMessage marshals v and seals the result.
func SealMessage(key []byte, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Seal(key, b)
}

// OpenMessage decrypts env and unmarshals it into v.
func OpenMessage(key, env []byte, v any) error {
	b, err := Open(key, env)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
