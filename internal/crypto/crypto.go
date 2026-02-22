// Package crypto provides AES-256-CBC encryption and decryption primitives
// for geheim. The implementation is byte-identical to Ruby's OpenSSL
// AES-256-CBC cipher so that files encrypted by the Ruby CLI can be
// decrypted by the Go implementation and vice-versa.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"os"
)

const defaultBlockSize = 16

// Cipher holds the derived key and IV used for every encrypt/decrypt call.
// Both values are fixed for the lifetime of the struct; create a new Cipher
// if the key file or PIN changes.
type Cipher struct {
	key []byte // exactly keyLength bytes (default 32 for AES-256)
	iv  []byte // exactly 16 bytes (AES block size)
}

// NewCipher reads the raw key material from keyFile, pads/truncates it to
// keyLength bytes using the same doubling strategy as the Ruby reference
// implementation, and derives the 16-byte IV from pin and addToIV.
//
// keyLength is typically 32 (AES-256). pin and addToIV must be ASCII strings
// because the IV is constructed at the byte level (not the rune level).
func NewCipher(keyFile string, keyLength int, pin string, addToIV string) (*Cipher, error) {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading key file %q: %w", keyFile, err)
	}
	if len(raw) == 0 {
		return nil, errors.New("key file is empty")
	}

	return &Cipher{
		key: enforceKeyLength(raw, keyLength),
		iv:  buildIV(pin, addToIV),
	}, nil
}

// enforceKeyLength replicates the Ruby `enforce_key_length` method:
//
//	new_key += key while new_key.size < force_size
//	new_key[0, force_size]
//
// If key is already exactly size bytes it is returned unchanged (after a copy).
// If it is longer it is simply truncated. If it is shorter the key is
// concatenated with itself until it reaches at least size bytes, then
// truncated to exactly size bytes.
func enforceKeyLength(key []byte, size int) []byte {
	newKey := make([]byte, len(key))
	copy(newKey, key)

	// Keep appending the original key until we have enough bytes.
	for len(newKey) < size {
		newKey = append(newKey, key...)
	}

	return newKey[:size]
}

// buildIV constructs the 16-byte initialization vector the same way the Ruby
// reference does:
//
//	iv_str = pin * 2 + add_to_iv + pin * 2
//	iv = iv_str.byteslice(0, 16)
//
// The slice is performed on bytes, not runes, so ASCII PINs are required for
// correct cross-language compatibility.
func buildIV(pin, addToIV string) []byte {
	ivStr := pin + pin + addToIV + pin + pin
	return []byte(ivStr)[:16]
}

// Encrypt encrypts plaintext using AES-256-CBC with PKCS7 padding and returns
// the raw binary ciphertext (no base64 encoding). PKCS7 always adds a full
// extra block when the plaintext length is already a multiple of 16.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	padded := pkcs7Pad(plaintext, defaultBlockSize)

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, c.iv)
	mode.CryptBlocks(ciphertext, padded)

	return ciphertext, nil
}

// Decrypt decrypts AES-256-CBC ciphertext (raw binary, no base64) and strips
// PKCS7 padding, returning the original plaintext bytes.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%defaultBlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of block size %d",
			len(ciphertext), defaultBlockSize)
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext is empty")
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	// Decrypt in-place: CBC decrypter writes back into the same slice.
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, c.iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext)
}

// pkcs7Pad appends PKCS7 padding so that len(result) is a multiple of
// blockSize. A full extra block is added when the input is already aligned,
// matching OpenSSL's default behaviour.
func pkcs7Pad(data []byte, blockSize int) []byte {
	// padding value is the number of bytes that need to be added;
	// at minimum 1, at maximum blockSize (full block when already aligned).
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// pkcs7Unpad validates and removes PKCS7 padding from decrypted data.
// It returns an error if the padding byte value is out of range (0 or >16) or
// if any of the trailing padding bytes do not equal the padding value.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7Unpad: data is empty")
	}

	padLen := int(data[len(data)-1])
	if padLen < 1 || padLen > defaultBlockSize {
		return nil, fmt.Errorf("pkcs7Unpad: invalid padding byte %d", padLen)
	}
	if padLen > len(data) {
		return nil, fmt.Errorf("pkcs7Unpad: padding length %d exceeds data length %d", padLen, len(data))
	}

	// Validate that every padding byte equals padLen.
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("pkcs7Unpad: invalid padding at byte %d: got %d, want %d",
				i, data[i], padLen)
		}
	}

	return data[:len(data)-padLen], nil
}
