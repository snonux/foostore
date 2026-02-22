// Package crypto tests verify byte-for-byte compatibility with the Ruby
// OpenSSL AES-256-CBC reference implementation in geheim.rb.
//
// Golden hex values were generated with:
//
//	ruby -e '
//	  require "openssl"
//	  def enforce_key(key, size)
//	    k = key.dup; k += key while k.size < size; k[0, size]
//	  end
//	  def do_enc(plain, pin, key_content, add_to_iv="Hello world", key_length=32)
//	    key = enforce_key(key_content, key_length)
//	    iv_str = pin * 2 + add_to_iv + pin * 2
//	    iv = iv_str.byteslice(0, 16)
//	    aes = OpenSSL::Cipher.new("AES-256-CBC")
//	    aes.encrypt; aes.key = key; aes.iv = iv
//	    ct = aes.update(plain) + aes.final
//	    puts ct.bytes.map { |b| "%02x" % b }.join
//	  end
//	  do_enc("Hello, world!", "1234", "shortkey")
//	  do_enc("Hello, world!", "ab", "x" * 32)
//	  do_enc("Hello, world!", "abcd1234", "y" * 64)
//	  do_enc("a" * 16, "1234", "shortkey")
//	  do_enc("b" * 48, "1234", "shortkey")
//	  do_enc("\x00\x01\x02\xff", "1234", "shortkey")
//	'
package crypto

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// --- helpers -----------------------------------------------------------------

// writeKeyFile writes content to a temporary file and returns the path.
// The file is removed when the test completes.
func writeKeyFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyfile")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeKeyFile: %v", err)
	}
	return path
}

// mustHex decodes a hex string, failing the test on any error.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("mustHex(%q): %v", s, err)
	}
	return b
}

// --- TestEnforceKeyLength ----------------------------------------------------

// TestEnforceKeyLength covers the four interesting edge cases for the key
// extension algorithm that mirrors Ruby's `enforce_key_length`.
func TestEnforceKeyLength(t *testing.T) {
	cases := []struct {
		name string
		key  []byte
		size int
		want []byte
	}{
		{
			name: "key shorter than size — doubled until long enough then truncated",
			key:  []byte("ab"),
			size: 5,
			want: []byte("ababa"),
		},
		{
			name: "key exact size — returned unchanged",
			key:  []byte("abcde"),
			size: 5,
			want: []byte("abcde"),
		},
		{
			name: "key longer than size — truncated",
			key:  []byte("abcdefgh"),
			size: 5,
			want: []byte("abcde"),
		},
		{
			name: "single-byte key expanded to 32 bytes",
			key:  []byte("x"),
			size: 32,
			want: []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := enforceKeyLength(tc.key, tc.size)
			if string(got) != string(tc.want) {
				t.Errorf("enforceKeyLength(%q, %d) = %q; want %q",
					tc.key, tc.size, got, tc.want)
			}
		})
	}
}

// --- TestBuildIV -------------------------------------------------------------

// TestBuildIV verifies that the IV derivation matches the Ruby reference:
//
//	iv_str = pin * 2 + add_to_iv + pin * 2, then byteslice(0, 16).
//
// Verified with Ruby: pin="1234" → "12341234Hello wo"; pin="ab" → "ababHello worlda"
func TestBuildIV(t *testing.T) {
	cases := []struct {
		pin     string
		addToIV string
		// wantStr is the expected string content of the 16-byte IV.
		// Verified via: ruby -e 'pin="X"; iv_str=pin*2+"ADD"+pin*2; p iv_str.byteslice(0,16)'
		wantStr string
	}{
		{
			// "1234"*2 + "Hello world" + "1234"*2 = "12341234Hello world12341234"
			// first 16 bytes: "12341234Hello wo"
			pin:     "1234",
			addToIV: "Hello world",
			wantStr: "12341234Hello wo",
		},
		{
			// "ab"*2 + "Hello world" + "ab"*2 = "ababHello worldabab"
			// first 16 bytes: "ababHello worlda"
			pin:     "ab",
			addToIV: "Hello world",
			wantStr: "ababHello worlda",
		},
		{
			// pin="" → addToIV fills all 16 bytes
			pin:     "",
			addToIV: "0123456789abcdef",
			wantStr: "0123456789abcdef",
		},
	}

	for _, tc := range cases {
		t.Run(tc.pin+"|"+tc.addToIV, func(t *testing.T) {
			got := buildIV(tc.pin, tc.addToIV)
			if len(got) != 16 {
				t.Errorf("buildIV returned %d bytes; want 16", len(got))
			}
			gotHex := hex.EncodeToString(got)
			wantHex := hex.EncodeToString([]byte(tc.wantStr))
			if gotHex != wantHex {
				t.Errorf("buildIV(%q, %q)\n  got  hex=%q (%q)\n  want hex=%q (%q)",
					tc.pin, tc.addToIV, gotHex, got, wantHex, tc.wantStr)
			}
		})
	}
}

// --- TestPKCS7PadUnpad -------------------------------------------------------

// TestPKCS7PadUnpad checks padding for inputs of various lengths including the
// critical case where the input is already block-aligned (must add a full extra
// block), and validates that pkcs7Unpad rejects corrupted padding.
func TestPKCS7PadUnpad(t *testing.T) {
	t.Run("pad 15-byte input to 16", func(t *testing.T) {
		data := make([]byte, 15)
		got := pkcs7Pad(data, 16)
		if len(got) != 16 {
			t.Fatalf("expected 16 bytes; got %d", len(got))
		}
		if got[15] != 0x01 {
			t.Errorf("last byte = 0x%02x; want 0x01", got[15])
		}
	})

	t.Run("pad 16-byte input adds full extra block of 0x10", func(t *testing.T) {
		data := make([]byte, 16)
		got := pkcs7Pad(data, 16)
		if len(got) != 32 {
			t.Fatalf("expected 32 bytes; got %d", len(got))
		}
		// All 16 padding bytes must equal 0x10.
		for i := 16; i < 32; i++ {
			if got[i] != 0x10 {
				t.Errorf("padding byte %d = 0x%02x; want 0x10", i, got[i])
			}
		}
	})

	t.Run("pad 0-byte input to 16 bytes of 0x10", func(t *testing.T) {
		got := pkcs7Pad([]byte{}, 16)
		if len(got) != 16 {
			t.Fatalf("expected 16 bytes; got %d", len(got))
		}
		for i, b := range got {
			if b != 0x10 {
				t.Errorf("byte %d = 0x%02x; want 0x10", i, b)
			}
		}
	})

	t.Run("unpad valid padding — 3 data bytes, 1 byte of padding 0x01", func(t *testing.T) {
		// 15 data bytes (0x00..0x0e) followed by 0x01 padding → unpad yields 15 bytes.
		data := []byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x01,
		}
		got, err := pkcs7Unpad(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 15 {
			t.Errorf("expected 15 bytes after unpad; got %d", len(got))
		}
	})

	t.Run("unpad valid padding — 12 data bytes, 4 bytes of padding 0x04", func(t *testing.T) {
		// 12 data bytes followed by four 0x04 bytes → unpad yields 12 bytes.
		data := []byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x04, 0x04, 0x04, 0x04,
		}
		got, err := pkcs7Unpad(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 12 {
			t.Errorf("expected 12 bytes after unpad; got %d", len(got))
		}
	})

	t.Run("unpad invalid padding byte value 0", func(t *testing.T) {
		// A padding byte of 0 is never valid in PKCS7.
		data := make([]byte, 16) // all zeros → last byte is 0
		_, err := pkcs7Unpad(data)
		if err == nil {
			t.Error("expected error for padding byte 0; got nil")
		}
	})

	t.Run("unpad invalid padding byte value 17 (> blockSize)", func(t *testing.T) {
		data := make([]byte, 16)
		data[15] = 0x11 // 17 > block size of 16
		_, err := pkcs7Unpad(data)
		if err == nil {
			t.Error("expected error for padding byte 17; got nil")
		}
	})

	t.Run("unpad corrupted padding bytes", func(t *testing.T) {
		// Claim 3 bytes of padding but the second-to-last bytes don't match.
		data := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x99, 0x03, 0x03}
		_, err := pkcs7Unpad(data)
		if err == nil {
			t.Error("expected error for corrupted padding bytes; got nil")
		}
	})
}

// --- TestEncryptGolden -------------------------------------------------------

// TestEncryptGolden compares Go Encrypt output against hex values generated by
// the Ruby OpenSSL reference implementation, ensuring byte-for-byte output
// compatibility.
func TestEncryptGolden(t *testing.T) {
	cases := []struct {
		name      string
		plaintext []byte
		pin       string
		keyData   string
		addToIV   string
		keyLength int
		wantHex   string
	}{
		{
			name:      "Hello world / pin=1234 / shortkey",
			plaintext: []byte("Hello, world!"),
			pin:       "1234",
			keyData:   "shortkey",
			addToIV:   "Hello world",
			keyLength: 32,
			wantHex:   "78c08330c963e089ab15700bf9453700",
		},
		{
			name:      "Hello world / pin=ab / 32x 'x'",
			plaintext: []byte("Hello, world!"),
			pin:       "ab",
			keyData:   "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // 32 bytes
			addToIV:   "Hello world",
			keyLength: 32,
			wantHex:   "6190f985f42374d24dd8e17b3b2d6057",
		},
		{
			name:      "Hello world / pin=abcd1234 / 64x 'y'",
			plaintext: []byte("Hello, world!"),
			pin:       "abcd1234",
			// 64 bytes of 'y': key is already 2x the required 32 bytes so it gets truncated.
			keyData:   "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
			addToIV:   "Hello world",
			keyLength: 32,
			wantHex:   "b2a0c920a53676a3d32c7422e5f7fb4f",
		},
		{
			name: "16x 'a' (block-aligned) / pin=1234 / shortkey",
			// A block-aligned plaintext still gets a full extra block of padding.
			plaintext: []byte("aaaaaaaaaaaaaaaa"),
			pin:       "1234",
			keyData:   "shortkey",
			addToIV:   "Hello world",
			keyLength: 32,
			wantHex:   "8968368e480298e8c3273c5d6169f57cf4827f5e4697c2772428c0e603487367",
		},
		{
			name:      "48x 'b' / pin=1234 / shortkey",
			plaintext: []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
			pin:       "1234",
			keyData:   "shortkey",
			addToIV:   "Hello world",
			keyLength: 32,
			// 128 hex chars = 64 bytes (48-byte plaintext + 16-byte padding block)
			wantHex: "3c3cb309ea80422e958e454528f965fc40e46409ebb0ee459c769dd2be14976938a1551e3b907e7cb165da78196caa3cf50bdf6fcbe1128c14a39024f84eb168",
		},
		{
			name:      "binary input 00 01 02 ff / pin=1234 / shortkey",
			plaintext: []byte{0x00, 0x01, 0x02, 0xff},
			pin:       "1234",
			keyData:   "shortkey",
			addToIV:   "Hello world",
			keyLength: 32,
			wantHex:   "ccaf7cb5d2ce8703e20716beb9ecfc82",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyFile := writeKeyFile(t, tc.keyData)
			c, err := NewCipher(keyFile, tc.keyLength, tc.pin, tc.addToIV)
			if err != nil {
				t.Fatalf("NewCipher: %v", err)
			}

			got, err := c.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			gotHex := hex.EncodeToString(got)
			if gotHex != tc.wantHex {
				t.Errorf("Encrypt mismatch:\n  got  %s\n  want %s", gotHex, tc.wantHex)
			}
		})
	}
}

// --- TestEncryptDecryptRoundtrip ---------------------------------------------

// TestEncryptDecryptRoundtrip verifies that Decrypt(Encrypt(plain)) == plain
// for a variety of inputs. It does not rely on golden values, so it catches
// padding or mode errors that the golden test might miss if both paths share
// the same bug.
func TestEncryptDecryptRoundtrip(t *testing.T) {
	cases := []struct {
		name      string
		plaintext []byte
		pin       string
		keyData   string
	}{
		{"empty input", []byte{}, "pin", "somekey"},
		{"short ASCII", []byte("hello"), "1234", "shortkey"},
		{"exactly 16 bytes", []byte("0123456789abcdef"), "1234", "shortkey"},
		{"17 bytes", []byte("0123456789abcdefX"), "pin99", "mykey"},
		{"32 bytes", make([]byte, 32), "abcd", "k"},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xfe, 0xff}, "zz", "binarykey"},
		{"127 bytes", make([]byte, 127), "longpin12345678", "keydata"},
		{"128 bytes", make([]byte, 128), "x", "y"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyFile := writeKeyFile(t, tc.keyData)
			c, err := NewCipher(keyFile, 32, tc.pin, "Hello world")
			if err != nil {
				t.Fatalf("NewCipher: %v", err)
			}

			ciphertext, err := c.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			recovered, err := c.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if string(recovered) != string(tc.plaintext) {
				t.Errorf("roundtrip mismatch:\n  got  %x\n  want %x", recovered, tc.plaintext)
			}
		})
	}
}

// --- TestNewCipherErrors -----------------------------------------------------

// TestNewCipherErrors exercises the error paths in NewCipher.
func TestNewCipherErrors(t *testing.T) {
	t.Run("non-existent key file", func(t *testing.T) {
		_, err := NewCipher("/nonexistent/path/keyfile", 32, "pin", "addiv")
		if err == nil {
			t.Error("expected error for missing key file; got nil")
		}
	})

	t.Run("empty key file", func(t *testing.T) {
		keyFile := writeKeyFile(t, "")
		_, err := NewCipher(keyFile, 32, "pin", "addiv")
		if err == nil {
			t.Error("expected error for empty key file; got nil")
		}
	})
}

// --- TestDecryptErrors -------------------------------------------------------

// TestDecryptErrors verifies that Decrypt returns sensible errors for
// malformed input rather than panicking or silently returning garbage.
func TestDecryptErrors(t *testing.T) {
	keyFile := writeKeyFile(t, "somekey")
	c, err := NewCipher(keyFile, 32, "1234", "Hello world")
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	t.Run("empty ciphertext", func(t *testing.T) {
		_, err := c.Decrypt([]byte{})
		if err == nil {
			t.Error("expected error for empty ciphertext; got nil")
		}
	})

	t.Run("ciphertext not multiple of block size", func(t *testing.T) {
		_, err := c.Decrypt(mustHex(t, "deadbeef01"))
		if err == nil {
			t.Error("expected error for non-aligned ciphertext; got nil")
		}
	})
}
