package store

import "context"

// Encryptor is the minimal crypto dependency needed by store operations.
type Encryptor interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

// Committer is the minimal git dependency needed by store operations.
type Committer interface {
	Add(context.Context, string) error
	Remove(context.Context, string) error
}
