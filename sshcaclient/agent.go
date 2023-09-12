package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/inconshreveable/log15"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Agent struct {
	pubKey ssh.PublicKey
	signer crypto.PrivateKey
}

// List returns the identities known to the agent.
func (a *Agent) List() ([]*agent.Key, error) {
	return []*agent.Key{
		{
			Format:  a.pubKey.Type(),
			Blob:    a.pubKey.Marshal(),
			Comment: fmt.Sprintf("CA key"),
		},
		{
			Format:  a.pubKey.Type() + "-CERT",
			Blob:    a.pubKey.Marshal(),
			Comment: fmt.Sprintf("CA cert"),
		},
	}, nil
}

func (a *Agent) serveConn(c net.Conn) {
	lgr := log15.New()
	if err := agent.ServeAgent(a, c); err != io.EOF {
		lgr.Error("agent_conn_err", "err", err)
	}
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if !bytes.Equal(a.pubKey.Marshal(), key.Marshal()) {
		return nil, fmt.Errorf("no private keys match the requested public key")
	}

	signer, err := ssh.NewSignerFromKey(a.signer)
	if err != nil {
		return nil, fmt.Errorf("get ssh signer err: %w", err)
	}

	cert, ok := a.pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("public key is not an ssh.Certificate")
	}

	signer, err = ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("new cert signer err: %w", err)
	}

	lgr := log15.New()
	lgr.Info("sign_req", "alg", key.Type(), "flags", flags, "signer", signer.PublicKey().Type())

	return signer.Sign(rand.Reader, data)
}

var ErrOperationUnsupported = errors.New("operation unsupported")

// Add adds a private key to the agent.
func (a *Agent) Add(key agent.AddedKey) error {
	return ErrOperationUnsupported
}

// Remove removes all identities with the given public key.
func (a *Agent) Remove(key ssh.PublicKey) error {
	return ErrOperationUnsupported
}

// RemoveAll removes all identities.
func (a *Agent) RemoveAll() error {
	return ErrOperationUnsupported
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (a *Agent) Lock(passphrase []byte) error {
	return ErrOperationUnsupported
}

// Unlock undoes the effect of Lock
func (a *Agent) Unlock(passphrase []byte) error {
	return ErrOperationUnsupported
}

// Signers returns signers for all the known keys.
func (a *Agent) Signers() ([]ssh.Signer, error) {
	signer, err := ssh.NewSignerFromKey(a.signer)
	if err != nil {
		return nil, fmt.Errorf("get ssh signer err: %w", err)
	}
	return []ssh.Signer{signer}, nil
}
