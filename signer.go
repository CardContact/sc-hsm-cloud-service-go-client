package openapi

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

type Signer struct {
	client    *APIClient
	keyID     string
	publicKey crypto.PublicKey
}

func NewSigner(client *APIClient, keyID string) (*Signer, error) {
	ctx, cancel := defaultContext()
	defer cancel()

	key, httpRsp, err := client.DefaultAPI.GetKey(ctx, keyID).Execute()

	if httpRsp != nil && httpRsp.StatusCode == 404 {
		return nil, fmt.Errorf("schsm: key %v not found", keyID)
	}

	if err != nil {
		return nil, fmt.Errorf("schsm: GetKey failed: %w", err)
	}
	defer httpRsp.Body.Close()

	if key.Pubkey == nil {
		return nil, fmt.Errorf("schsm: key %v has no public key", keyID)
	}

	derBytes, err := base64.StdEncoding.DecodeString(*key.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("schsm: decoding public key failed: %w", err)
	}

	pubKey, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("schsm: parsing public key failed: %w", err)
	}

	signer := &Signer{
		client:    client,
		keyID:     keyID,
		publicKey: pubKey,
	}

	return signer, nil
}

func (c *APIClient) NewSigner(keyID string) (*Signer, error) {
	return NewSigner(c, keyID)
}

func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx, cancel := defaultContext()
	defer cancel()

	var algo KeyAlgorithm
	if _, ok := s.publicKey.(*rsa.PublicKey); ok {
		algo = RSA_PSS
	} else {
		algo = ECDSA
	}

	hash := hex.EncodeToString(digest)
	signatureInput := NewSignatureInput(hash, algo)

	signatureRsp, httpRsp, err := s.client.DefaultAPI.SignHash(ctx, s.keyID).SignatureInput(*signatureInput).Execute()

	if httpRsp != nil && httpRsp.StatusCode != 200 {
		return nil, fmt.Errorf("schsm: SignHash failed with status code: %v", httpRsp.StatusCode)
	}
	if err != nil {
		return nil, fmt.Errorf("schsm: SignHash failed: %w", err)
	}

	signature, err := hex.DecodeString(signatureRsp.GetSignature())
	return signature, err
}

func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}
