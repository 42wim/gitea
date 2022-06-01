// Copyright 2021 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	asymkey_model "code.gitea.io/gitea/models/asymkey"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/web/middleware"

	"github.com/go-fed/httpsig"
	"golang.org/x/crypto/ssh"
)

// Ensure the struct implements the interface.
var (
	_ Method = &HTTPSign{}
	_ Named  = &HTTPSign{}
)

// HTTPSign implements the Auth interface and authenticates requests (API requests
// only) by looking for http signature data in the "Signature" header.
// more information can be found on https://github.com/go-fed/httpsig
type HTTPSign struct{}

// Name represents the name of auth method
func (h *HTTPSign) Name() string {
	return "httpsign"
}

// Verify extracts and validates HTTPsign from the Signature header of the request and returns
// the corresponding user object on successful validation.
// Returns nil if header is empty or validation fails.
func (h *HTTPSign) Verify(req *http.Request, w http.ResponseWriter, store DataStore, sess SessionStore) *user_model.User {
	// HTTPSign authentication should only fire on API
	if !middleware.IsAPIPath(req) {
		return nil
	}

	sigHead := req.Header.Get("Signature")
	if len(sigHead) == 0 {
		return nil
	}

	var (
		validpk *asymkey_model.PublicKey
		err     error
	)

	if len(req.Header.Get("X-Ssh-Certificate")) != 0 {
		// Handle Signature signed by SSH certificates
		if len(setting.SSH.TrustedUserCAKeys) == 0 {
			return nil
		}

		validpk, err = VerifyCert(req)
		if err != nil {
			log.Debug("VerifyCert on request from %s: failed: %v", req.RemoteAddr, err)
			log.Warn("Failed authentication attempt from %s", req.RemoteAddr)
			return nil
		}
	} else {
		// Handle Signature signed by Public Key
		validpk, err = VerifyPubKey(req)
		if err != nil {
			log.Debug("VerifyPubKey on request from %s: failed: %v", req.RemoteAddr, err)
			log.Warn("Failed authentication attempt from %s", req.RemoteAddr)
			return nil
		}
	}

	u, err := user_model.GetUserByID(validpk.OwnerID)
	if err != nil {
		log.Error("GetUserByID:  %v", err)
		return nil
	}

	store.GetData()["IsApiToken"] = true

	log.Trace("HTTP Sign: Logged in user %-v", u)

	return u
}

func VerifyPubKey(r *http.Request) (*asymkey_model.PublicKey, error) {
	verifier, err := httpsig.NewVerifier(r)
	if err != nil {
		return nil, fmt.Errorf("httpsig.NewVerifier failed: %s", err)
	}

	keyID := verifier.KeyId()

	validpk, err := asymkey_model.SearchPublicKey(0, keyID)
	if err != nil {
		return nil, err
	}

	if len(validpk) == 0 {
		return nil, fmt.Errorf("no public key found for keyid %s", keyID)
	}

	pk, err := ssh.ParsePublicKey([]byte(validpk[0].Content))
	if err != nil {
		return nil, err
	}

	if err := doVerify(verifier, []ssh.PublicKey{pk}); err != nil {
		return nil, err
	}

	return validpk[0], nil
}

// VerifyCert verifies the validity of the ssh certificate and returns the publickey of the signer
// We verify that the certificate is signed with the correct CA
// We verify that the http request is signed with the private key (of the public key mentioned in the certificate)
func VerifyCert(r *http.Request) (*asymkey_model.PublicKey, error) {
	var validpk *asymkey_model.PublicKey

	// Get our certificate from the header
	bcert, err := base64.RawStdEncoding.DecodeString(r.Header.Get("x-ssh-certificate"))
	if err != nil {
		return validpk, err
	}

	pk, err := ssh.ParsePublicKey(bcert)
	if err != nil {
		return validpk, err
	}

	// Check if it's really a ssh certificate
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return validpk, fmt.Errorf("no certificate found")
	}

	for _, principal := range cert.ValidPrincipals {
		validpk, err = asymkey_model.SearchPublicKeyByContentExact(r.Context(), principal)
		if err != nil {
			if asymkey_model.IsErrKeyNotExist(err) {
				continue
			}
			log.Error("SearchPublicKeyByContentExact: %v", err)
			return validpk, err
		}

		c := &ssh.CertChecker{
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				marshaled := auth.Marshal()

				for _, k := range setting.SSH.TrustedUserCAKeysParsed {
					if bytes.Equal(marshaled, k.Marshal()) {
						return true
					}
				}

				return false
			},
		}

		// check the CA of the cert
		if !c.IsUserAuthority(cert.SignatureKey) {
			return validpk, fmt.Errorf("CA check failed")
		}

		// validate the cert for this principal
		if err := c.CheckCert(principal, cert); err != nil {
			return validpk, fmt.Errorf("no valid principal found")
		}

		break
	}

	// validpk will be nil when we didn't find a principal matching the certificate registered in gitea
	if validpk == nil {
		return validpk, fmt.Errorf("no valid principal found")
	}

	verifier, err := httpsig.NewVerifier(r)
	if err != nil {
		return validpk, fmt.Errorf("httpsig.NewVerifier failed: %s", err)
	}

	// now verify that we signed this request with the publickey of the cert
	err = doVerify(verifier, []ssh.PublicKey{cert.Key})
	if err != nil {
		return validpk, err
	}

	return validpk, nil
}

// doVerify iterates across the provided public keys attempting the verify the current request against each key in turn
func doVerify(verifier httpsig.Verifier, publickeys []ssh.PublicKey) error {
	verified := false

	for _, pubkey := range publickeys {
		cryptoPubkey := pubkey.(ssh.CryptoPublicKey).CryptoPublicKey()

		var algos []httpsig.Algorithm

		switch {
		case strings.HasPrefix(pubkey.Type(), "ssh-ed25519"):
			algos = []httpsig.Algorithm{httpsig.ED25519}
		case strings.HasPrefix(pubkey.Type(), "ssh-rsa"):
			algos = []httpsig.Algorithm{httpsig.RSA_SHA1, httpsig.RSA_SHA256, httpsig.RSA_SHA512}
		}
		for _, algo := range algos {
			err := verifier.Verify(cryptoPubkey, algo)
			if err == nil {
				verified = true
				break
			}
		}
	}

	if verified {
		return nil
	}

	return errors.New("verification failed")
}
