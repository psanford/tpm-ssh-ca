package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/inconshreveable/log15"
	"github.com/psanford/lambdahttp/lambdahttpv2"
	"github.com/psanford/logmiddleware"
	"github.com/psanford/tpm-ssh-ca/messages"
	"github.com/psanford/tpm-ssh-ca/sshcaserver/config"
	"github.com/retailnext/unixtime"
	"golang.org/x/crypto/ssh"
)

var (
	addr    = flag.String("listen-addr", "127.0.0.1:1234", "Host/Port to listen on")
	cliMode = flag.String("mode", "http", "execution mode: http|lambda")

	configPath = flag.String("config", "sshcaserver.hcl", "Path to server config")
)

func main() {
	flag.Parse()

	handler := log15.StreamHandler(os.Stdout, log15.LogfmtFormat())
	log15.Root().SetHandler(handler)
	lgr := log15.New()

	conf := config.Load(*configPath)

	caKey, err := ssh.ParsePrivateKey([]byte(conf.CA.PrivateKey))
	if err != nil {
		lgr.Error("parse_ssh_ca_key_err", "err", err)
		os.Exit(1)
	}

	s := &server{
		challenges: make(map[string]*pendingChallenge),
		keyToUser:  make(map[string]*userKey),
		caKey:      caKey,
	}

	for _, user := range conf.Users {
		for _, pubPem := range user.EndorsementKeys {
			pubPem = strings.TrimSpace(pubPem)
			key, err := parseKey(pubPem)
			if err != nil {
				lgr.Error("parse_key_err", "key", pubPem, "user", user.ID, "err", err)
				os.Exit(1)
			}

			canonicalPem, err := keyToPem(key)
			if err != nil {
				lgr.Error("key_to_pem_err", "key", pubPem, "user", user.ID, "err", err)
				os.Exit(1)
			}

			user := user
			s.keyToUser[string(canonicalPem)] = &userKey{
				user: &user,
				ek:   key,
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/request_challenge", s.challengeHandler)
	mux.HandleFunc("/prove", s.proofHandler)

	h := logmiddleware.New(mux)

	switch *cliMode {
	case "http":
		fmt.Printf("Listening on %s\n", *addr)
		panic(http.ListenAndServe(*addr, h))
	default:
		lambda.Start(lambdahttpv2.NewLambdaHandler(h))
	}
}

type server struct {
	caKey     ssh.Signer
	keyToUser map[string]*userKey

	mu         sync.Mutex
	challenges map[string]*pendingChallenge
}

type userKey struct {
	user *config.User
	ek   crypto.PublicKey
}

type pendingChallenge struct {
	ek     crypto.PublicKey
	ak     crypto.PublicKey
	akHash crypto.Hash
	secret []byte
}

func (s *server) challengeHandler(w http.ResponseWriter, r *http.Request) {
	lgr := logmiddleware.LgrFromContext(r.Context())
	var req messages.RequestChallenge
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		lgr.Error("decode_json_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	params := req.AttestationParameters
	ak := attest.AttestationParameters{
		Public:                  params.Public,
		UseTCSDActivationFormat: params.UseTCSDActivationFormat,
		CreateData:              params.CreateData,
		CreateAttestation:       params.CreateAttestation,
		CreateSignature:         params.CreateSignature,
	}

	ek, err := parseKey(req.EndorsementKeyPem)
	if err != nil {
		lgr.Error("parse_ek_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	akActivationParams := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion(req.TPMVersion),
		EK:         ek,
		AK:         ak,
	}

	secret, encryptedCredentials, err := akActivationParams.Generate()
	if err != nil {
		lgr.Error("generate_challenge_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	tpmKey, err := tpm2.DecodePublic(ak.Public)
	if err != nil {
		lgr.Error("parse_tpm2_ak_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	akPubKey, err := tpmKey.Key()
	if err != nil {
		lgr.Error("get_ak_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	hash, err := tpmKey.RSAParameters.Sign.Hash.Hash()
	if err != nil {
		lgr.Error("get_ak_hash_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()

	challengeIDBytes := make([]byte, 20)
	rand.Read(challengeIDBytes)

	challengeID := hex.EncodeToString(challengeIDBytes)
	s.challenges[challengeID] = &pendingChallenge{
		ek:     ek,
		ak:     akPubKey,
		akHash: hash,
		secret: secret,
	}
	s.mu.Unlock()

	resp := messages.ChallengeResponse{
		ChallengeID: challengeID,
		Credential:  encryptedCredentials.Credential,
		Secret:      encryptedCredentials.Secret,
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *server) proofHandler(w http.ResponseWriter, r *http.Request) {
	lgr := logmiddleware.LgrFromContext(r.Context())
	var proof messages.ChallengeProof
	err := json.NewDecoder(r.Body).Decode(&proof)
	if err != nil {
		lgr.Error("decode_json_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	pending := s.challenges[proof.ChallengeID]
	delete(s.challenges, proof.ChallengeID)
	s.mu.Unlock()

	if pending == nil {
		lgr.Error("no_key_found_for_secret")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if subtle.ConstantTimeCompare(proof.Secret, pending.secret) != 1 {
		lgr.Error("bad_secret")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	canonicalPem, err := keyToPem(pending.ek)
	if err != nil {
		lgr.Error("key_to_pem_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	user := s.keyToUser[canonicalPem]
	if user == nil {
		lgr.Error("user_not_found")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	params := proof.CertificationParameters
	certParams := attest.CertificationParameters{
		Public:            params.Public,
		CreateData:        params.CreateData,
		CreateAttestation: params.CreateAttestation,
		CreateSignature:   params.CreateSignature,
	}

	err = certParams.Verify(attest.VerifyOpts{
		Public: pending.ak,
		Hash:   pending.akHash,
	})
	if err != nil {
		lgr.Error("verify_app_key_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	tpmKey, err := tpm2.DecodePublic(certParams.Public)
	if err != nil {
		lgr.Error("parse_tpm2_app_key_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	appPubKey, err := tpmKey.Key()
	if err != nil {
		lgr.Error("get_app_key_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	sshKey, err := ssh.NewPublicKey(appPubKey)
	if err != nil {
		lgr.Error("ak_to_ssh_public_key_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username := user.user.ID
	keyID := fmt.Sprintf("%s-%d", username, unixtime.ToUnix(time.Now(), time.Millisecond))

	principals := user.user.Principals
	if principals == nil {
		principals = []string{username}
	}

	serialBytes := make([]byte, 8)
	rand.Read(serialBytes)
	serial := binary.BigEndian.Uint64(serialBytes)

	lgr = lgr.New("username", username, "key_id", keyID, "principals", principals, "serial", serial)

	expires := time.Now().Add(24 * time.Hour)
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             sshKey,
		KeyId:           keyID,
		Serial:          serial,
		ValidAfter:      uint64(time.Now().Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(expires.Unix()),
		ValidPrincipals: principals,
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}
	err = cert.SignCert(rand.Reader, s.caKey)
	if err != nil {
		lgr.Error("sign_cert_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	lgr.Info("cert_issued", "valid_before", expires, "fingerprint", ssh.FingerprintSHA256(cert.Key))

	signedKey := ssh.MarshalAuthorizedKey(cert)

	resp := messages.SignedCert{
		SignedCert: signedKey,
	}
	json.NewEncoder(w).Encode(&resp)
}

func parseKey(keyPem string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(keyPem))
	if block == nil {
		return nil, errors.New("decode pem fail")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key err: %w", err)
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("unsupported public key type")
	}
}

func keyToPem(key crypto.PublicKey) (string, error) {
	marshalled, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal pkix err: %w", err)
	}

	canonicalPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshalled,
	})

	return string(canonicalPem), nil
}
