package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/inconshreveable/log15"
	"github.com/psanford/tpm-ssh-ca/messages"
	"golang.org/x/crypto/ssh"
)

var (
	printEK    = flag.Bool("print-keys", false, "Print TPM EK keys and exit")
	serverURL  = flag.String("url", "http://localhost:1234", "Server url")
	socketPath = flag.String("l", "", "agent: path of the UNIX socket to listen on")
)

func main() {
	flag.Parse()

	if *socketPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	handler := log15.StreamHandler(os.Stdout, log15.LogfmtFormat())
	log15.Root().SetHandler(handler)
	lgr := log15.New()

	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		lgr.Error("open_tpm_err", "err", err)
		os.Exit(1)
	}
	defer tpm.Close()

	tpmInfo, err := tpm.Info()
	if err != nil {
		lgr.Error("get_tpm_info_err", "err", err)
		os.Exit(1)
	}
	fmt.Printf("TPM info: %+v\n", tpmInfo)

	eks, err := tpm.EKs()
	if err != nil {
		lgr.Error("get_EKs_err", "err", err)
		os.Exit(1)
	}

	if *printEK {
		for i, ek := range eks {
			fmt.Printf("%d:\n%s\n", i, keyToPem(ek.Public))
		}
		os.Exit(0)
	}

	var ek *attest.EK
	ek = &eks[0]

OUTER:
	for _, candidateEK := range eks {
		switch candidateEK.Public.(type) {
		case *ecdsa.PublicKey:
			k := candidateEK
			ek = &k
			break OUTER
		case *rsa.PublicKey:
			k := candidateEK
			ek = &k
		default:
			lgr.Warn("unexpected_ek_key_type", "type", fmt.Sprintf("%T", candidateEK.Public))
		}
	}

	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		lgr.Error("gen_ak_err", "err", err)
		os.Exit(1)
	}
	akAttestParams := ak.AttestationParameters()
	akBytes, err := ak.Marshal()
	if err != nil {
		ak.Close(tpm)
		lgr.Error("marshal_ak_err", "err", err)
		os.Exit(1)
	}
	ak.Close(tpm)

	reqChallenge := messages.RequestChallenge{
		TPMVersion:        int(attest.TPMVersion20),
		EndorsementKeyPem: keyToPem(ek.Public),
		AttestationParameters: messages.AttestationParameters{
			Public:                  akAttestParams.Public,
			UseTCSDActivationFormat: akAttestParams.UseTCSDActivationFormat,
			CreateData:              akAttestParams.CreateData,
			CreateAttestation:       akAttestParams.CreateAttestation,
			CreateSignature:         akAttestParams.CreateSignature,
		},
	}

	reqChallengeJson, err := json.Marshal(reqChallenge)
	if err != nil {
		panic(err)
	}

	resp, err := http.Post(*serverURL+"/request_challenge", "application/json", bytes.NewBuffer(reqChallengeJson))
	if err != nil {
		lgr.Error("post_challenge_err", "err", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		lgr.Error("challenge_request_err", "status", resp.StatusCode, "err", msg)
		os.Exit(1)
	}

	var challenge messages.ChallengeResponse
	err = json.NewDecoder(resp.Body).Decode(&challenge)
	if err != nil {
		lgr.Error("decode_challenge_err", "err", err)
		os.Exit(1)
	}

	encryptedCredentials := attest.EncryptedCredential{
		Credential: challenge.Credential,
		Secret:     challenge.Secret,
	}

	ak, err = tpm.LoadAK(akBytes)
	if err != nil {
		lgr.Error("load_ak_err", "err", err)
		os.Exit(1)
	}

	secret, err := ak.ActivateCredential(tpm, encryptedCredentials)
	if err != nil {
		lgr.Error("activate_credential_err", "err", err)
		os.Exit(1)
	}

	appKey, err := tpm.NewKey(ak, nil)
	if err != nil {
		lgr.Error("new_app_key_err", "err", err)
		os.Exit(1)
	}
	defer ak.Close(tpm)

	certParams := appKey.CertificationParameters()

	proof := messages.ChallengeProof{
		ChallengeID: challenge.ChallengeID,
		Secret:      secret,
		CertificationParameters: messages.CertificationParameters{
			Public:            certParams.Public,
			CreateData:        certParams.CreateData,
			CreateAttestation: certParams.CreateAttestation,
			CreateSignature:   certParams.CreateSignature,
		},
	}
	proofJson, err := json.Marshal(proof)
	if err != nil {
		panic(err)
	}

	resp, err = http.Post(*serverURL+"/prove", "application/json", bytes.NewBuffer(proofJson))
	if err != nil {
		lgr.Error("post_proof_err", "err", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		lgr.Error("proof_request_err", "status", resp.StatusCode, "err", msg)
		os.Exit(1)
	}

	var signedResp messages.SignedCert
	err = json.NewDecoder(resp.Body).Decode(&signedResp)
	if err != nil {
		lgr.Error("decode_singed_cert_err", "err", err)
		os.Exit(1)
	}

	pubKeyCert, err := parseOpenSSHPublicKey(signedResp.SignedCert)
	if err != nil {
		lgr.Error("parse_public_key_cert_err", "err", err)
		os.Exit(1)
	}

	privateKey, err := appKey.Private(appKey.Public())
	if err != nil {
		lgr.Error("get_app_private_key_err", "err", err)
		os.Exit(1)
	}

	a := Agent{
		pubKey: pubKeyCert,
		signer: privateKey,
	}

	os.Remove(*socketPath)
	l, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}

	for {
		c, err := l.Accept()
		if err != nil {
			type temporary interface {
				Temporary() bool
			}
			if err, ok := err.(temporary); ok && err.Temporary() {
				log.Println("Temporary Accept error, sleeping 1s:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatalln("Failed to accept connections:", err)
		}
		go a.serveConn(c)
	}
}

func keyToPem(key crypto.PublicKey) string {
	marshalled, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		panic(err)
	}

	canonicalPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshalled,
	})

	return string(canonicalPem)
}

func parseOpenSSHPublicKey(encoded []byte) (ssh.PublicKey, error) {
	parts := bytes.SplitN(encoded, []byte(" "), 3)
	if len(parts) < 2 {
		return nil, errors.New("public key or certificate not in OpenSSH format")
	}

	decoded, err := base64.StdEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, err
	}

	return ssh.ParsePublicKey(decoded)
}
