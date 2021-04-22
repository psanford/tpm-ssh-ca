package messages

type RequestChallenge struct {
	TPMVersion            int                   `json:"tpm_version"`
	EndorsementKeyPem     string                `json:"endorsement_key"`
	AttestationParameters AttestationParameters `json:"attestation_parameters"`
}

type AttestationParameters struct {
	Public                  []byte `json:"public"`
	UseTCSDActivationFormat bool   `json:"use_tcsd_activation_format"`
	CreateData              []byte `json:"create_data"`
	CreateAttestation       []byte `json:"create_attestation"`
	CreateSignature         []byte `json:"create_signature"`
}

type ChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Credential  []byte `json:"credential"`
	Secret      []byte `json:"secret"`
}

type ChallengeProof struct {
	ChallengeID             string                  `json:"challenge_id"`
	Secret                  []byte                  `json:"secret"`
	CertificationParameters CertificationParameters `json:"certification_parameters"`
}

type SignedCert struct {
	SignedCert []byte `json:"signed_cert"`
}

type CertificationParameters struct {
	Public            []byte
	CreateData        []byte
	CreateAttestation []byte
	CreateSignature   []byte
}
