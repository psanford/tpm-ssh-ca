package config

import (
	"log"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

type ServerConfig struct {
	CA    CA     `hcl:"ca,block"`
	Users []User `hcl:"user,block"`
}

type CA struct {
	PrivateKey string `hcl:"private_key"`
}

type User struct {
	ID              string   `hcl:"id,label"`
	Principals      []string `hcl:"principals,optional"`
	EndorsementKeys []string `hcl:"endorsement_keys"`
}

func Load(configPath string) *ServerConfig {
	var config ServerConfig
	err := hclsimple.DecodeFile(configPath, nil, &config)
	if err != nil {
		log.Fatalf("Failed to load configuration: %s", err)
	}
	return &config
}
