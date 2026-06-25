package aquasec

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
)

var (
	acceptanceTestAuthOnce sync.Once
	acceptanceTestAuthErr  error
)

func ensureAcceptanceTestAuth() error {
	acceptanceTestAuthOnce.Do(func() {
		log.Println("setup acceptance test auth")

		var (
			present                                          bool
			username, password, aquaURL                      string
			verifyTLS, useAPIKey                             bool
			verifyTLSString, apiKey, secretKey, useAPIKeyStr string
			caCertPath                                       string
			err                                              error
			caCertByte                                       []byte
		)

		aquaURL, present = os.LookupEnv("AQUA_URL")
		if !present || aquaURL == "" {
			acceptanceTestAuthErr = fmt.Errorf("AQUA_URL env is missing or empty, please set it")
			return
		}

		apiKey = os.Getenv("AQUA_API_KEY")
		secretKey = os.Getenv("AQUA_API_SECRET")
		useAPIKeyStr = os.Getenv("AQUA_USE_API_KEY")

		if useAPIKeyStr != "" {
			useAPIKey, err = strconv.ParseBool(useAPIKeyStr)
			if err != nil {
				acceptanceTestAuthErr = fmt.Errorf("invalid boolean for AQUA_USE_API_KEY: %w", err)
				return
			}
		} else if apiKey != "" && secretKey != "" {
			useAPIKey = true
		}

		if useAPIKey {
			if apiKey == "" {
				acceptanceTestAuthErr = fmt.Errorf("AQUA_API_KEY env is missing or empty, please set it when using API key authentication")
				return
			}
			if secretKey == "" {
				acceptanceTestAuthErr = fmt.Errorf("AQUA_API_SECRET env is missing or empty, please set it when using API key authentication")
				return
			}
		} else {
			username, present = os.LookupEnv("AQUA_USER")
			if !present || username == "" {
				acceptanceTestAuthErr = fmt.Errorf("AQUA_USER env is missing or empty, please set it (or use AQUA_API_KEY and AQUA_API_SECRET for API key auth)")
				return
			}

			password, present = os.LookupEnv("AQUA_PASSWORD")
			if !present || password == "" {
				acceptanceTestAuthErr = fmt.Errorf("AQUA_PASSWORD env is missing or empty, please set it (or use AQUA_API_KEY and AQUA_API_SECRET for API key auth)")
				return
			}
		}

		verifyTLSString, present = os.LookupEnv("AQUA_TLS_VERIFY")
		if !present {
			verifyTLSString = "true"
		}
		verifyTLS, _ = strconv.ParseBool(verifyTLSString)

		caCertPath, present = os.LookupEnv("AQUA_CA_CERT_PATH")
		if present && caCertPath != "" {
			caCertByte, err = os.ReadFile(caCertPath)
			if err != nil {
				acceptanceTestAuthErr = fmt.Errorf("unable to read CA certificates: %w", err)
				return
			}
		}

		var aquaClient *client.Client
		if useAPIKey {
			aquaClient, err = client.NewClientWithAPIKey(aquaURL, apiKey, secretKey, verifyTLS, caCertByte)
			if err != nil {
				acceptanceTestAuthErr = fmt.Errorf("failed to create client with api key auth: %w", err)
				return
			}
		} else {
			aquaClient, err = client.NewClientWithTokenAuth(aquaURL, username, password, verifyTLS, caCertByte)
			if err != nil {
				acceptanceTestAuthErr = fmt.Errorf("failed to create client with token auth: %w", err)
				return
			}
		}

		token, url, err := aquaClient.GetAuthToken()
		if err != nil {
			acceptanceTestAuthErr = fmt.Errorf("failed to receive token: %w", err)
			return
		}

		if err = os.Setenv("TESTING_AUTH_TOKEN", token); err != nil {
			acceptanceTestAuthErr = fmt.Errorf("failed to set AUTH_TOKEN env: %w", err)
			return
		}
		if err = os.Setenv("TESTING_URL", url); err != nil {
			acceptanceTestAuthErr = fmt.Errorf("failed to set TESTING_URL env: %w", err)
			return
		}

		log.Println("finished setting acceptance test token")
	})

	return acceptanceTestAuthErr
}
