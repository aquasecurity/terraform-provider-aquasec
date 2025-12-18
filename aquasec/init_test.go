package aquasec

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
)

func init() {
	log.Println("setup suite")
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
		panic("AQUA_URL env is missing or empty, please set it")
	}

	apiKey = os.Getenv("AQUA_API_KEY")
	secretKey = os.Getenv("AQUA_API_SECRET")
	useAPIKeyStr = os.Getenv("AQUA_USE_API_KEY")
	useAPIKey = false

	// Check if AQUA_USE_API_KEY is explicitly set
	if useAPIKeyStr != "" {
		var err error
		useAPIKey, err = strconv.ParseBool(useAPIKeyStr)
		if err != nil {
			panic(fmt.Sprintf("Invalid boolen for AQUA_USE_API_KEY: %v", err))
		}
	} else {
		// Auto-detect: use API key auth if API key credentials are provided
		if apiKey != "" && secretKey != "" {
			useAPIKey = true
		}
	}

	// Get credentials based on auth method
	if useAPIKey {
		if apiKey == "" {
			panic("AQUA_API_KEY env is missing or empty, please set it when using API key authentication")
		}
		if secretKey == "" {
			panic("AQUA_API_SECRET env is missing or empty, please set it when using API key authentication")
		}
	} else {
		username, present = os.LookupEnv("AQUA_USER")
		if !present || username == "" {
			panic("AQUA_USER env is missing or empty, please set it (or use AQUA_API_KEY and AQUA_API_SECRET for API key auth)")
		}

		password, present = os.LookupEnv("AQUA_PASSWORD")
		if !present || password == "" {
			panic("AQUA_PASSWORD env is missing or empty, please set it (or use AQUA_API_KEY and AQUA_API_SECRET for API key auth)")
		}
	}

	verifyTLSString, present = os.LookupEnv("AQUA_TLS_VERIFY")
	if !present {
		verifyTLSString = "true"
	}
	verifyTLS, _ = strconv.ParseBool(verifyTLSString)

	caCertPath, present = os.LookupEnv("AQUA_CA_CERT_PATH")
	if present {
		if caCertPath != "" {
			caCertByte, err = os.ReadFile(caCertPath)
			if err != nil {
				panic("Unable to read CA certificates")
			}
		}
	}

	var aquaClient *client.Client
	if useAPIKey {
		aquaClient, err = client.NewClientWithAPIKey(aquaURL, apiKey, secretKey, verifyTLS, caCertByte)
		if err != nil {
			panic(fmt.Errorf("failed to create client with api key auth, error: %s", err))
		}
	} else {
		aquaClient, err = client.NewClientWithTokenAuth(aquaURL, username, password, verifyTLS, caCertByte)
		if err != nil {
			panic(fmt.Errorf("failed to create client with token auth, error: %s", err))
		}
	}
	token, url, err := aquaClient.GetAuthToken()

	if err != nil {
		panic(fmt.Errorf("failed to receive token, error: %s", err))
	}

	err = os.Setenv("TESTING_AUTH_TOKEN", token)
	if err != nil {
		panic("Failed to set AUTH_TOKEN env")
	}

	err = os.Setenv("TESTING_URL", url)
	if err != nil {
		panic("Failed to set TESTING_URL env")
	}
	log.Println("Finished to set token")

}
