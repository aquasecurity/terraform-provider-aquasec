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
	if !present {
		panic("AQUA_URL env is missing, please set it")
	}

	apiKey = os.Getenv("AQUA_API_KEY")
	secretKey = os.Getenv("AQUA_API_SECRET")
	useAPIKeyStr = os.Getenv("AQUA_USE_API_KEY")
	useAPIKey = false
	if useAPIKeyStr != "" {
		var err error
		useAPIKey, err = strconv.ParseBool(useAPIKeyStr)
		if err != nil {
			panic(fmt.Sprintf("Invalid boolen for AQUA_USE_API_KEY: %v", err))
		}
	}

	if !useAPIKey {
		username, present = os.LookupEnv("AQUA_USER")
		if !present {
			panic("AQUA_USER env is missing, please set it")
		}

		password, present = os.LookupEnv("AQUA_PASSWORD")
		if !present {
			panic("AQUA_PASSWORD env is missing, please set it")
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
		aquaClient = client.NewClientWithAPIKey(aquaURL, apiKey, secretKey, verifyTLS, caCertByte)
	} else {
		aquaClient = client.NewClientWithTokenAuth(aquaURL, username, password, verifyTLS, caCertByte)
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
