package aquasec

import (
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

func init() {
	log.Println("setup suite")
	var (
		present, verifyTLS                                       bool
		username, password, aquaURL, verifyTLSString, caCertPath string
		err                                                      error
		caCertByte                                               []byte
	)

	username, present = os.LookupEnv("AQUA_USER")
	if !present {
		panic("AQUA_USER env is missing, please set it")
	}

	password, present = os.LookupEnv("AQUA_PASSWORD")
	if !present {
		panic("AQUA_PASSWORD env is missing, please set it")
	}

	aquaURL, present = os.LookupEnv("AQUA_URL")
	if !present {
		panic("AQUA_URL env is missing, please set it")
	}

	verifyTLSString, present = os.LookupEnv("AQUA_TLS_VERIFY")
	if !present {
		verifyTLSString = "true"
	}

	caCertPath, present = os.LookupEnv("AQUA_CA_CERT_PATH")
	if present {
		if caCertPath != "" {
			caCertByte, err = ioutil.ReadFile(caCertPath)
			if err != nil {
				panic("Unable to read CA certificates")
			}
		}
		panic("AQUA_CA_CERT_PATH env is missing, please set it")
	}

	verifyTLS, _ = strconv.ParseBool(verifyTLSString)

	aquaClient := client.NewClient(aquaURL, username, password, verifyTLS, caCertByte)
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
