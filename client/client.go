package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/parnurzeal/gorequest"
	"log"
	"strings"
)

// Client - API client
type Client struct {
	url       string
	user      string
	password  string
	token     string
	name      string
	gorequest *gorequest.SuperAgent
}

// NewClient - initialize and return the Client
func NewClient(url, user, password string, verifyTLS bool, caCertByte []byte) *Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !verifyTLS,
	}

	roots := x509.NewCertPool()
	if len(caCertByte) > 0 {
		roots.AppendCertsFromPEM(caCertByte)

		if verifyTLS {
			tlsConfig = &tls.Config{
				RootCAs: roots,
			}
		}
	}

	c := &Client{
		url:       url,
		user:      user,
		password:  password,
		gorequest: gorequest.New().TLSClientConfig(tlsConfig),
	}
	return c
}

// GetAuthToken - Connect to Aqua and return a JWT bearerToken (string)
// Return: bool - successfully connected?
func (cli *Client) GetAuthToken() (string, error) {
	resp, body, errs := cli.gorequest.Post(cli.url + "/api/v1/login").
		Send(`{"id":"` + cli.user + `", "password":"` + cli.password + `"}`).End()
	if errs != nil {
		return "", getMergedError(errs)
	}

	if resp.StatusCode == 200 {
		var raw map[string]interface{}
		_ = json.Unmarshal([]byte(body), &raw)
		cli.token = raw["token"].(string)
		return cli.token, nil
	}

	return "", fmt.Errorf("request failed. status: %s, response: %s", resp.Status, body)
}

// GetUSEAuthToken - Connect to Aqua SaaS solution and return a JWT bearerToken (string)
// Return: bool - successfully connected?
func (cli *Client) GetUSEAuthToken() (string, error) {
	token_url := ""
	prov_url := ""

	if strings.Contains(cli.url, "d.cloud.aquasec.com") {
		token_url = "https://stage.api.cloudsploit.com"
		prov_url = "https://prov-dev.cloud.aquasec.com"
	} else {
		token_url = "https://api.cloudsploit.com"
		prov_url = "https://prov.cloud.aquasec.com"
	}
	resp, body, errs := cli.gorequest.Post(token_url + "/v2/signin").
		Send(`{"email":"` + cli.user + `", "password":"` + cli.password + `"}`).End()
	if errs != nil {
		return "", getMergedError(errs)
	}

	if resp.StatusCode == 200 {
		var raw map[string]interface{}
		_ = json.Unmarshal([]byte(body), &raw)
		data := raw["data"].(map[string]interface{})
		cli.token = data["token"].(string)
		//get the ese_url to make the API requests.
		request := cli.gorequest
		request.Set("Authorization", "Bearer "+cli.token)
		events, body, errs := request.Clone().Get(prov_url + "/v1/envs").End()

		if errs != nil {
			log.Println(events.StatusCode)
			err := fmt.Errorf("error calling %s", prov_url)
			return "", err
		}

		if events.StatusCode == 200 {
			var raw map[string]interface{}
			_ = json.Unmarshal([]byte(body), &raw)
			data := raw["data"].(map[string]interface{})
			cli.url = "https://" + data["ese_url"].(string)
		}

		return cli.token, nil
	}

	return "", fmt.Errorf("request failed. status: %s, response: %s", resp.Status, body)
}
