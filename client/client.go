package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/parnurzeal/gorequest"
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
