package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/aquasecurity/terraform-provider-aquasec/consts"
	"github.com/parnurzeal/gorequest"
)

// Client - API client
type Client struct {
	url        string
	user       string
	password   string
	token      string
	name       string
	gorequest  *gorequest.SuperAgent
	clientType string
}

const Csp string = "csp"
const Saas = "saas"
const SaasDev = "saasDev"

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

	proxy := os.Getenv("https_proxy")
	if len(proxy) > 0 {
		c.gorequest.Proxy(proxy)
	}

	switch url {
	case "https://cloud.aquasec.com":
		c.clientType = Saas
		break
	case "https://cloud-dev.aquasec.com":
		c.clientType = SaasDev
		break
	default:
		c.clientType = Csp
		break
	}

	return c
}

func (cli *Client) SetAuthToken(token string) {
	cli.token = token
}

func (cli *Client) SetUrl(url string) {
	cli.url = url
}

func (cli *Client) GetAuthToken() (string, string, error) {
	var err error

	if cli.clientType == "csp" {
		_, err = cli.GetCspAuthToken()
	} else {
		_, _, err = cli.GetUSEAuthToken()
	}

	if err != nil {
		return "", "", err
	}
	return cli.token, cli.url, nil
}

// GetAuthToken - Connect to Aqua and return a JWT bearerToken (string)
func (cli *Client) GetCspAuthToken() (string, error) {
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
func (cli *Client) GetUSEAuthToken() (string, string, error) {
	tokenUrl := consts.SaasTokenUrl
	provUrl := consts.SaasProvUrl

	if cli.clientType == "saasDev" {
		tokenUrl = consts.SaasDevTokenUrl
		provUrl = consts.SaasDevProvUrl
	}

	resp, body, errs := cli.gorequest.Post(tokenUrl + "/v2/signin").
		Send(`{"email":"` + cli.user + `", "password":"` + cli.password + `"}`).End()
	if errs != nil {
		return "", "", getMergedError(errs)
	}

	if resp.StatusCode == 200 {
		var raw map[string]interface{}
		_ = json.Unmarshal([]byte(body), &raw)
		data := raw["data"].(map[string]interface{})
		cli.token = data["token"].(string)
		//get the ese_url to make the API requests.
		request := cli.gorequest
		request.Set("Authorization", "Bearer "+cli.token)
		events, body, errs := request.Clone().Get(provUrl + "/v1/envs").End()

		if errs != nil {
			log.Println(events.StatusCode)
			err := fmt.Errorf("error calling %s", provUrl)
			return "", "", err
		}

		if events.StatusCode == 200 {
			var raw map[string]interface{}
			_ = json.Unmarshal([]byte(body), &raw)
			data := raw["data"].(map[string]interface{})
			cli.url = "https://" + data["ese_url"].(string)
		}

		return cli.token, cli.url, nil
	}

	return "", "", fmt.Errorf("request failed. status: %s, response: %s", resp.Status, body)
}
