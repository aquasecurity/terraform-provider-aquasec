package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	neturl "net/url"

	"github.com/aquasecurity/terraform-provider-aquasec/consts"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/net/http/httpproxy"
	"golang.org/x/time/rate"
)

// Client - API client
type Client struct {
	url        string
	saasUrl    string
	tokenUrl   string
	user       string
	password   string
	token      string
	name       string
	gorequest  *gorequest.SuperAgent
	clientType string
	limiter    *rate.Limiter
}

const Csp string = "csp"
const Saas = "saas"
const SaasDev = "saasDev"

const UserAgentBase = "terraform-provider-aquasec"

var version string

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

	request := gorequest.New().TLSClientConfig(tlsConfig)

	c := &Client{
		url:       url,
		user:      user,
		password:  password,
		gorequest: request,
		// we are setting rate limit for 10 connection per second
		limiter: rate.NewLimiter(10, 3),
	}

	// Determine if we need to use a proxy
	uURL, _ := neturl.Parse(c.url)
	proxy, _ := httpproxy.FromEnvironment().ProxyFunc()(uURL)
	if proxy != nil {
		c.gorequest.Proxy(proxy.String())
	}

	switch url {
	case consts.SaasUrl:
		c.clientType = Saas
		c.tokenUrl = consts.SaasTokenUrl
		c.saasUrl = consts.SaasUrl
		break
	case consts.SaasEu1Url:
		c.clientType = Saas
		c.tokenUrl = consts.SaasEu1TokenUrl
		c.saasUrl = consts.SaasEu1Url
		break
	case consts.SaasAsia1Url:
		c.clientType = Saas
		c.tokenUrl = consts.SaasAsia1TokenUrl
		c.saasUrl = consts.SaasAsia1Url
		break
	case consts.SaasAsia2Url:
		c.clientType = Saas
		c.tokenUrl = consts.SaasAsia2TokenUrl
		c.saasUrl = consts.SaasAsia2Url
		break
	case consts.SaaSAu2Url:
		c.clientType = Saas
		c.tokenUrl = consts.SaasAu2TokenUrl
		c.saasUrl = consts.SaaSAu2Url
		break
	case consts.SaasDevUrl:
		c.clientType = SaasDev
		c.tokenUrl = consts.SaasDevTokenUrl
		c.saasUrl = consts.SaasDevUrl
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
	}

	if err != nil {
		return "", "", err
	}
	return cli.token, cli.url, nil
}

// GetAuthToken - Connect to Aqua and return a JWT bearerToken (string)
func (cli *Client) GetCspAuthToken() (string, error) {
	resp, body, errs := cli.makeRequest().Post(cli.url + "/api/v1/login").
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

func (cli *Client) makeRequest() *gorequest.SuperAgent {
	userAgent := fmt.Sprintf("%s/%s", UserAgentBase, version)
	return cli.gorequest.Clone().Set("User-Agent", userAgent)
}
