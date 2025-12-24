package client

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	neturl "net/url"
	"strings"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/consts"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/net/http/httpproxy"
	"golang.org/x/time/rate"
)

// Client - API client
type Client struct {
	url              string
	saasUrl          string
	tokenUrl         string
	saasScpUrl       string
	user             string
	password         string
	token            string
	name             string
	aqua_api_key     string
	aqua_api_secret  string
	useAPIKey        bool
	gorequest        *gorequest.SuperAgent
	clientType       string
	limiter          *rate.Limiter
	Validity         int
	AllowedEndpoints []string
	CSPRoles         []string
}

const Csp string = "csp"
const Saas = "saas"
const SaasDev = "saasDev"

const UserAgentBase = "terraform-provider-aquasec"

var version string

func NewClientWithTokenAuth(urlStr, user, password string, verifyTLS bool, caCertByte []byte) (*Client, error) {
	return NewClient(urlStr, user, password, "", "", false, verifyTLS, caCertByte)
}

func NewClientWithAPIKey(urlStr, apiKey, secretkey string, verifyTLS bool, caCertByte []byte) (*Client, error) {
	if strings.TrimSpace(apiKey) == "" || strings.TrimSpace(secretkey) == "" {
		return nil, fmt.Errorf("api key auth requires both aqua_api_key and aqua_api_secret")
	}
	return NewClient(urlStr, "", "", apiKey, secretkey, true, verifyTLS, caCertByte)
}

// NewClient - initialize and return the Client
func NewClient(url, user, password, apiKey, secretkey string, useAPIKey, verifyTLS bool, caCertByte []byte) (*Client, error) {
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
		url:             url,
		user:            user,
		password:        password,
		gorequest:       request,
		aqua_api_key:    apiKey,
		aqua_api_secret: secretkey,
		useAPIKey:       useAPIKey,
		// we are setting rate limit for 10 connection per second
		limiter:          rate.NewLimiter(10, 3),
		Validity:         1500,
		AllowedEndpoints: []string{"ANY"},
		CSPRoles:         []string{"Admin"},
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
		c.saasScpUrl = consts.SaasSupplyChainUrl
		break
	case consts.SaasEu1Url:
		c.clientType = Saas
		c.tokenUrl = consts.SaasEu1TokenUrl
		c.saasUrl = consts.SaasEu1Url
		c.saasScpUrl = consts.SaasSupplyChainUrl
		break
	case consts.SaasAsia1Url:
		c.clientType = Saas
		c.tokenUrl = consts.SaasAsia1TokenUrl
		c.saasUrl = consts.SaasAsia1Url
		c.saasScpUrl = consts.SaasSupplyChainUrl
		break
	case consts.SaasAsia2Url:
		c.clientType = Saas
		c.tokenUrl = consts.SaasAsia2TokenUrl
		c.saasUrl = consts.SaasAsia2Url
		c.saasScpUrl = consts.SaasSupplyChainUrl
		break
	case consts.SaaSAu2Url:
		c.clientType = Saas
		c.tokenUrl = consts.SaasAu2TokenUrl
		c.saasUrl = consts.SaaSAu2Url
		c.saasScpUrl = consts.SaasSupplyChainUrl
		break
	case consts.SaasDevUrl:
		c.clientType = SaasDev
		c.tokenUrl = consts.SaasDevTokenUrl
		c.saasUrl = consts.SaasDevUrl
		c.saasScpUrl = consts.SaasSupplyChainUrl
		break
	default:
		c.clientType = Csp
		break
	}

	return c, nil
}

func (cli *Client) AuthenticateWithAPIKey() (string, error) {
	apiPath := "/v2/tokens"

	var provUrl string

	switch cli.url {
	case consts.SaasUrl:
		provUrl = consts.SaasProvUrl
		break
	case consts.SaasEu1Url:
		provUrl = consts.SaasEu1ProvUrl
		break
	case consts.SaasAsia1Url:
		provUrl = consts.SaasAsia1ProvUrl
		break
	case consts.SaasAsia2Url:
		provUrl = consts.SaasAsia2ProvUrl
		break
	case consts.SaaSAu2Url:
		provUrl = consts.SaasAu2ProvUrl
		break
	default:
		return "", fmt.Errorf("%v URL is not allowed USE url", cli.url)
	}
	reqBody := map[string]interface{}{
		"validity":          cli.Validity,
		"allowed_endpoints": cli.AllowedEndpoints,
		"csp_roles":         cli.CSPRoles,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %v", err)
	}
	agent, errs := cli.signedRequest("POST", cli.tokenUrl+apiPath, jsonBody)
	if errs != nil {
		return "", errs
	}
	resp, body, err1 := agent.Post(cli.tokenUrl + apiPath).Send(string(jsonBody)).SetDebug(true).End()
	if err1 != nil {
		return "", getMergedError(err1)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("API key token request failed: status %s, body %s", resp.Status, body)
	}
	if resp.StatusCode == 200 {
		var raw map[string]interface{}
		_ = json.Unmarshal([]byte(body), &raw)
		data, ok := raw["data"]
		if !ok {
			return "", fmt.Errorf("response missing data field: %v", raw)
		}
		if token, isStr := data.(string); isStr {
			cli.token = token
		}
		//get the ese_url to make the API requests.
		request := cli.gorequest
		if request == nil {
			return "", fmt.Errorf("request is uninitialized")
		}

		request.Set("Authorization", "Bearer "+cli.token)
		events, body, errs := request.Clone().Get(provUrl + "/v1/envs").End()
		if errs != nil || events == nil {
			if events != nil {
				log.Println(events.StatusCode)
			}
			err := fmt.Errorf("error calling %s", provUrl)
			return "", err
		}

		if events.StatusCode == 200 {
			var raw map[string]interface{}
			_ = json.Unmarshal([]byte(body), &raw)
			data := raw["data"].(map[string]interface{})
			cli.url = "https://" + data["ese_url"].(string)
		}
	}
	return cli.token, nil
}

func (cli *Client) SetAuthToken(token string) {
	cli.token = token
}

func (cli *Client) SetUrl(url string) {
	cli.url = url
}

func (cli *Client) GetAuthToken() (string, string, error) {
	var err error

	if cli.useAPIKey {
		if cli.token != "" {
			return cli.token, cli.url, nil
		}
		tok, err := cli.AuthenticateWithAPIKey()
		if err != nil {
			return "", "", err
		}
		return tok, cli.url, nil
	}
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

// GetUSEAuthToken - Connect to Aqua SaaS solution and return a JWT bearerToken (string)
func (cli *Client) GetUSEAuthToken() (string, string, error) {
	var provUrl string

	switch cli.url {
	case consts.SaasUrl:
		provUrl = consts.SaasProvUrl
		break
	case consts.SaasEu1Url:
		provUrl = consts.SaasEu1ProvUrl
		break
	case consts.SaasAsia1Url:
		provUrl = consts.SaasAsia1ProvUrl
		break
	case consts.SaasAsia2Url:
		provUrl = consts.SaasAsia2ProvUrl
		break
	case consts.SaaSAu2Url:
		provUrl = consts.SaasAu2ProvUrl
		break
	case consts.SaasDevUrl:
		provUrl = consts.SaasDevProvUrl
		break
	default:
		return "", "", fmt.Errorf("%v URL is not allowed USE url", cli.url)
	}

	resp, body, errs := cli.makeRequest().Post(cli.tokenUrl + "/v2/signin").
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
		if request == nil {
			return "", "", fmt.Errorf("request is uninitialized")
		}

		request.Set("Authorization", "Bearer "+cli.token)
		events, body, errs := request.Clone().Get(provUrl + "/v1/envs").End()
		if errs != nil || events == nil {
			if events != nil {
				log.Println(events.StatusCode)
			}
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

func (cli *Client) makeRequest() *gorequest.SuperAgent {
	userAgent := fmt.Sprintf("%s/%s", UserAgentBase, version)
	return cli.gorequest.Clone().Set("User-Agent", userAgent)
}

func (cli *Client) signedRequest(method, fullURL string, body []byte) (*gorequest.SuperAgent, error) {
	u, err := url.Parse(fullURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url %q: %w", fullURL, err)
	}
	path := u.Path
	methodUpper := strings.ToUpper(method)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	bodyStr := ""
	if len(body) > 0 {
		bodyStr = string(body)
	}

	payload := timestamp + methodUpper + path + bodyStr

	mac := hmac.New(sha256.New, []byte(cli.aqua_api_secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	agent := cli.gorequest.Clone()
	agent.Set("X-API-Key", cli.aqua_api_key)
	agent.Set("X-Timestamp", timestamp)
	agent.Set("X-Signature", sig)

	return agent, nil
}
