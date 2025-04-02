package client

import (
	"context"
	json "encoding/json"
	"fmt"
	"log"

	"github.com/aquasecurity/terraform-provider-aquasec/consts"
	"github.com/pkg/errors"
)

type Saml struct {
	AquaCredsEnable bool                `json:"aqua_creds_enable"`
	AssertionUrl    string              `json:"assertion_url"`
	AuthByRole      bool                `json:"auth_by_role"`
	Enabled         bool                `json:"enabled"`
	Idpissuer       string              `json:"idpissuer"`
	Idpslourl       string              `json:"idpslourl"`
	IdpSSOurl       string              `json:"idpssourl"`
	LogoutUrl       string              `json:"logout_url"`
	RoleMapping     map[string][]string `json:"role_mapping"`
	SignedRequest   bool                `json:"signed_request"`
	SloEnabled      bool                `json:"slo_enabled"`
	SpId            string              `json:"sp_id"`
	SSOEnable       bool                `json:"sso_enable"`
	TokenProvided   bool                `json:"token_provided"`
	UserLoginid     string              `json:"user_loginid"`
	UserRole        string              `json:"user_role"`
	X509cert        string              `json:"x509cert"`
}

type OAuth2 struct {
	Enabled     bool                `json:"enabled"`
	IssUrl      string              `json:"iss_url"`
	JwksUrl     string              `json:"jwks_url"`
	RoleMapping map[string][]string `json:"role_mapping"`
	UserLoginid string              `json:"user_loginid"`
	UserRole    string              `json:"user_role"`
}

type OpenId struct {
	AuthByRole   bool                `json:"auth_by_role"`
	ClientId     string              `json:"client_id"`
	Enabled      bool                `json:"enabled"`
	IdpUrl       string              `json:"idp_url"`
	ProviderName string              `json:"provider_name"`
	RedirectUrl  string              `json:"redirect_url"`
	RoleMapping  map[string][]string `json:"role_mapping"`
	Scopes       []string            `json:"scopes"`
	Secret       string              `json:"secret"`
	User         string              `json:"user"`
	UserRole     string              `json:"user_role"`
}

type SSO struct {
	Saml   Saml   `json:"saml"`
	OAuth2 OAuth2 `json:"oauth2"`
	OpenId OpenId `json:"open_id"`
}

type IntegrationState struct {
	OIDCSettings   bool `json:"OIDCSettings"`
	OpenIdSettings bool `json:"OpenIdSettings"`
	SAMLSettings   bool `json:"SAMLSettings"`
}

func (cli *Client) GetSSO() (*SSO, error) {
	var response SSO

	res, err := cli.getSsoBasic(consts.SamlSettingsApiPath)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(res), &response.Saml); err != nil {
		log.Printf("Error parsing SAML config: %v", err)
		return nil, errors.Wrap(err, "could not unmarshal SAML response")
	}

	res, err = cli.getSsoBasic(consts.OIDCSettingsApiPath)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(res), &response.OAuth2); err != nil {
		log.Printf("Error parsing OAuth2 config: %v", err)
		return nil, errors.Wrap(err, "could not unmarshal OAuth2 response")
	}

	res, err = cli.getSsoBasic(consts.OpenIdSettingsApiPath)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(res), &response.OpenId); err != nil {
		log.Printf("Error parsing OpenId config: %v", err)
		return nil, errors.Wrap(err, "could not unmarshal OpenId response")
	}

	return &response, nil
}

func (cli *Client) CreateSSO(sso *SSO) error {
	if sso.Saml.RoleMapping != nil {
		if err := cli.createSsoBasic(consts.SamlSettingsApiPath, sso.Saml); err != nil {
			return err
		}
	}
	if sso.OAuth2.RoleMapping != nil {
		if err := cli.createSsoBasic(consts.OIDCSettingsApiPath, sso.OAuth2); err != nil {
			return err
		}
	}
	if sso.OpenId.RoleMapping != nil {
		if err := cli.createSsoBasic(consts.OpenIdSettingsApiPath, sso.OpenId); err != nil {
			return err
		}
	}
	return nil
}

func (cli *Client) UpdateSSO(sso *SSO) error {
	return cli.CreateSSO(sso)
}

func (cli *Client) DeleteSSO(sso *SSO) error {
	return cli.CreateSSO(sso)
}

func (cli *Client) getSsoBasic(apiPath string) (string, error) {
	if cli.clientType != Csp {
		return "", fmt.Errorf("GetSSO is supported only in Aqua on-prem environment")
	}
	if err := cli.limiter.Wait(context.Background()); err != nil {
		return "", err
	}
	resp, body, errs := cli.gorequest.Get(cli.url + apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).End()
	if errs != nil {
		return "", fmt.Errorf("failed GET %s: %v", apiPath, errs)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("bad response from %s: %s", apiPath, body)
	}
	return body, nil
}

func (cli *Client) createSsoBasic(apiPath string, sso interface{}) error {
	payload, err := json.Marshal(sso)
	if err != nil {
		return err
	}
	if cli.clientType != Csp {
		return fmt.Errorf("CreateSSO is supported only in Aqua on-prem environment")
	}
	if err := cli.limiter.Wait(context.Background()); err != nil {
		return err
	}
	resp, _, errs := cli.gorequest.Put(cli.url + apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(string(payload)).End()
	if errs != nil {
		return fmt.Errorf("failed PUT %s: %v", apiPath, errs)
	}
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("bad response from %s: %v", apiPath, resp.StatusCode)
	}
	return nil
}

func (cli *Client) GetIntegrationState() (*IntegrationState, error) {
	if cli.clientType != Csp {
		return nil, fmt.Errorf("GetIntegrationState is supported only in Aqua on-prem environment")
	}
	if err := cli.limiter.Wait(context.Background()); err != nil {
		return nil, err
	}
	resp, body, errs := cli.gorequest.Get(cli.url + "/api/v2/integrationsEnabledState").Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).End()
	if errs != nil {
		return nil, fmt.Errorf("error calling integrations state API")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected response status: %s", body)
	}

	var state IntegrationState
	if err := json.Unmarshal([]byte(body), &state); err != nil {
		log.Printf("Error parsing integration state: %v", err)
		return nil, errors.Wrap(err, "could not unmarshal integration state")
	}
	return &state, nil
}