package client

import (
	"context"
	json "encoding/json"
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/consts"
	"github.com/parnurzeal/gorequest"
	"github.com/pkg/errors"
	"log"
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

type RoleMappingSaas struct {
	CspRole    string   `json:"csp_role"`
	SamlGroups []string `json:"saml_groups"`
	Id         int      `json:"id"`
	Created    string   `json:"created"`
	AccountId  int      `json:"account_id"`
}

type RoleMappingSaasList struct {
	Items []RoleMappingSaas `json:"data"`
}

type RoleMappingSaasResponse struct {
	RoleMappingSaas RoleMappingSaas `json:"data"`
}

// GetSSO - returns Aqua SSO
func (cli *Client) GetSSO() (*SSO, error) {
	var err error
	var response SSO

	res, err := cli.getSsoBasic(consts.SamlSettingsApiPath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(res), &response.Saml)
	if err != nil {
		log.Printf("Error calling func GetSSO from %s%s, %v ", cli.url, consts.SamlSettingsApiPath, err)
		return nil, errors.Wrap(err, "could not unmarshal SAML response")
	}

	res, err = cli.getSsoBasic(consts.OIDCSettingsApiPath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(res), &response.OAuth2)
	if err != nil {
		log.Printf("Error calling func GetSSO from %s%s, %v ", cli.url, consts.OIDCSettingsApiPath, err)
		return nil, errors.Wrap(err, "could not unmarshal oAuth2 response")
	}

	res, err = cli.getSsoBasic(consts.OpenIdSettingsApiPath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(res), &response.OpenId)
	if err != nil {
		log.Printf("Error calling func GetSSO from %s%s, %v ", cli.url, consts.OpenIdSettingsApiPath, err)
		return nil, errors.Wrap(err, "could not unmarshal OpenId response")
	}

	return &response, err
}

// GetIntegrationState - returns SSO enable state
func (cli *Client) GetIntegrationState() (*IntegrationState, error) {
	var err error
	var response IntegrationState
	request := gorequest.New()
	request.Clone()
	request.Data = nil

	apiPath := ""
	baseUrl := ""

	switch cli.clientType {
	case Csp:
		apiPath = "/api/v2/integrationsEnabledState"
		baseUrl = cli.url
		request.Set("Authorization", "Bearer "+cli.token)
	case SaasDev:
		err = fmt.Errorf("GetSSO is Supported only in Aqua on prem env")
		return nil, err
	case Saas:
		err = fmt.Errorf("GetSSO is Supported only in Aqua on prem env")
		return nil, err
	default:
		err = fmt.Errorf("GetSSO is Supported only in Aqua on prem env")
		return nil, err
	}
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Get(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}

	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetIntegrationState from %s%s, %v ", cli.url, apiPath, err)
			return nil, errors.Wrap(err, "could not unmarshal SSOs response")
		}
	}
	return &response, err
}

// CreateSSO - creates Aqua SSO
func (cli *Client) CreateSSO(SSO *SSO) error {
	var err error
	if SSO.Saml.RoleMapping != nil && len(SSO.Saml.RoleMapping) > 0 {
		err = cli.createSsoBasic(consts.SamlSettingsApiPath, SSO.Saml)
		if err != nil {
			return err
		}
	}

	if SSO.OAuth2.RoleMapping != nil && len(SSO.OAuth2.RoleMapping) > 0 {
		err = cli.createSsoBasic(consts.OIDCSettingsApiPath, SSO.OAuth2)
		if err != nil {
			return err
		}
	}

	if SSO.OpenId.RoleMapping != nil && len(SSO.OpenId.RoleMapping) > 0 {
		err = cli.createSsoBasic(consts.OpenIdSettingsApiPath, SSO.OpenId)
		if err != nil {
			return err
		}
	}

	return nil
}

// UpdateSSO updates an existing SSO
func (cli *Client) UpdateSSO(SSO *SSO) error {
	return cli.CreateSSO(SSO)
}

// DeleteSSO removes a SSO
func (cli *Client) DeleteSSO(SSO *SSO) error {
	return cli.CreateSSO(SSO)
}

// getSsoBasic
func (cli *Client) getSsoBasic(apiPath string) (string, error) {
	baseUrl := ""
	var err error
	request := gorequest.New()
	request.Clone()
	request.Data = nil

	switch cli.clientType {
	case Csp:
		baseUrl = cli.url
		request.Set("Authorization", "Bearer "+cli.token)
	case SaasDev:
		err = fmt.Errorf("GetSSO is Supported only in Aqua on prem env")
		return "", err
	case Saas:
		err = fmt.Errorf("GetSSO is Supported only in Aqua on prem env")
		return "", err
	default:
		err = fmt.Errorf("GetSSO is Supported only in Aqua on prem env")
		return "", err
	}

	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return "", err
	}
	events, body, errs := request.Get(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return "", err
	}

	if events.StatusCode != 200 {
		return "", nil
	}
	return body, nil
}

// createSsoBasic
func (cli *Client) createSsoBasic(apiPath string, sso interface{}) error {
	payload, err := json.Marshal(sso)
	if err != nil {
		return err
	}
	baseUrl := ""
	request := gorequest.New()
	request.Clone()
	request.Data = nil

	switch cli.clientType {
	case Csp:
		baseUrl = cli.url
		request.Set("Authorization", "Bearer "+cli.token)
	case SaasDev:
		err = fmt.Errorf("GetSSO is Supported only in Aqua on prem env")
		return err
	case Saas:
		err = fmt.Errorf("GetSSO is Supported only in Aqua on prem env")
		return err
	default:
		err = fmt.Errorf("GetSSO is Supported only in Aqua on prem env")
		return err
	}

	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	events, _, errs := request.Put(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(string(payload)).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s, error: %v", apiPath, err)
		return err
	}

	if events.StatusCode != 200 && events.StatusCode != 204 {
		err = fmt.Errorf(fmt.Sprintf("Bad response form the following api %s, error: %v", apiPath, events.Body))
		return err
	}
	return nil
}

// GetRoleMappingSass - returns Aqua RoleMappingSaas
func (cli *Client) GetRoleMappingSass(id string) (*RoleMappingSaas, error) {
	var err error
	var response RoleMappingSaas
	baseUrl := ""
	apiPath := fmt.Sprintf("/v2/samlmappings/%s", id)
	switch cli.clientType {
	case Csp:
		err = fmt.Errorf("GetRoleMappingSass is Supported only in Aqua SASS env")
		return nil, err
	case SaasDev:
		baseUrl = consts.SaasDevTokenUrl
	case Saas:
		baseUrl = consts.SaasTokenUrl
	default:
		err = fmt.Errorf("GetRoleMappingSass is Supported only in Aqua SASS env")
		return nil, err
	}

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}

	events, body, errs := request.Get(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}

	if events.StatusCode != 200 {
		return nil, fmt.Errorf("error calling %s, error: %s", apiPath, body)
	}

	err = json.Unmarshal([]byte(body), &response)
	if err != nil {
		log.Printf("Error calling func GetRolesMappingSass from %s%s, %v ", baseUrl, apiPath, err)
		return nil, errors.Wrap(err, "could not unmarshal roleMappingSaas response")
	}

	return &response, nil

}

// GetRolesMappingSass - returns Aqua RoleMappingSaas
func (cli *Client) GetRolesMappingSass() (*RoleMappingSaasList, error) {
	var err error
	var response RoleMappingSaasList
	baseUrl := ""
	apiPath := "/v2/samlmappings"

	switch cli.clientType {
	case Csp:
		err = fmt.Errorf("GetRolesMappingSass is Supported only in Aqua SASS env")
		return nil, err
	case SaasDev:
		baseUrl = consts.SaasDevTokenUrl
	case Saas:
		baseUrl = consts.SaasTokenUrl
	default:
		err = fmt.Errorf("GetRolesMappingSass is Supported only in Aqua SASS env")
		return nil, err
	}

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}

	events, body, errs := request.Get(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}

	if events.StatusCode != 200 {
		return nil, fmt.Errorf("error calling %s, error: %s", apiPath, body)
	}

	err = json.Unmarshal([]byte(body), &response)
	if err != nil {
		log.Printf("Error calling func GetRolesMappingSass from %s%s, %v ", baseUrl, apiPath, err)
		return nil, errors.Wrap(err, "could not unmarshal roleMappingSaasList response")
	}

	return &response, nil

}

func (cli *Client) CreateRoleMappingSaas(saas *RoleMappingSaas) error {
	var err error
	var roleMappingResponse RoleMappingSaasResponse
	baseUrl := ""
	apiPath := "/v2/samlmappings"

	switch cli.clientType {
	case Csp:
		err = fmt.Errorf("GetRolesMappingSass is Supported only in Aqua SASS env")
		return err
	case SaasDev:
		baseUrl = consts.SaasDevTokenUrl
	case Saas:
		baseUrl = consts.SaasTokenUrl
	default:
		err = fmt.Errorf("GetRolesMappingSass is Supported only in Aqua SASS env")
		return err
	}
	saasTmp := map[string]interface{}{
		"csp_role":    saas.CspRole,
		"saml_groups": saas.SamlGroups,
	}

	payload, err := json.Marshal(saasTmp)

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}

	events, body, errs := request.Post(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(string(payload)).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return err
	}

	if events.StatusCode != 201 {
		return fmt.Errorf("error calling %s, error: %s", apiPath, body)
	}

	err = json.Unmarshal([]byte(body), &roleMappingResponse)
	if err != nil {
		log.Printf("Error calling func GetRolesMappingSass from %s%s, %v ", baseUrl, apiPath, err)
		return errors.Wrap(err, "could not unmarshal roleMappingSaas response")
	}
	saas.Id = roleMappingResponse.RoleMappingSaas.Id
	saas.AccountId = roleMappingResponse.RoleMappingSaas.AccountId
	saas.Created = roleMappingResponse.RoleMappingSaas.Created
	return nil
}

func (cli *Client) UpdateRoleMappingSaas(saas *RoleMappingSaas, id string) error {
	var err error
	baseUrl := ""
	apiPath := fmt.Sprintf("/v2/samlmappings/%s", id)

	switch cli.clientType {
	case Csp:
		err = fmt.Errorf("GetRolesMappingSass is Supported only in Aqua SASS env")
		return err
	case SaasDev:
		baseUrl = consts.SaasDevTokenUrl
	case Saas:
		baseUrl = consts.SaasTokenUrl
	default:
		err = fmt.Errorf("GetRolesMappingSass is Supported only in Aqua SASS env")
		return err
	}
	saasTmp := map[string]interface{}{
		"saml_groups": saas.SamlGroups,
	}

	payload, err := json.Marshal(saasTmp)
	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}

	events, body, errs := request.Put(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(string(payload)).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return err
	}

	if events.StatusCode != 200 {
		return fmt.Errorf("error calling %s, error: %s", apiPath, body)
	}

	//err = json.Unmarshal([]byte(body), &saas)
	//if err != nil {
	//	log.Printf("Error calling func GetRolesMappingSass from %s%s, %v ", baseUrl, apiPath, err)
	//	return errors.Wrap(err, "could not unmarshal roleMappingSaas response")
	//}

	return nil
}

// DeleteRoleMappingSass - returns Aqua RoleMappingSaas
func (cli *Client) DeleteRoleMappingSass(id string) error {
	var err error
	baseUrl := ""
	apiPath := fmt.Sprintf("/v2/samlmappings/%s", id)
	switch cli.clientType {
	case Csp:
		err = fmt.Errorf("GetRoleMappingSass is Supported only in Aqua SASS env")
		return err
	case SaasDev:
		baseUrl = consts.SaasDevTokenUrl
	case Saas:
		baseUrl = consts.SaasTokenUrl
	default:
		err = fmt.Errorf("GetRoleMappingSass is Supported only in Aqua SASS env")
		return err
	}

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}

	events, body, errs := request.Delete(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return err
	}

	if events.StatusCode != 200 {
		return fmt.Errorf("error calling %s, error: %s", apiPath, body)
	}

	return nil

}
