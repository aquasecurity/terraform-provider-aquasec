package client

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/consts"
	"github.com/parnurzeal/gorequest"
	"log"
)

type Ldap struct {
	AccountAttrName     string              `json:"account_attr_name"`
	BaseDn              string              `json:"base_dn"`
	Cacert              string              `json:"cacert"`
	DisplaynameAttrName string              `json:"displayname_attr_name"`
	DnAttrName          string              `json:"dn_attr_name"`
	Domain              string              `json:"domain"`
	Enable              bool                `json:"enable"`
	GroupAttrName       string              `json:"group_attr_name"`
	GroupNameAttrName   string              `json:"group_name_attr_name"`
	GroupObjectClass    string              `json:"group_object_class"`
	ObjectClass         string              `json:"object_class"`
	Password            string              `json:"password"`
	Port                string              `json:"port"`
	RoleMapping         map[string][]string `json:"role_mapping"`
	Ssl                 bool                `json:"ssl"`
	Type                string              `json:"type"`
	User                string              `json:"user"`
	UserMemberAttrName  string              `json:"user_member_attr_name"`
	VerifyCert          bool                `json:"verify_cert"`
}

func (cli *Client) GetLdap() (*Ldap, error) {
	var err error
	var response Ldap

	baseUrl := ""
	apiPath := consts.LdapSettingsApiPath
	request := gorequest.New()
	request.Clone()
	request.Data = nil

	switch cli.clientType {
	case Csp:
		baseUrl = cli.url
		request.Set("Authorization", "Bearer "+cli.token)
	case SaasDev:
		err = fmt.Errorf("GetLdap is Supported only in Aqua on prem env")
		return nil, err
	case Saas:
		err = fmt.Errorf("GetLdap is Supported only in Aqua on prem env")
		return nil, err
	default:
		err = fmt.Errorf("GetLdap is Supported only in Aqua on prem env")
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

	if events.StatusCode != 200 {
		return nil, nil
	}

	err = json.Unmarshal([]byte(body), &response)
	if err != nil {
		log.Printf("Error calling func GetLdap from %s%s, %v ", cli.url, apiPath, err)
		return nil, err
	}
	return &response, nil
}

func (cli *Client) CreateLdap(ldap *Ldap) error {

	if ldap.RoleMapping != nil && len(ldap.RoleMapping) > 0 {
		payload, err := json.Marshal(ldap)
		if err != nil {
			return err
		}
		baseUrl := ""
		apiPath := consts.LdapSettingsApiPath
		request := gorequest.New()
		request.Clone()
		request.Data = nil

		switch cli.clientType {
		case Csp:
			baseUrl = cli.url
			request.Set("Authorization", "Bearer "+cli.token)
		case SaasDev:
			err = fmt.Errorf("CreateLdap is Supported only in Aqua on prem env")
			return err
		case Saas:
			err = fmt.Errorf("CreateLdap is Supported only in Aqua on prem env")
			return err
		default:
			err = fmt.Errorf("CreateLdap is Supported only in Aqua on prem env")
			return err
		}

		err = cli.limiter.Wait(context.Background())
		if err != nil {
			return err
		}
		events, _, errs := request.Post(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(string(payload)).End()

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

	return nil
}

func (cli *Client) UpdateLdap(ldap *Ldap) error {
	return cli.CreateLdap(ldap)
}

func (cli *Client) DeleteLdap(ldap *Ldap) error {
	return cli.CreateLdap(ldap)
}
