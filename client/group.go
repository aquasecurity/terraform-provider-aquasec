package client

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/consts"
	"github.com/parnurzeal/gorequest"
	"github.com/pkg/errors"
	"log"
)

// Group represents a local Aqua Group
type Group struct {
	Id      int    `json:"id"`
	Name    string `json:"name,omitempty"`
	Created string `json:"created,omitempty"`
}

// GroupList contains a list of Group
type GroupList struct {
	Items []Group `json:"data,omitempty"`
}

// GetGroup - returns single Aqua Group
func (cli *Client) GetGroup(id int) (*Group, error) {
	var err error
	var response Group
	request := gorequest.New()
	request.Clone()
	request.Data = nil

	apiPath := ""
	baseUrl := ""

	switch cli.clientType {
	case Csp:
		err = fmt.Errorf("GetGroup is Supported only in Auaa SAAS")
		return nil, err
	case SaasDev:
		apiPath = fmt.Sprintf("/v2/groups/%v", id)
		baseUrl = consts.SaasDevTokenUrl
	case Saas:
		apiPath = fmt.Sprintf("/v2/groups/%v", id)
		baseUrl = consts.SaasTokenUrl
	default:
		err = fmt.Errorf("GetGroups is Supported only in Auaa SAAS")
		return nil, err
	}
	events, body, errs := request.Get(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).End()

	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}

	if events.StatusCode == 200 {
		response, err = getGroupResponse(body, "GetGroup", baseUrl, apiPath)
		if err != nil {
			return nil, err
		}
	}
	return &response, err
}

// GetGroups - returns all Aqua GroupList
func (cli *Client) GetGroups() ([]Group, error) {
	var err error
	var response GroupList
	request := gorequest.New()
	request.Clone()
	request.Data = nil

	apiPath := ""
	baseUrl := ""

	switch cli.clientType {
	case Csp:
		err = fmt.Errorf("GetGroups is Supported only in Auaa SAAS")
		return nil, err
	case SaasDev:
		apiPath = "/v2/groups"
		baseUrl = consts.SaasDevTokenUrl
	case Saas:
		apiPath = "/v2/groups"
		baseUrl = consts.SaasTokenUrl
	default:
		err = fmt.Errorf("GetGroups is Supported only in Auaa SAAS")
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
			log.Printf("Error calling func GetGroups from %s%s, %v ", cli.url, apiPath, err)
			return nil, errors.Wrap(err, "could not unmarshal groups response")
		}
	}
	return response.Items, err
}

// CreateGroup - creates single Aqua group
func (cli *Client) CreateGroup(group *Group) error {
	baseUrl := ""
	apiPath := ""
	var err error

	switch cli.clientType {
	case Csp:
		err = fmt.Errorf("GetGroup is Supported only in Auaa SAAS")
		return err
	case SaasDev:
		apiPath = "/v2/groups"
		baseUrl = consts.SaasDevTokenUrl
	case Saas:
		apiPath = "/v2/groups"
		baseUrl = consts.SaasTokenUrl
	default:
		err = fmt.Errorf("GetGroups is Supported only in Auaa SAAS")
		return err
	}

	payload := make(map[string]string)
	payload["name"] = group.Name

	request := cli.gorequest
	resp, data, errs := request.Post(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(payload).End()
	fmt.Sprintf(data)
	if errs != nil {
		return errors.Wrap(err, "failed creating user")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		if err == nil {
			err = fmt.Errorf(data)
		}
		return err
	}
	dataGroup, err := getGroupResponse(data, "CreateGroup", baseUrl, apiPath)

	if err != nil {
		return err
	}
	group.Id = dataGroup.Id
	return nil
}

// UpdateGroup updates an existing group
func (cli *Client) UpdateGroup(group *Group) error {
	baseUrl := ""
	apiPath := ""
	var err error

	switch cli.clientType {
	case Csp:
		err = fmt.Errorf("GetGroup is Supported only in Auaa SAAS")
		return err
	case SaasDev:
		apiPath = fmt.Sprintf("/v2/groups/%v", group.Id)
		baseUrl = consts.SaasDevTokenUrl
	case Saas:
		apiPath = fmt.Sprintf("/v2/groups/%v", group.Id)
		baseUrl = consts.SaasTokenUrl
	default:
		err = fmt.Errorf("GetGroups is Supported only in Auaa SAAS")
		return err
	}

	payload := make(map[string]string)
	payload["name"] = group.Name

	request := cli.gorequest
	resp, data, errs := request.Put(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(payload).End()
	if errs != nil {
		return errors.Wrap(err, "failed modifying user")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		if err == nil {
			err = fmt.Errorf(data)
		}
		return err
	}
	return nil
}

// DeleteGroup removes a group
func (cli *Client) DeleteGroup(id string) error {
	baseUrl := ""
	apiPath := ""
	var err error

	switch cli.clientType {
	case Csp:
		err = fmt.Errorf("GetGroup is Supported only in Auaa SAAS")
		return err
	case SaasDev:
		apiPath = fmt.Sprintf("/v2/groups/%v", id)
		baseUrl = consts.SaasDevTokenUrl
	case Saas:
		apiPath = fmt.Sprintf("/v2/groups/%v", id)
		baseUrl = consts.SaasTokenUrl
	default:
		err = fmt.Errorf("GetGroups is Supported only in Auaa SAAS")
		return err
	}
	request := cli.gorequest

	events, _, errs := request.Delete(baseUrl+apiPath).Set("Authorization", "Bearer "+cli.token).End()
	if errs != nil {
		return fmt.Errorf("error while calling DELETE on %s%s, status: %v", baseUrl, apiPath, events.StatusCode)
	}
	if events.StatusCode != 204 && events.StatusCode != 200 {
		return fmt.Errorf("failed deleting group name: %s, status code: %v", id, events.StatusCode)
	}
	return nil
}

// ManageUserGroups removes a group
func (cli *Client) ManageUserGroups(groupId, userId int, groupAdmin bool, operation string) error {
	baseUrl := ""
	apiPath := ""
	var err error

	if cli.clientType == Saas {
		baseUrl = consts.SaasTokenUrl
		apiPath = fmt.Sprintf("/v2/groups/%v", groupId)
	}

	if cli.clientType == SaasDev {
		baseUrl = consts.SaasDevTokenUrl
		apiPath = fmt.Sprintf("/v2/groups/%v", groupId)
	}
	payload := make(map[string]interface{})

	switch operation {
	case "add":
		payload["action"] = "adding"
		payload["group_admin"] = groupAdmin
		payload["user_id"] = userId
	case "remove":
		payload["action"] = "removing"
		payload["user_id"] = userId
	}

	request := cli.gorequest
	resp, data, errs := request.Put(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(payload).End()
	if errs != nil {
		return errors.Wrap(err, "failed modifying user")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		if err == nil {
			err = fmt.Errorf(data)
		}
		return err
	}
	return nil
}

func getGroupResponse(body string, operation, baseUrl, apiPath string) (Group, error) {
	var err error
	var response Group

	var sassResponse map[string]interface{}

	err = json.Unmarshal([]byte(body), &sassResponse)

	if err != nil {
		log.Printf("Error calling func %s from %s%s, %v ", operation, baseUrl, apiPath, err)
		return response, errors.Wrap(err, "could not unmarshal groups response")
	}
	data, err := json.Marshal(sassResponse["data"])

	if err == nil {
		err = json.Unmarshal(data, &response)
	}

	if err != nil {
		log.Printf("Error calling func %s from %s%s, %v ", operation, baseUrl, apiPath, err)
		return response, errors.Wrap(err, "could not unmarshal Group response")
	}

	return response, nil
}
