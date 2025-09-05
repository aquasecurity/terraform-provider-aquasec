package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/pkg/errors"
)

// Group represents a local Aqua Group
type Group struct {
	Id         int    `json:"id"`
	Name       string `json:"name,omitempty"`
	Created    string `json:"created,omitempty"`
	GroupAdmin bool   `json:"group_admin,omitempty"`
}

// GroupList contains a list of Group
type GroupList struct {
	Items []Group `json:"data,omitempty"`
}

// GetGroup - returns single Aqua Group
func (cli *Client) GetGroup(id int) (*Group, error) {
	var err error
	var response Group
	request := cli.gorequest

	apiPath := ""
	baseUrl := ""
	if cli.clientType == Saas || cli.clientType == SaasDev {
		apiPath = fmt.Sprintf("/v2/groups/%v", id)
		baseUrl = cli.tokenUrl
	} else {
		err = fmt.Errorf("GetGroup is Supported only in Aqua SaaS env")
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
	request := cli.gorequest
	apiPath := ""
	baseUrl := ""

	if cli.clientType == Saas || cli.clientType == SaasDev {
		apiPath = "/v2/groups"
		baseUrl = cli.tokenUrl
	} else {
		err = fmt.Errorf("GetGroups is Supported only in Aqua SaaS env")
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

	if cli.clientType == Saas || cli.clientType == SaasDev {
		apiPath = "/v2/groups"
		baseUrl = cli.tokenUrl
	} else {
		err = fmt.Errorf("CreateGroup is Supported only in Aqua SaaS env")
		return err
	}

	payload := make(map[string]string)
	payload["name"] = group.Name

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Post(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(payload).End()
	fmt.Sprintf(data)
	if errs != nil {
		return errors.Wrap(err, "failed creating user")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
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

	if cli.clientType == Saas || cli.clientType == SaasDev {
		apiPath = fmt.Sprintf("/v2/groups/%v", group.Id)
		baseUrl = cli.tokenUrl
	} else {
		err = fmt.Errorf("UpdateGroup is Supported only in Aqua SaaS env")
		return err
	}

	payload := make(map[string]string)
	payload["name"] = group.Name

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, data, errs := request.Put(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(payload).End()
	if errs != nil {
		return errors.Wrap(err, "failed modifying user")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}

// DeleteGroup removes a group
func (cli *Client) DeleteGroup(id string) error {
	baseUrl := ""
	apiPath := ""
	var err error

	if cli.clientType == Saas || cli.clientType == SaasDev {
		apiPath = fmt.Sprintf("/v2/groups/%v", id)
		baseUrl = cli.tokenUrl
	} else {
		err = fmt.Errorf("DeleteGroup is Supported only in Aqua SaaS env")
		return err
	}

	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
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
	baseUrl := cli.tokenUrl
	apiPath := fmt.Sprintf("/v2/groups/%v", groupId)
	var err error
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
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	request := cli.gorequest
	resp, data, errs := request.Put(baseUrl+apiPath).Set("Authorization", fmt.Sprintf("Bearer %s", cli.token)).Send(payload).End()
	if errs != nil {
		return errors.Wrap(err, "failed modifying user")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.Errorf(data)
	}
	return nil
}

func getGroupResponse(body string, operation, baseUrl, apiPath string) (Group, error) {
	var err error
	var response Group

	var saasResponse map[string]interface{}

	err = json.Unmarshal([]byte(body), &saasResponse)

	if err != nil {
		log.Printf("Error calling func %s from %s%s, %v ", operation, baseUrl, apiPath, err)
		return response, errors.Wrap(err, "could not unmarshal groups response")
	}
	data, err := json.Marshal(saasResponse["data"])

	if err == nil {
		err = json.Unmarshal(data, &response)
	}

	if err != nil {
		log.Printf("Error calling func %s from %s%s, %v ", operation, baseUrl, apiPath, err)
		return response, errors.Wrap(err, "could not unmarshal Group response")
	}

	return response, nil
}
