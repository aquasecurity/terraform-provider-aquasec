package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/pkg/errors"
)

type ApplicationScope struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Author      string   `json:"author"`
	OwnerEmail  string   `json:"owner_email"`
	Categories  Category `json:"categories"`
}

type Category struct {
	Artifacts      Artifact       `json:"artifacts"`
	Workloads      Workload       `json:"workloads"`
	Infrastructure Infrastructure `json:"infrastructure"`
	EntityScope    CommonStruct   `json:"entity_scope"`
}

type Artifact struct {
	Image    CommonStruct `json:"image"`
	Function CommonStruct `json:"function"`
	CF       CommonStruct `json:"cf"`
	CodeBuild CommonStruct `json:"codebuild"`
}

type Workload struct {
	Kubernetes CommonStruct `json:"kubernetes"`
	OS         CommonStruct `json:"os"`
	WCF        CommonStruct `json:"cf"`
}

type Infrastructure struct {
	IKubernetes CommonStruct `json:"kubernetes"`
	IOS         CommonStruct `json:"os"`
}

type CommonStruct struct {
	Expression string      `json:"expression"`
	Variables  []Variables `json:"variables"`
}

type Variables struct {
	Attribute string `json:"attribute"`
	Value     string `json:"value"`
	Name      string `json:"name"`
}

// Get Application Scope
func (cli *Client) GetApplicationScope(name string) (*ApplicationScope, error) {
	var err error
	var response ApplicationScope
	var baseUrl = cli.url

	cli.gorequest.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v2/access_management/scopes/%s", name)

	if cli.clientType == Saas || cli.clientType == SaasDev {
		baseUrl = cli.saasUrl + "/api"
		apiPath = fmt.Sprintf("/access_mgmt/scopes/%s", name)
	}

	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, body, errs := cli.gorequest.Clone().Get(baseUrl + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting Application Scopes")
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetApplicationScope from %s%s, %v ", baseUrl, apiPath, err)
			return nil, err
		}
	} else {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return nil, err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return nil, err
		}
		return nil, fmt.Errorf("failed getting Application Scope. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	if response.Name == "" {
		return nil, fmt.Errorf("application Scope: %s not found 404", name)
	}
	return &response, err
}

// CreateApplicationScope - creates single Aqua Application Scope
func (cli *Client) CreateApplicationScope(applicationscope *ApplicationScope) error {
	baseUrl := cli.url
	apiPath := fmt.Sprintf("/api/v2/access_management/scopes")
	request := cli.gorequest

	if cli.clientType == Saas || cli.clientType == SaasDev {
		baseUrl = cli.saasUrl + "/api"
		apiPath = "/access_mgmt/scopes"
	}

	payload, err := json.Marshal(applicationscope)
	if err != nil {
		return err
	}

	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Post(baseUrl + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed creating Application Scope.")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed creating Application Scope. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// UpdateApplicationScope updates an existing Application Scope
func (cli *Client) UpdateApplicationScope(applicationscope *ApplicationScope, name string) error {
	payload, err := json.Marshal(applicationscope)
	if err != nil {
		return err
	}
	baseUrl := cli.url
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/access_management/scopes/%s", name)

	if cli.clientType == Saas || cli.clientType == SaasDev {
		baseUrl = cli.saasUrl + "/api"
		apiPath = "/access_mgmt/scopes"
	}

	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(baseUrl + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed modifying Application Scope")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed modifying Application Scope. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// DeleteApplicationScope removes a Application Scope
func (cli *Client) DeleteApplicationScope(name string) error {
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/access_management/scopes/%s", name)
	baseUrl := cli.url

	if cli.clientType == Saas || cli.clientType == SaasDev {
		baseUrl = cli.saasUrl + "/api"
		apiPath = fmt.Sprintf("/access_mgmt/scopes/%s", name)
	}

	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(baseUrl + apiPath).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed deleting Application Scope")
	}
	if resp.StatusCode != 204 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed deleting Application Scope, status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}
