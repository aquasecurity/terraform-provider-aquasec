package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
)

type SuppressionRule struct {
	ID                int      `json:"id,omitempty"`
	Name              string   `json:"name,omitempty"`
	ApplicationScopes []string `json:"application_scopes,omitempty"`
	Scope             *Scope   `json:"scope,omitempty"`
	Score             []int    `json:"score"`
	Severity          string   `json:"severity,omitempty"`
	FixAvailable      string   `json:"fix_available,omitempty"`
	Vulnerabilities   string   `json:"vulnerabilities,omitempty"`
	Expiry            int      `json:"expiry,omitempty"`
	Comment           string   `json:"comment,omitempty"`
	Created           string   `json:"created,omitempty"`
	Author            string   `json:"author,omitempty"`
	Status            bool     `json:"status,omitempty"`
}

type SuppressionRuleResponse struct {
	Count            int               `json:"count"`
	Page             int               `json:"page"`
	PageSize         int               `json:"pagesize"`
	SuppressionRules []SuppressionRule `json:"result"`
}

type CreateSuppressionRuleResponse struct {
	ID int `json:"rule_id"`
}

func (cli *Client) GetSuppressionRules() ([]SuppressionRule, error) {

	var err error
	var response SuppressionRuleResponse

	var suppressionRules []SuppressionRule
	var totalPages = 1
	var page = 1

	for page <= totalPages {
		request := cli.gorequest
		apiPath := fmt.Sprintf("/api/v2/images/ack_suppression_rules/search?page=%d", page)
		err = cli.limiter.Wait(context.Background())
		if err != nil {
			return nil, err
		}
		resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
		if errs != nil {
			err = fmt.Errorf("error calling %s", apiPath)
			return nil, err
		}
		if resp.StatusCode == 200 {
			err = json.Unmarshal([]byte(body), &response)
			if err != nil {
				log.Printf("Error calling func GetSuppressionRules from %s%s, %v ", cli.url, apiPath, err)
				return nil, err
			}
			suppressionRules = append(suppressionRules, response.SuppressionRules...)
			totalPages = response.Count/response.PageSize + 1
			page++
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
			return nil, fmt.Errorf("failed getting SuppressionRules status: %v. error message: %v", resp.Status, errorResponse.Message)
		}
	}
	return suppressionRules, nil
}

func (cli *Client) GetSuppressionRule(id string) (*SuppressionRule, error) {

	var err error
	var response SuppressionRuleResponse

	request := cli.gorequest
	//request.Set(")
	apiPath := fmt.Sprintf("/api/v2/images/ack_suppression_rules/search?rule_id=%s", id)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return nil, err
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetSuppressionRule from %s%s, %v ", cli.url, apiPath, err)
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
		return nil, fmt.Errorf("failed getting SuppressionRule status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	if len(response.SuppressionRules) == 0 {
		return nil, fmt.Errorf("SuppressionRule not found")
	}
	return &response.SuppressionRules[0], nil
}

func (cli *Client) CreateSuppressionRule(suppressionRule SuppressionRule) (int, error) {

	var err error
	var response CreateSuppressionRuleResponse

	request := cli.gorequest.Clone()
	request.Set("Authorization", "Bearer "+cli.token)
	request.Type("json")
	request.Send(suppressionRule)
	apiPath := "/api/v2/images/ack_suppression_rules/add"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return 0, err
	}
	events, body, errs := request.Clone().Post(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return 0, err
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func CreateSuppressionRule from %s%s, %v ", cli.url, apiPath, err)
			return 0, err
		}
	}
	if events.StatusCode != 200 || response.ID == 0 {
		body, err := io.ReadAll(events.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return 0, err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return 0, err
		}
		return 0, fmt.Errorf("failed creating SuppressionRule status: %v. error message: %v", events.StatusCode, errorResponse.Message)
	}
	return response.ID, nil
}

func (cli *Client) UpdateSuppressionRule(suppressionRule SuppressionRule) error {

	var err error

	request := cli.gorequest.Clone()
	request.Set("Authorization", "Bearer "+cli.token)
	request.Type("json")
	request.Send(suppressionRule)
	apiPath := "/api/v2/images/ack_suppression_rules/update"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	events, _, errs := request.Clone().Put(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return err
	}
	if events.StatusCode != 204 {
		body, err := io.ReadAll(events.Body)
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
		return fmt.Errorf("failed updating SuppressionRule status: %v. error message: %v", events.StatusCode, errorResponse.Message)
	}
	return nil
}

func (cli *Client) DeleteSuppressionRule(id string) error {

	var err error

	request := cli.gorequest.Clone()
	request.Set("Authorization", "Bearer "+cli.token)
	request.Send(`[` + id + `]`)
	apiPath := "/api/v2/images/ack_suppression_rules/delete"
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	events, _, errs := request.Clone().Delete(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return err
	}
	if events.StatusCode != 204 {
		body, err := io.ReadAll(events.Body)
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
		return fmt.Errorf("failed deleting SuppressionRule status: %v. error message: %v", events.StatusCode, errorResponse.Message)
	}
	return nil
}

func (cli *Client) ActivateSuppressionRule(id string) error {

	var err error

	request := cli.gorequest.Clone()
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v2/images/ack_suppression_rules/activate/%s", id)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	events, _, errs := request.Clone().Put(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return err
	}
	if events.StatusCode != 204 {
		body, err := io.ReadAll(events.Body)
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
		return fmt.Errorf("failed activating SuppressionRule status: %v. error message: %v", events.StatusCode, errorResponse.Message)
	}
	return nil
}

func (cli *Client) DisableSuppressionRule(id string) error {

	var err error

	request := cli.gorequest.Clone()
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v2/images/ack_suppression_rules/disable/%s", id)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	events, _, errs := request.Clone().Put(cli.url + apiPath).End()
	if errs != nil {
		err = fmt.Errorf("error calling %s", apiPath)
		return err
	}
	if events.StatusCode != 204 {
		body, err := io.ReadAll(events.Body)
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
		return fmt.Errorf("failed disabling SuppressionRule status: %v. error message: %v", events.StatusCode, errorResponse.Message)
	}
	return nil
}
