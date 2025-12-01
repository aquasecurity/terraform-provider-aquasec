package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"
)

type SuppressionRule struct {
	PolicyID            string                       `json:"policy_id,omitempty"`
	Name                string                       `json:"name"`
	Description         string                       `json:"description,omitempty"`
	Enable              bool                         `json:"enable"`
	Created             *time.Time                   `json:"created,omitempty"`
	Updated             *time.Time                   `json:"updated,omitempty"`
	CreatedBy           string                       `json:"created_by,omitempty"`
	UpdatedBy           string                       `json:"updated_by,omitempty"`
	Enforce             bool                         `json:"enforce,omitempty"`
	FailBuild           bool                         `json:"fail_build,omitempty"`
	FailPR              bool                         `json:"fail_pr,omitempty"`
	EnforcementSchedule string                       `json:"enforcement_schedule,omitempty"`
	ClearSchedule       bool                         `json:"clear_schedule,omitempty"`
	PolicyType          PolicyType                   `json:"policy_type,omitempty"`
	Controls            []BuildSecuritypolicyControl `json:"controls,omitempty"`
	Scope               BuildSecurityPolicyScope     `json:"scope,omitempty"`
	ApplicationScopes   []string                     `json:"application_scopes"`
}

type BuildSecuritypolicyControl struct {
	Type             PolicyControlType `json:"type,omitempty"`
	ScanType         ScanType          `json:"scan_type,omitempty"`
	Provider         string            `json:"provider,omitempty"`
	Service          string            `json:"service,omitempty"`
	DependencyName   string            `json:"dependency_name,omitempty"`
	Version          string            `json:"version,omitempty"`
	DependencySource string            `json:"dependency_source,omitempty"`
	Operator         Operator          `json:"operator,omitempty"`
	Severity         Severity          `json:"severity,omitempty"`
	VendorFix        bool              `json:"vendorFix,omitempty"`
	DirectOnly       bool              `json:"direct_only,omitempty"`
	ReachableOnly    bool              `json:"reachable_only,omitempty"`

	CveIDs        []string `json:"cve_ids,omitempty"`
	AvdIDs        []string `json:"avd_ids,omitempty"`
	DependencyIDs []string `json:"dependency_ids,omitempty"`
	IDs           []string `json:"ids,omitempty"`

	Checks              []Check             `json:"checks,omitempty"`
	Patterns            []string            `json:"patterns,omitempty"`
	Ports               []int               `json:"ports,omitempty"`
	FileChanges         FileChanges         `json:"file_changes,omitempty"`
	TargetFile          string              `json:"target_file,omitempty"`
	TargetLine          int                 `json:"target_line,omitempty"`
	Fingerprint         string              `json:"fingerprint,omitempty"`
	FileGlobs           []string            `json:"file_globs,omitempty"`
	PublishedDateFilter PublishedDateFilter `json:"published_date_filter,omitempty"`
}

type Check struct {
	ProviderName string   `json:"provider_name,omitempty"`
	ServiceName  string   `json:"service_name,omitempty"`
	CheckID      string   `json:"check_id,omitempty"`
	CheckName    string   `json:"check_name,omitempty"`
	ScanType     ScanType `json:"scan_type,omitempty"`
}

type FileChanges struct {
	Pattern string   `json:"pattern,omitempty"`
	Changes []string `json:"changes,omitempty"`
}

type PublishedDateFilter struct {
	Days    int  `json:"days,omitempty"`
	Enabled bool `json:"enabled"`
}

type BuildSecurityPolicyScope struct {
	Expression string                       `json:"expression"`
	Variables  []BuildSecurityScopeVariable `json:"variables"`
}

type BuildSecurityScopeVariable struct {
	Attribute Attribute `json:"attribute"`
	Value     string    `json:"value"`
}

type PolicyType string

const (
	PolicyTypePolicy      PolicyType = "policy"
	PolicyTypeSuppression PolicyType = "suppression"
)

type PolicyControlType string

const (
	PolicyControlVulnerabilitySeverity               PolicyControlType = "vulnerabilitySeverity"
	PolicyControlCveByIds                            PolicyControlType = "cveByIds"
	PolicyControlVulnerabilityWithVendorFix          PolicyControlType = "vulnerabilityWithVendorFix"
	PolicyControlMisconfigurations                   PolicyControlType = "misconfigurations"
	PolicyControlMisconfigurationsBySeverity         PolicyControlType = "misconfigurationsBySeverity"
	PolicyControlMisconfigurationsByService          PolicyControlType = "misconfigurationsByService"
	PolicyControlSecretSeverity                      PolicyControlType = "secretSeverity"
	PolicyControlSecretByPatterns                    PolicyControlType = "secretByPatterns"
	PolicyControlSecretByIds                         PolicyControlType = "secretByIds"
	PolicyControlSASTSeverity                        PolicyControlType = "sastSeverity"
	PolicyControlSASTAiSeverity                      PolicyControlType = "sastAiSeverity"
	PolicyControlSASTByIds                           PolicyControlType = "sastByIds"
	PolicyControlPipelineMisconfigurations           PolicyControlType = "pipelineMisconfigurations"
	PolicyControlPipelineMisconfigurationsBySeverity PolicyControlType = "pipelineMisconfigurationsBySeverity"
	PolicyControlDependencyByName                    PolicyControlType = "dependencyByName"
	PolicyControlDependencyByVersion                 PolicyControlType = "dependencyByVersion"
	PolicyControlDependencyByLicense                 PolicyControlType = "dependencyByLicense"
	PolicyControlManifestSecurityScanChecks          PolicyControlType = "manifestSecurityScanChecks"
	PolicyControlManifestSourceCodeProtection        PolicyControlType = "manifestSourceCodeProtection"
	PolicyControlImageName                           PolicyControlType = "imageName"
	PolicyControlDetectionIds                        PolicyControlType = "detectionIds"
	PolicyControlDetectionsBySeverity                PolicyControlType = "detectionsBySeverity"
	PolicyControlFSPath                              PolicyControlType = "fsPath"
	PolicyControlNetworkURL                          PolicyControlType = "networkUrl"
	PolicyControlPortRange                           PolicyControlType = "portRange"
)

type ScanType string

const (
	ScanTypeMisconfiguration ScanType = "misconfiguration"
	ScanTypeVulnerability    ScanType = "vulnerability"
	ScanTypeSecret           ScanType = "secret"
	ScanTypePipeline         ScanType = "pipeline"
	ScanTypeSAST             ScanType = "sast"
	ScanTypeDependency       ScanType = "dependency"
	ScanTypeProfile          ScanType = "profile"
	ScanTypeManifest         ScanType = "manifest"
)

type Operator string

const (
	OperatorGreaterThan          Operator = "greater_than"
	OperatorLessThan             Operator = "less_than"
	OperatorEqualsTo             Operator = "equals_to"
	OperatorGreaterThanOrEqualTo Operator = "greater_than_or_equal_to"
	OperatorLessThanOrEqualTo    Operator = "less_than_or_equal_to"
	OperatorAllVersions          Operator = "all_versions"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityUnknown  Severity = "unknown"
)

type Attribute string

const (
	AttributeRepositoryID           Attribute = "repository.id"
	AttributeRepositoryName         Attribute = "repository.name"
	AttributeRepositoryBranch       Attribute = "repository.branch"
	AttributeRepositoryTopic        Attribute = "repository.topic"
	AttributeRepositoryLabel        Attribute = "repository.label"
	AttributeRepositoryOrganization Attribute = "repository.organization"
	AttributeRepositoryProvider     Attribute = "repository.provider"
)

type SuppressionRuleResp struct {
	CurrentPage     int               `json:"current_page"`
	NextPage        int               `json:"next_page"`
	ReturnedCount   int               `json:"returned_count"`
	TotalCount      int               `json:"total_count"`
	SelectionScopes []interface{}     `json:"selection_scopes,omitempty"`
	Data            []SuppressionRule `json:"data,omitempty"`
}

type SuppressionRuleQuery struct {
	OrderBy  string `json:"order_by"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

func (cli *Client) GetSuppressionRules(query SuppressionRuleQuery) (*SuppressionRuleResp, error) {
	request := cli.gorequest

	orderBy := query.OrderBy
	apiPath := fmt.Sprintf("/v2/build/suppressionsV2?page=%d&page_size=%d&order_by=%s&type=%s",
		query.Page, query.PageSize, url.QueryEscape(orderBy), "suppression")

	if err := cli.limiter.Wait(context.Background()); err != nil {
		return nil, err
	}
	resp, body, errs := request.Clone().
		Set("Authorization", "Bearer "+cli.token).
		Get(cli.saasScpUrl + apiPath).
		End()
	if errs != nil {
		return nil, fmt.Errorf("error calling %s: %v", apiPath, errs)
	}
	if resp.StatusCode != 200 {
		var errResp ErrorResponse
		if uerr := json.Unmarshal([]byte(body), &errResp); uerr == nil && errResp.Message != "" {
			return nil, fmt.Errorf("failed getting suppression rules: status=%s message=%s", resp.Status, errResp.Message)
		}
		return nil, fmt.Errorf("failed getting suppression rules: status=%s body=%s", resp.Status, body)
	}

	var wrapper SuppressionRuleResp
	if err := json.Unmarshal([]byte(body), &wrapper); err != nil {
		// Unexpected shape — return helpful error with raw body.
		log.Printf("GetSuppressionRules: failed to unmarshal list wrapper: %v, body: %q", err, body)
		return nil, fmt.Errorf("unexpected response shape from %s: %s", apiPath, body)
	}

	return &wrapper, nil
}

func (cli *Client) GetSuppressionRule(id string) (*SuppressionRule, error) {
	var err error
	var response SuppressionRule

	request := cli.gorequest
	apiPath := fmt.Sprintf("/v2/build/suppressionsV2/%s", id)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.saasScpUrl + apiPath).End()
	if errs != nil {
		return nil, fmt.Errorf("error calling %s", apiPath)
	}
	if resp.StatusCode != 200 {
		var errResp ErrorResponse
		if uerr := json.Unmarshal([]byte(body), &errResp); uerr == nil && errResp.Message != "" {
			return nil, fmt.Errorf("failed getting suppression rule: status=%s message=%s", resp.Status, errResp.Message)
		}
		return nil, fmt.Errorf("failed getting suppression rule: status=%s body=%s", resp.Status, body)
	}

	if err = json.Unmarshal([]byte(body), &response); err != nil {
		log.Printf("Error calling func GetSuppressionRule from %s%s, %v ", cli.saasScpUrl, apiPath, err)
		return nil, err
	}

	return &response, nil
}

func (cli *Client) CreateSuppressionRule(rule *SuppressionRule) (*SuppressionRule, error) {
	payload, err := json.Marshal(rule)
	if err != nil {
		return nil, err
	}

	request := cli.gorequest
	apiPath := "/v2/build/suppressionsV2"
	if err := cli.limiter.Wait(context.Background()); err != nil {
		return nil, err
	}

	resp, body, errs := request.Clone().
		Set("Authorization", "Bearer "+cli.token).
		Post(cli.saasScpUrl + apiPath).
		Send(string(payload)).
		End()

	if errs != nil {
		return nil, fmt.Errorf("error calling %s: %v", apiPath, errs)
	}
	log.Printf("CreateSuppressionRule: status=%s body=%q", resp.Status, body)

	if resp.StatusCode != 201 && resp.StatusCode != 204 && resp.StatusCode != 200 {
		var errorResponse ErrorResponse
		if err := json.Unmarshal([]byte(body), &errorResponse); err != nil {
			log.Printf("Failed to unmarshal error body for %s: %v. body: %q", apiPath, err, body)
			return nil, fmt.Errorf("failed creating Suppression Rule: status %s, body: %s", resp.Status, body)
		}
		return nil, fmt.Errorf("failed creating Suppression Rule: status %s, message: %s", resp.Status, errorResponse.Message)
	}
	var created SuppressionRule
	if body == "" {
		created = *rule
		if loc := resp.Header.Get("Location"); loc != "" {
			parts := strings.Split(strings.TrimRight(loc, "/"), "/")
			if len(parts) > 0 {
				created.PolicyID = parts[len(parts)-1]
			}
		}
		return &created, nil
	}

	if err := json.Unmarshal([]byte(body), &created); err != nil {
		return nil, fmt.Errorf("failed to parse create response: %v. body: %q", err, body)
	}
	return &created, nil
}

func (cli *Client) UpdateSuppressionRule(id string, rule *SuppressionRule) error {
	payload, err := json.Marshal(rule)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := fmt.Sprintf("/v2/build/suppressionsV2/%s", id)
	if err := cli.limiter.Wait(context.Background()); err != nil {
		return err
	}

	resp, body, errs := request.Clone().
		Set("Authorization", "Bearer "+cli.token).
		Put(cli.saasScpUrl + apiPath).
		Send(string(payload)).
		End()

	if errs != nil {
		return fmt.Errorf("error calling %s: %v", apiPath, errs)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errorResponse ErrorResponse
		if err := json.Unmarshal([]byte(body), &errorResponse); err != nil {
			log.Printf("Failed to unmarshal update error body for %s: %v. body: %q", apiPath, err, body)
			return fmt.Errorf("failed updating Suppression Rule: status %s, body: %s", resp.Status, body)
		}
		return fmt.Errorf("failed updating Suppression Rule: status %s, message: %s", resp.Status, errorResponse.Message)
	}
	return nil
}

func (cli *Client) DeleteSuppressionRule(id string) error {
	request := cli.gorequest
	apiPath := fmt.Sprintf("/v2/build/suppressionsV2/%s", id)
	if err := cli.limiter.Wait(context.Background()); err != nil {
		return err
	}
	resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.saasScpUrl + apiPath).End()
	if errs != nil {
		return fmt.Errorf("error calling %s: %v", apiPath, errs)
	}
	if resp.StatusCode != 200 && resp.StatusCode != 202 && resp.StatusCode != 204 {
		var errorResponse ErrorResponse
		if err := json.Unmarshal([]byte(body), &errorResponse); err != nil {
			log.Printf("Failed to unmarshal delete error body for %s: %v. body: %q", apiPath, err, body)
			return fmt.Errorf("failed deleting Suppression Rule: status %s, body: %s", resp.Status, body)
		}
		return fmt.Errorf("failed deleting Suppression Rule: status %s, message: %s", resp.Status, errorResponse.Message)
	}
	return nil
}
