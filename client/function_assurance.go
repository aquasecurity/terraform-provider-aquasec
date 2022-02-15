package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/pkg/errors"
)

type FunctionAssurancePolicy struct {
	AssuranceType                    string        `json:"assurance_type"`
	Id                               int           `json:"id"`
	Name                             string        `json:"name"`
	Author                           string        `json:"author"`
	Registry                         string        `json:"registry"`
	Lastupdate                       time.Time     `json:"lastupdate"`
	CvssSeverityEnabled              bool          `json:"cvss_severity_enabled"`
	CvssSeverity                     string        `json:"cvss_severity"`
	CvssSeverityExcludeNoFix         bool          `json:"cvss_severity_exclude_no_fix"`
	CustomSeverityEnabled            bool          `json:"custom_severity_enabled"`
	MaximumScoreEnabled              bool          `json:"maximum_score_enabled"`
	MaximumScore                     float64       `json:"maximum_score"`
	ControlExcludeNoFix              bool          `json:"control_exclude_no_fix"`
	CvesBlackListEnabled             bool          `json:"cves_black_list_enabled"`
	OnlyNoneRootUsers                bool          `json:"only_none_root_users"`
	ScanSensitiveData                bool          `json:"scan_sensitive_data"`
	AuditOnFailure                   bool          `json:"audit_on_failure"`
	FailCicd                         bool          `json:"fail_cicd"`
	BlockFailed                      bool          `json:"block_failed"`
	Scope                            Scopes        `json:"scope"`
	Registries                       interface{}   `json:"registries"`
	CvesBlackList                    []string      `json:"cves_black_list"`
	ReadOnly                         bool          `json:"read_only"`
	DockerCisEnabled                 bool          `json:"docker_cis_enabled"`
	KubeCisEnabled                   bool          `json:"kube_cis_enabled"`
	EnforceExcessivePermissions      bool          `json:"enforce_excessive_permissions"`
	FunctionIntegrityEnabled         bool          `json:"function_integrity_enabled"`
	DtaEnabled                       bool          `json:"dta_enabled"`
	CvesWhiteList                    []string      `json:"cves_white_list"`
	CvesWhiteListEnabled             bool          `json:"cves_white_list_enabled"`
	BlacklistPermissionsEnabled      bool          `json:"blacklist_permissions_enabled"`
	BlacklistPermissions             []interface{} `json:"blacklist_permissions"`
	Enabled                          bool          `json:"enabled"`
	Enforce                          bool          `json:"enforce"`
	EnforceAfterDays                 int           `json:"enforce_after_days"`
	IgnoreRecentlyPublishedVln       bool          `json:"ignore_recently_published_vln"`
	IgnoreRecentlyPublishedVlnPeriod int           `json:"ignore_recently_published_vln_period"`
	IgnoreRiskResourcesEnabled       bool          `json:"ignore_risk_resources_enabled"`
	IgnoredRiskResources             []string      `json:"ignored_risk_resources"`
	ApplicationScopes                []string      `json:"application_scopes"`
	AutoScanEnabled                  bool          `json:"auto_scan_enabled"`
	AutoScanConfigured               bool          `json:"auto_scan_configured"`
	AutoScanTime                     ScanTimeAuto  `json:"auto_scan_time"`
	DomainName                       string        `json:"domain_name"`
	Domain                           string        `json:"domain"`
	Description                      string        `json:"description"`
	DtaSeverity                      string        `json:"dta_severity"`
	ScanNfsMounts                    bool          `json:"scan_nfs_mounts"`
	PartialResultsImageFail          bool          `json:"partial_results_image_fail"`
}

// GetFunctionAssurancePolicy - returns single Function Assurance Policy
func (cli *Client) GetFunctionAssurancePolicy(name string) (*FunctionAssurancePolicy, error) {
	var err error
	var response FunctionAssurancePolicy
	cli.gorequest.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v2/assurance_policy/function/%s", name)
	resp, body, errs := cli.gorequest.Clone().Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting Function Assurance Policy")
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetFunctionAssurancePolicy from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	} else {
		body, err := ioutil.ReadAll(resp.Body)
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
		return nil, fmt.Errorf("failed getting Function Assurance Policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	if response.Name == "" {
		return nil, fmt.Errorf("function Assurance Policy not found: %s", name)
	}
	return &response, err
}

// CreateFunctionAssurancePolicy - creates single Aqua Function Assurance Policy
func (cli *Client) CreateFunctionAssurancePolicy(Functionassurancepolicy *FunctionAssurancePolicy) error {
	payload, err := json.Marshal(Functionassurancepolicy)
	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v2/assurance_policy/function")
	resp, _, errs := request.Clone().Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed creating Function Assurance Policy.")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
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
		return fmt.Errorf("failed creating Function Assurance Policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// UpdateFunctionAssurancePolicy updates an existing Function Assurance Policy
func (cli *Client) UpdateFunctionAssurancePolicy(Functionassurancepolicy *FunctionAssurancePolicy) error {
	payload, err := json.Marshal(Functionassurancepolicy)
	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v2/assurance_policy/function/%s", Functionassurancepolicy.Name)
	resp, _, errs := request.Clone().Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed modifying Function Assurance Policy")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
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
		return fmt.Errorf("failed modifying Function Assurance Policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// DeleteFunctionAssurancePolicy removes a Function Assurance Policy
func (cli *Client) DeleteFunctionAssurancePolicy(name string) error {
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v2/assurance_policy/function/%s", name)
	resp, _, errs := request.Clone().Delete(cli.url + apiPath).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed deleting Function Assurance Policy")
	}
	if resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
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
		return fmt.Errorf("failed deleting Function Assurance Policy, status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}
