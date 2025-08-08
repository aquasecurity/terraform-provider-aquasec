package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/pkg/errors"
)

type AssurancePolicy struct {
	AssuranceType                       string              `json:"assurance_type"`
	Id                                  int                 `json:"id"`
	Name                                string              `json:"name"`
	Author                              string              `json:"author"`
	Registry                            string              `json:"registry,omitempty"`
	Lastupdate                          string              `json:"lastupdate,omitempty"`
	CvssSeverityEnabled                 bool                `json:"cvss_severity_enabled"`
	CvssSeverity                        string              `json:"cvss_severity"`
	CvssSeverityExcludeNoFix            bool                `json:"cvss_severity_exclude_no_fix"`
	CustomSeverityEnabled               bool                `json:"custom_severity_enabled"`
	MaximumScoreEnabled                 bool                `json:"maximum_score_enabled"`
	MaximumScore                        float64             `json:"maximum_score"`
	ControlExcludeNoFix                 bool                `json:"control_exclude_no_fix"`
	Category                            string              `json:"category"`
	CustomChecksEnabled                 bool                `json:"custom_checks_enabled"`
	ScapEnabled                         bool                `json:"scap_enabled"`
	CvesBlackListEnabled                bool                `json:"cves_black_list_enabled"`
	PackagesBlackListEnabled            bool                `json:"packages_black_list_enabled"`
	PackagesWhiteListEnabled            bool                `json:"packages_white_list_enabled"`
	OnlyNoneRootUsers                   bool                `json:"only_none_root_users"`
	TrustedBaseImagesEnabled            bool                `json:"trusted_base_images_enabled"`
	ScanSensitiveData                   bool                `json:"scan_sensitive_data"`
	AuditOnFailure                      bool                `json:"audit_on_failure"`
	FailCicd                            bool                `json:"fail_cicd,omitempty"`
	BlockFailed                         bool                `json:"block_failed"`
	DisallowMalware                     bool                `json:"disallow_malware"`
	MonitoredMalwarePaths               []interface{}       `json:"monitored_malware_paths"`
	ExceptionalMonitoredMalwarePaths    []interface{}       `json:"exceptional_monitored_malware_paths"`
	BlacklistedLicensesEnabled          bool                `json:"blacklisted_licenses_enabled"`
	BlacklistedLicenses                 []string            `json:"blacklisted_licenses"`
	WhitelistedLicensesEnabled          bool                `json:"whitelisted_licenses_enabled"`
	WhitelistedLicenses                 []string            `json:"whitelisted_licenses"`
	CustomChecks                        []Checks            `json:"custom_checks"`
	ScapFiles                           []interface{}       `json:"scap_files"`
	Scope                               Scopes              `json:"scope"`
	Registries                          interface{}         `json:"registries"`
	Labels                              interface{}         `json:"labels"`
	Images                              interface{}         `json:"images"`
	CvesBlackList                       []string            `json:"cves_black_list"`
	PackagesBlackList                   []ListPackages      `json:"packages_black_list"`
	PackagesWhiteList                   []ListPackages      `json:"packages_white_list"`
	AllowedImages                       interface{}         `json:"allowed_images"`
	TrustedBaseImages                   []BaseImagesTrusted `json:"trusted_base_images"`
	ReadOnly                            bool                `json:"read_only"`
	ForceMicroenforcer                  bool                `json:"force_microenforcer"`
	DockerCisEnabled                    bool                `json:"docker_cis_enabled"`
	KubeCisEnabled                      bool                `json:"kube_cis_enabled"`
	EnforceExcessivePermissions         bool                `json:"enforce_excessive_permissions"`
	FunctionIntegrityEnabled            bool                `json:"function_integrity_enabled"`
	DtaEnabled                          bool                `json:"dta_enabled"`
	CvesWhiteList                       []string            `json:"cves_white_list"`
	CvesWhiteListEnabled                bool                `json:"cves_white_list_enabled"`
	BlacklistPermissionsEnabled         bool                `json:"blacklist_permissions_enabled"`
	BlacklistPermissions                []interface{}       `json:"blacklist_permissions"`
	Enabled                             bool                `json:"enabled,omitempty"`
	Enforce                             bool                `json:"enforce,omitempty"`
	EnforceAfterDays                    int                 `json:"enforce_after_days,omitempty"`
	IgnoreRecentlyPublishedVln          bool                `json:"ignore_recently_published_vln"`
	IgnoreRecentlyPublishedVlnPeriod    int                 `json:"ignore_recently_published_vln_period"`
	IgnoreRecentlyPublishedFixVln       bool                `json:"ignore_recently_published_fix_vln"`
	IgnoreRecentlyPublishedFixVlnPeriod int                 `json:"ignore_recently_published_fix_vln_period"`
	IgnoreRiskResourcesEnabled          bool                `json:"ignore_risk_resources_enabled"`
	IgnoredRiskResources                []string            `json:"ignored_risk_resources"`
	ApplicationScopes                   []string            `json:"application_scopes"`
	AutoScanEnabled                     bool                `json:"auto_scan_enabled"`
	AutoScanConfigured                  bool                `json:"auto_scan_configured"`
	AutoScanTime                        ScanTimeAuto        `json:"auto_scan_time"`
	RequiredLabelsEnabled               bool                `json:"required_labels_enabled"`
	RequiredLabels                      []Labels            `json:"required_labels"`
	ForbiddenLabelsEnabled              bool                `json:"forbidden_labels_enabled"`
	ForbiddenLabels                     []Labels            `json:"forbidden_labels"`
	DomainName                          string              `json:"domain_name,omitempty"`
	Domain                              string              `json:"domain,omitempty"`
	Description                         string              `json:"description"`
	DtaSeverity                         string              `json:"dta_severity"`
	ScanNfsMounts                       bool                `json:"scan_nfs_mounts"`
	MalwareAction                       string              `json:"malware_action"`
	PartialResultsImageFail             bool                `json:"partial_results_image_fail"`
	MaximumScoreExcludeNoFix            bool                `json:"maximum_score_exclude_no_fix"`
	//JSON
	CustomSeverity              string                  `json:"custom_severity"`
	VulnerabilityExploitability bool                    `json:"vulnerability_exploitability"`
	DisallowExploitTypes        []string                `json:"disallow_exploit_types"`
	IgnoreBaseImageVln          bool                    `json:"ignore_base_image_vln"`
	IgnoredSensitiveResources   []string                `json:"ignored_sensitive_resources"`
	Permission                  string                  `json:"permission"`
	ScanMalwareInArchives       bool                    `json:"scan_malware_in_archives"`
	KubernetesControls          KubernetesControlsArray `json:"kubernetes_controls"`
	KubernetesControlsNames     []string                `json:"kubernetes_controls_names"`
	ScanWindowsRegistry         bool                    `json:"scan_windows_registry"`
	ScanProcessMemory           bool                    `json:"scan_process_memory"`
	PolicySettings              PolicySettings          `json:"policy_settings,omitempty"`
	ExcludeApplicationScopes    []string                `json:"exclude_application_scopes"`
	LinuxCisEnabled             bool                    `json:"linux_cis_enabled"`
	WindowsCisEnabled           bool                    `json:"windows_cis_enabled"`
	OpenshiftHardeningEnabled   bool                    `json:"openshift_hardening_enabled"`
	KubernetesControlsAvdIds    []string                `json:"kubernetes_controls_avd_ids"`
	VulnerabilityScoreRange     []int                   `json:"vulnerability_score_range"`
	AggregatedVulnerability     AggregatedVulnerability `json:"aggregated_vulnerability"`
}

type Checks struct {
	ScriptID     string `json:"script_id"`
	Name         string `json:"name"`
	Path         string `json:"path"`
	LastModified int    `json:"last_modified"`
	Description  string `json:"description"`
	Engine       string `json:"engine"`
	Snippet      string `json:"snippet"`
	ReadOnly     bool   `json:"read_only"`
	Severity     string `json:"severity"`
	Author       string `json:"author"`
}

type Labels struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Scopes struct {
	Expression string      `json:"expression"`
	Variables  []VariableI `json:"variables"`
}

type VariableI struct {
	Attribute string `json:"attribute"`
	Value     string `json:"value"`
	Name      string `json:"name,omitempty"`
}

type ListPackages struct {
	Format       string `json:"format"`
	Name         string `json:"name"`
	Epoch        string `json:"epoch"`
	Version      string `json:"version"`
	VersionRange string `json:"version_range"`
	Release      string `json:"release"`
	Arch         string `json:"arch"`
	License      string `json:"license"`
	Display      string `json:"display"`
}

type BaseImagesTrusted struct {
	Registry    string `json:"registry"`
	Imagename   string `json:"imagename"`
	Author      string `json:"author"`
	ImageDigest string `json:"imagedigest"`
	ImageID     int    `json:"imageid"`
	LastUpdated int    `json:"lastupdated"`
}

type ScanTimeAuto struct {
	IterationType string        `json:"iteration_type"`
	Time          string        `json:"time"`
	Iteration     int           `json:"iteration"`
	WeekDays      []interface{} `json:"week_days"`
}

//JSON

type PolicySettings struct {
	Enforce        bool   `json:"enforce"`
	Warn           bool   `json:"warn"`
	WarningMessage string `json:"warning_message"`
	IsAuditChecked bool   `json:"is_audit_checked"`
}

type KubernetesControls struct {
	ScriptID    int    `json:"script_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Severity    string `json:"severity"`
	Kind        string `json:"kind"`
	OOTB        bool   `json:"ootb"`
	AvdID       string `json:"avd_id"`
}

type AggregatedVulnerability struct {
	Enabled               bool      `json:"enabled"`
	ScoreRange            []float32 `json:"score_range"`
	CustomSeverityEnabled bool      `json:"custom_severity_enabled"`
	Severity              string    `json:"severity"`
}

type TrustedBaseImages struct {
	Author      string `json:"author"`
	ImageDigest string `json:"image_digest"`
	ImageID     int    `json:"image_id"`
	ImageName   string `json:"image_name"`
	LastUpdated int    `json:"last_updated"`
	Registry    string `json:"registry"`
}

type KubernetesControlsArray []KubernetesControls

// GetAssurancePolicy - returns single  Assurance Policy
func (cli *Client) GetAssurancePolicy(name string, assuranceType string) (*AssurancePolicy, error) {
	var err error
	var response AssurancePolicy
	var atype string
	if strings.EqualFold(assuranceType, "host") {
		atype = "host"
	} else if strings.EqualFold(assuranceType, "image") {
		atype = "image"
	} else if strings.EqualFold(assuranceType, "function") {
		atype = "function"
	} else if strings.EqualFold(assuranceType, "kubernetes") {
		atype = "kubernetes"
	} else if strings.EqualFold(assuranceType, "cf_application") {
		atype = "cf_application"
	}

	apiPath := "/api/v2/assurance_policy/" + atype + "/" + name
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, body, errs := cli.gorequest.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting  Assurance Policy")
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetAssurancePolicy from %s%s, %v ", cli.url, apiPath, err)
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
		return nil, fmt.Errorf("failed getting  Assurance Policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	if response.Name == "" {
		return nil, fmt.Errorf(" Assurance Policy: %s not found 404", name)
	}
	return &response, err
}

// CreateAssurancePolicy - creates single Aqua  Assurance Policy
func (cli *Client) CreateAssurancePolicy(assurancePolicy *AssurancePolicy, assuranceType string) error {
	payload, err := json.Marshal(assurancePolicy)
	var atype string
	if strings.EqualFold(assuranceType, "host") {
		atype = "host"
	} else if strings.EqualFold(assuranceType, "image") {
		atype = "image"
	} else if strings.EqualFold(assuranceType, "function") {
		atype = "function"
	} else if strings.EqualFold(assuranceType, "kubernetes") {
		atype = "kubernetes"
	} else if strings.EqualFold(assuranceType, "cf_application") {
		atype = "cf_application"
	}

	apiPath := "/api/v2/assurance_policy/" + atype
	if err != nil {
		return err
	}
	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed creating  Assurance Policy.")
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
		return fmt.Errorf("failed creating  Assurance Policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// UpdateAssurancePolicy updates an existing  Assurance Policy
func (cli *Client) UpdateAssurancePolicy(assurancePolicy *AssurancePolicy, assuranceType string) error {
	payload, err := json.Marshal(assurancePolicy)
	if err != nil {
		return err
	}
	var atype string
	if strings.EqualFold(assuranceType, "host") {
		atype = "host"
	} else if strings.EqualFold(assuranceType, "image") {
		atype = "image"
	} else if strings.EqualFold(assuranceType, "function") {
		atype = "function"
	} else if strings.EqualFold(assuranceType, "kubernetes") {
		atype = "kubernetes"
	} else if strings.EqualFold(assuranceType, "cf_application") {
		atype = "cf_application"
	}
	apiPath := "/api/v2/assurance_policy/" + atype + "/" + assurancePolicy.Name
	request := cli.gorequest
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed modifying  Assurance Policy")
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
		return fmt.Errorf("failed modifying  Assurance Policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// DeleteAssurancePolicy removes a  Assurance Policy
func (cli *Client) DeleteAssurancePolicy(name string, assuranceType string) error {
	request := cli.gorequest
	var atype string
	if strings.EqualFold(assuranceType, "host") {
		atype = "host"
	} else if strings.EqualFold(assuranceType, "image") {
		atype = "image"
	} else if strings.EqualFold(assuranceType, "function") {
		atype = "function"
	} else if strings.EqualFold(assuranceType, "kubernetes") {
		atype = "kubernetes"
	} else if strings.EqualFold(assuranceType, "cf_application") {
		atype = "cf_application"
	}
	apiPath := "/api/v2/assurance_policy/" + atype + "/" + name
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.url + apiPath).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed deleting  Assurance Policy")
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
		return fmt.Errorf("failed deleting  Assurance Policy, status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}
