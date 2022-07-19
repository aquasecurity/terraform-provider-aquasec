package aquasec

import (
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceImageAssurancePolicy() *schema.Resource {
	return &schema.Resource{
		Create: resourceImageAssurancePolicyCreate,
		Read:   resourceImageAssurancePolicyRead,
		Update: resourceImageAssurancePolicyUpdate,
		Delete: resourceImageAssurancePolicyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"assurance_type": {
				Type:        schema.TypeString,
				Description: "What type of assurance policy is described.",
				Optional:    true,
			},
			"id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "Name of user account that created the policy.",
				Computed:    true,
			},
			"registry": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"cvss_severity_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if the cvss severity is scanned.",
				Optional:    true,
			},
			"cvss_severity": {
				Type:        schema.TypeString,
				Description: "Identifier of the cvss severity.",
				Optional:    true,
			},
			"cvss_severity_exclude_no_fix": {
				Type:        schema.TypeBool,
				Description: "Indicates that policy should ignore cvss cases that do not have a known fix.",
				Optional:    true,
			},
			"custom_severity_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"maximum_score_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if exceeding the maximum score is scanned.",
				Optional:    true,
			},
			"maximum_score": {
				Type:        schema.TypeFloat,
				Description: "Value of allowed maximum score.",
				Optional:    true,
			},
			"control_exclude_no_fix": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"custom_checks_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if scanning should include custom checks.",
				Optional:    true,
			},
			"scap_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if scanning should include scap.",
				Optional:    true,
			},
			"cves_black_list_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if cves blacklist is relevant.",
				Optional:    true,
			},
			"packages_black_list_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if packages blacklist is relevant.",
				Optional:    true,
			},
			"packages_white_list_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if packages whitelist is relevant.",
				Optional:    true,
			},
			"only_none_root_users": {
				Type:        schema.TypeBool,
				Description: "Indicates if raise a warning for images that should only be run as root.",
				Optional:    true,
			},
			"trusted_base_images_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if list of trusted base images is relevant.",
				Optional:    true,
			},
			"scan_sensitive_data": {
				Type:        schema.TypeBool,
				Description: "Indicates if scan should include sensitive data in the image.",
				Optional:    true,
			},
			"audit_on_failure": {
				Type:        schema.TypeBool,
				Description: "Indicates if auditing for failures.",
				Optional:    true,
				Default:     true,
			},
			"fail_cicd": {
				Type:        schema.TypeBool,
				Description: "Indicates if cicd failures will fail the image.",
				Optional:    true,
				Default:     true,
			},
			"block_failed": {
				Type:        schema.TypeBool,
				Description: "Indicates if failed images are blocked.",
				Optional:    true,
				Default:     true,
			},
			"disallow_malware": {
				Type:        schema.TypeBool,
				Description: "Indicates if malware should block the image.",
				Optional:    true,
			},
			"monitored_malware_paths": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"exceptional_monitored_malware_paths": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"blacklisted_licenses_enabled": {
				Type:        schema.TypeBool,
				Description: "Lndicates if license blacklist is relevant.",
				Optional:    true,
			},
			"blacklisted_licenses": {
				Type:        schema.TypeList,
				Description: "List of blacklisted licenses.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"whitelisted_licenses_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if license blacklist is relevant.",
				Optional:    true,
			},
			"whitelisted_licenses": {
				Type:        schema.TypeList,
				Description: "List of whitelisted licenses.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"custom_checks": {
				Type:        schema.TypeList,
				Description: "List of Custom user scripts for checks.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"script_id": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"path": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"last_modified": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"description": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"engine": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"snippet": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"read_only": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"severity": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"author": {
							Type:        schema.TypeString,
							Description: "Name of user account that created the policy.",
							Optional:    true,
						},
					},
				},
			},
			"scap_files": {
				Type:        schema.TypeList,
				Description: "List of SCAP user scripts for checks.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"scope": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"expression": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"variables": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"attribute": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"value": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"name": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
			"registries": {
				Type:        schema.TypeList,
				Description: "List of registries.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"labels": {
				Type:        schema.TypeList,
				Description: "List of labels.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"images": {
				Type:        schema.TypeList,
				Description: "List of images.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"cves_black_list": {
				Type:        schema.TypeList,
				Description: "List of cves blacklisted items.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"packages_black_list": {
				Type:        schema.TypeSet,
				Description: "List of backlisted images.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"format": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"epoch": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"version": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"version_range": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"release": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"arch": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"license": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"display": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"packages_white_list": {
				Type:        schema.TypeSet,
				Description: "List of whitelisted images.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"format": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"epoch": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"version": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"version_range": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"release": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"arch": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"license": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"display": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"allowed_images": {
				Type:        schema.TypeList,
				Description: "List of explicitly allowed images.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"trusted_base_images": {
				Type:        schema.TypeSet,
				Description: "List of trusted images.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"registry": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"imagename": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"read_only": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"force_microenforcer": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"docker_cis_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"kube_cis_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"enforce_excessive_permissions": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"function_integrity_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"dta_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"cves_white_list_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if cves whitelist is relevant.",
				Optional:    true,
			},
			"cves_white_list": {
				Type:        schema.TypeList,
				Description: "List of cves whitelisted licenses",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"blacklist_permissions_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if blacklist permissions is relevant.",
				Optional:    true,
			},
			"blacklist_permissions": {
				Type:        schema.TypeList,
				Description: "List of function's forbidden permissions.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"enforce": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"enforce_after_days": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"ignore_recently_published_vln": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"ignore_recently_published_vln_period": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"ignore_risk_resources_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if risk resources are ignored.",
				Optional:    true,
			},
			"ignored_risk_resources": {
				Type:        schema.TypeList,
				Description: "List of ignored risk resources.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"application_scopes": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"auto_scan_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_scan_configured": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_scan_time": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"iteration_type": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"time": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"iteration": {
							Type:     schema.TypeInt,
							Optional: true,
							Computed: true,
						},
						"week_days": {
							Type:     schema.TypeList,
							Optional: true,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"required_labels_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"required_labels": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"key": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"value": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"forbidden_labels_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"forbidden_labels": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"key": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"value": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"domain_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"domain": {
				Type:        schema.TypeString,
				Description: "Name of the container image.",
				Optional:    true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"dta_severity": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"scan_nfs_mounts": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"malware_action": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"partial_results_image_fail": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"maximum_score_exclude_no_fix": {
				Type:        schema.TypeBool,
				Description: "Indicates that policy should ignore cases that do not have a known fix.",
				Optional:    true,
			},
		},
	}
}

func resourceImageAssurancePolicyCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	assurance_type := "image"

	iap := expandAssurancePolicy(d)
	err := ac.CreateAssurancePolicy(iap, assurance_type)

	if err != nil {
		return err
	}
	d.SetId(name)
	return resourceImageAssurancePolicyRead(d, m)

}

func resourceImageAssurancePolicyUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	assurance_type := "image"

	if d.HasChanges("description", "registry", "cvss_severity_enabled", "cvss_severity", "cvss_severity_exclude_no_fix", "custom_severity_enabled", "maximum_score_enabled", "maximum_score", "control_exclude_no_fix", "custom_checks_enabled",
		"scap_enabled", "cves_black_list_enabled", "packages_black_list_enabled", "packages_white_list_enabled", "only_none_root_users", "trusted_base_images_enabled", "scan_sensitive_data", "audit_on_failure", "fail_cicd", "block_failed",
		"disallow_malware", "monitored_malware_paths", "exceptional_monitored_malware_paths", "blacklisted_licenses_enabled", "blacklisted_licenses", "whitelisted_licenses_enabled", "whitelisted_licenses", "custom_checks", "scap_files", "scope",
		"registries", "labels", "images", "cves_black_list", "packages_black_list", "packages_white_list", "allowed_images", "trusted_base_images", "read_only", "force_microenforcer", "docker_cis_enabled", "kube_cis_enabled", "enforce_excessive_permissions",
		"function_integrity_enabled", "dta_enabled", "cves_white_list", "cves_white_list_enabled", "blacklist_permissions_enabled", "blacklist_permissions", "enabled", "enforce", "enforce_after_days", "ignore_recently_published_vln", "ignore_recently_published_vln_period",
		"ignore_risk_resources_enabled", "ignored_risk_resources", "application_scopes", "auto_scan_enabled", "auto_scan_configured", "auto_scan_time", "required_labels_enabled", "required_labels", "forbidden_labels_enabled", "forbidden_labels", "domain_name",
		"domain", "description", "dta_severity", "scan_nfs_mounts", "malware_action", "partial_results_image_fail", "maximum_score_exclude_no_fix") {
		iap := expandAssurancePolicy(d)
		err := ac.UpdateAssurancePolicy(iap, assurance_type)
		if err == nil {
			err1 := resourceImageAssurancePolicyRead(d, m)
			if err1 == nil {
				d.SetId(name)
			} else {
				return err1
			}
		} else {
			return err
		}
	}
	return nil
}

func resourceImageAssurancePolicyRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	assurance_type := "image"

	iap, err := ac.GetAssurancePolicy(d.Id(), assurance_type)
	if err == nil {
		d.Set("assurance_type", iap.AssuranceType)
		d.Set("name", iap.Name)
		d.Set("description", iap.Description)
		d.Set("author", iap.Author)
		d.Set("application_scopes", iap.ApplicationScopes)
		d.Set("registry", iap.Registry)
		d.Set("cvss_severity_enabled", iap.CvssSeverityEnabled)
		d.Set("cvss_severity", iap.CvssSeverity)
		d.Set("cvss_severity_exclude_no_fix", iap.CvssSeverityExcludeNoFix)
		d.Set("custom_severity_enabled", iap.CustomSeverityEnabled)
		d.Set("maximum_score_enabled", iap.MaximumScoreEnabled)
		d.Set("maximum_score", iap.MaximumScore)
		d.Set("control_exclude_no_fix", iap.ControlExcludeNoFix)
		d.Set("custom_checks_enabled", iap.CustomChecksEnabled)
		d.Set("scap_enabled", iap.ScapEnabled)
		d.Set("cves_black_list_enabled", iap.CvesBlackListEnabled)
		d.Set("packages_black_list_enabled", iap.PackagesBlackListEnabled)
		d.Set("packages_white_list_enabled", iap.PackagesWhiteListEnabled)
		d.Set("only_none_root_users", iap.OnlyNoneRootUsers)
		d.Set("trusted_base_images_enabled", iap.TrustedBaseImagesEnabled)
		d.Set("scan_sensitive_data", iap.ScanSensitiveData)
		d.Set("audit_on_failure", iap.AuditOnFailure)
		d.Set("fail_cicd", iap.FailCicd)
		d.Set("block_failed", iap.BlockFailed)
		d.Set("disallow_malware", iap.DisallowMalware)
		d.Set("monitored_malware_paths", iap.MonitoredMalwarePaths)
		d.Set("exceptional_monitored_malware_paths", iap.ExceptionalMonitoredMalwarePaths)
		d.Set("blacklisted_licenses_enabled", iap.BlacklistedLicensesEnabled)
		d.Set("blacklisted_licenses", iap.BlacklistedLicenses)
		d.Set("whitelisted_licenses_enabled", iap.WhitelistedLicensesEnabled)
		d.Set("whitelisted_licenses", iap.WhitelistedLicenses)
		d.Set("custom_checks", flattenCustomChecks(iap.CustomChecks))
		d.Set("scap_files", iap.ScapFiles)
		d.Set("scope", flatteniapscope(iap.Scope))
		d.Set("registries", iap.Registries)
		d.Set("labels", iap.Labels)
		d.Set("images", iap.Images)
		d.Set("cves_black_list", iap.CvesBlackList)
		d.Set("packages_black_list", flattenpackages(iap.PackagesBlackList))
		d.Set("packages_white_list", flattenpackages(iap.PackagesWhiteList))
		d.Set("allowed_images", iap.AllowedImages)
		d.Set("trusted_base_images", flattenTrustedBaseImages(iap.TrustedBaseImages))
		d.Set("read_only", iap.ReadOnly)
		d.Set("force_microenforcer", iap.ForceMicroenforcer)
		d.Set("docker_cis_enabled", iap.DockerCisEnabled)
		d.Set("kube_cis_enabled", iap.KubeCisEnabled)
		d.Set("enforce_excessive_permissions", iap.EnforceExcessivePermissions)
		d.Set("function_integrity_enabled", iap.FunctionIntegrityEnabled)
		d.Set("dta_enabled", iap.DtaEnabled)
		d.Set("cves_white_list_enabled", iap.CvesWhiteListEnabled)
		d.Set("cves_white_list", iap.CvesWhiteList)
		d.Set("blacklist_permissions_enabled", iap.BlacklistPermissionsEnabled)
		d.Set("blacklist_permissions", iap.BlacklistPermissions)
		d.Set("enabled", iap.Enabled)
		d.Set("enforce", iap.Enforce)
		d.Set("enforce_after_days", iap.EnforceAfterDays)
		d.Set("ignore_recently_published_vln", iap.IgnoreRecentlyPublishedVln)
		d.Set("ignore_recently_published_vln_period", iap.IgnoreRecentlyPublishedVlnPeriod)
		d.Set("ignore_risk_resources_enabled", iap.IgnoreRiskResourcesEnabled)
		d.Set("ignored_risk_resources", iap.IgnoredRiskResources)
		d.Set("application_scopes", iap.ApplicationScopes)
		d.Set("auto_scan_enabled", iap.AutoScanEnabled)
		d.Set("auto_scan_configured", iap.AutoScanConfigured)
		d.Set("auto_scan_time", flattenAutoScanTime(iap.AutoScanTime))
		d.Set("required_labels_enabled", iap.RequiredLabelsEnabled)
		d.Set("required_labels", flattenlabels(iap.RequiredLabels))
		d.Set("forbidden_labels_enabled", iap.ForbiddenLabelsEnabled)
		d.Set("forbidden_labels", flattenlabels(iap.ForbiddenLabels))
		d.Set("domain_name", iap.DomainName)
		d.Set("domain", iap.Domain)
		d.Set("dta_severity", iap.DtaSeverity)
		d.Set("scan_nfs_mounts", iap.ScanNfsMounts)
		d.Set("malware_action", iap.MalwareAction)
		d.Set("partial_results_image_fail", iap.PartialResultsImageFail)
		d.Set("maximum_score_exclude_no_fix", iap.MaximumScoreExcludeNoFix)
	} else {
		return err
	}
	return nil
}

func resourceImageAssurancePolicyDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	assurance_type := "image"
	err := ac.DeleteAssurancePolicy(name, assurance_type)

	if err == nil {
		d.SetId("")
	} else {
		return err
	}
	return nil
}

func flatteniapscope(scope1 client.Scopes) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"expression": scope1.Expression,
			"variables":  flattenscopevariables(scope1.Variables),
		},
	}
}

func flattenscopevariables(variable []client.VariableI) []interface{} {
	check := make([]interface{}, len(variable))
	for i := range variable {
		check[i] = map[string]interface{}{
			"attribute": variable[i].Attribute,
			"value":     variable[i].Value,
			"name":      variable[i].Name,
		}
	}

	return check
}

func flattenAutoScanTime(scantime client.ScanTimeAuto) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"iteration_type": scantime.IterationType,
			"time":           scantime.Time,
			"iteration":      scantime.Iteration,
			"week_days":      scantime.WeekDays,
		},
	}
}

func flattenCustomChecks(checks []client.Checks) []map[string]interface{} {
	check := make([]map[string]interface{}, len(checks))
	for i := range checks {
		check[i] = map[string]interface{}{
			"script_id":     checks[i].ScriptID,
			"name":          checks[i].Name,
			"path":          checks[i].Path,
			"last_modified": checks[i].LastModified,
			"description":   checks[i].Description,
			"engine":        checks[i].Engine,
			"snippet":       checks[i].Snippet,
			"read_only":     checks[i].ReadOnly,
			"severity":      checks[i].Severity,
			"author":        checks[i].Author,
		}
	}
	return check
}

func flattenlabels(labels []client.Labels) []map[string]interface{} {
	label := make([]map[string]interface{}, len(labels))
	for i := range labels {
		label[i] = map[string]interface{}{
			"key":   labels[i].Key,
			"value": labels[i].Value,
		}
	}
	return label
}

func flattenpackages(packages []client.ListPackages) []map[string]interface{} {
	package1 := make([]map[string]interface{}, len(packages))
	for i := range packages {
		package1[i] = map[string]interface{}{
			"format":        packages[i].Format,
			"name":          packages[i].Name,
			"epoch":         packages[i].Epoch,
			"version":       packages[i].Version,
			"version_range": packages[i].VersionRange,
			"release":       packages[i].Release,
			"arch":          packages[i].Arch,
			"license":       packages[i].License,
			"display":       packages[i].Display,
		}
	}
	return package1
}

func flattenTrustedBaseImages(TrustedBaseImages []client.BaseImagesTrusted) []map[string]interface{} {
	tbi := make([]map[string]interface{}, len(TrustedBaseImages))
	for i, v := range TrustedBaseImages {
		tbi[i] = map[string]interface{}{
			"registry":  v.Registry,
			"imagename": v.Imagename,
		}
	}
	return tbi
}

func expandAssurancePolicy(d *schema.ResourceData) *client.AssurancePolicy {
	app_scopes := d.Get("application_scopes").([]interface{})
	iap := client.AssurancePolicy{
		AssuranceType:     d.Get("assurance_type").(string),
		Name:              d.Get("name").(string),
		ApplicationScopes: convertStringArr(app_scopes),
	}

	description, ok := d.GetOk("description")
	if ok {
		iap.Description = description.(string)
	}

	author, ok := d.GetOk("author")
	if ok {
		iap.Author = author.(string)
	}

	registry, ok := d.GetOk("registry")
	if ok {
		iap.Registry = registry.(string)
	}

	auditonfailure, ok := d.GetOk("audit_on_failure")
	if ok {
		iap.AuditOnFailure = auditonfailure.(bool)
	}

	failcicd, ok := d.GetOk("fail_cicd")
	if ok {
		iap.FailCicd = failcicd.(bool)
	}

	blockfailed, ok := d.GetOk("block_failed")
	if ok {
		iap.BlockFailed = blockfailed.(bool)
	}

	cvssseverityenabled, ok := d.GetOk("cvss_severity_enabled")
	if ok {
		iap.CvssSeverityEnabled = cvssseverityenabled.(bool)
	}

	cvssseverity, ok := d.GetOk("cvss_severity")
	if ok {
		iap.CvssSeverity = cvssseverity.(string)
	}

	cvssseverityexcludenofix, ok := d.GetOk("cvss_severity_exclude_no_fix")
	if ok {
		iap.CvssSeverityExcludeNoFix = cvssseverityexcludenofix.(bool)
	}

	custom_severity_enabled, ok := d.GetOk("custom_severity_enabled")
	if ok {
		iap.CustomSeverityEnabled = custom_severity_enabled.(bool)
	}

	maximum_score_enabled, ok := d.GetOk("maximum_score_enabled")
	if ok {
		iap.MaximumScoreEnabled = maximum_score_enabled.(bool)
	}

	maximum_score, ok := d.GetOk("maximum_score")
	if ok {
		iap.MaximumScore = maximum_score.(float64)
	}

	control_exclude_no_fix, ok := d.GetOk("control_exclude_no_fix")
	if ok {
		iap.ControlExcludeNoFix = control_exclude_no_fix.(bool)
	}

	custom_checks_enabled, ok := d.GetOk("custom_checks_enabled")
	if ok {
		iap.CustomChecksEnabled = custom_checks_enabled.(bool)
	}

	scap_enabled, ok := d.GetOk("scap_enabled")
	if ok {
		iap.ScapEnabled = scap_enabled.(bool)
	}

	cves_black_list_enabled, ok := d.GetOk("cves_black_list_enabled")
	if ok {
		iap.CvesBlackListEnabled = cves_black_list_enabled.(bool)
	}

	packages_black_list_enabled, ok := d.GetOk("packages_black_list_enabled")
	if ok {
		iap.PackagesBlackListEnabled = packages_black_list_enabled.(bool)
	}

	packages_white_list_enabled, ok := d.GetOk("packages_white_list_enabled")
	if ok {
		iap.PackagesWhiteListEnabled = packages_white_list_enabled.(bool)
	}

	only_none_root_users, ok := d.GetOk("only_none_root_users")
	if ok {
		iap.OnlyNoneRootUsers = only_none_root_users.(bool)
	}

	trusted_base_images_enabled, ok := d.GetOk("trusted_base_images_enabled")
	if ok {
		iap.TrustedBaseImagesEnabled = trusted_base_images_enabled.(bool)
	}

	scan_sensitive_data, ok := d.GetOk("scan_sensitive_data")
	if ok {
		iap.ScanSensitiveData = scan_sensitive_data.(bool)
	}

	disallow_malware, ok := d.GetOk("disallow_malware")
	if ok {
		iap.DisallowMalware = disallow_malware.(bool)
	}

	monitored_malware_paths, ok := d.GetOk("monitored_malware_paths")
	if ok {
		iap.MonitoredMalwarePaths = monitored_malware_paths.([]interface{})
	}

	exceptional_monitored_malware_paths, ok := d.GetOk("exceptional_monitored_malware_paths")
	if ok {
		iap.ExceptionalMonitoredMalwarePaths = exceptional_monitored_malware_paths.([]interface{})
	}

	blacklisted_licenses_enabled, ok := d.GetOk("blacklisted_licenses_enabled")
	if ok {
		iap.BlacklistedLicensesEnabled = blacklisted_licenses_enabled.(bool)
	}

	blacklisted_licenses, ok := d.GetOk("blacklisted_licenses")
	if ok {
		strArr := convertStringArr(blacklisted_licenses.([]interface{}))
		iap.BlacklistedLicenses = strArr
	}

	whitelisted_licenses_enabled, ok := d.GetOk("whitelisted_licenses_enabled")
	if ok {
		iap.WhitelistedLicensesEnabled = whitelisted_licenses_enabled.(bool)
	}

	whitelisted_licenses, ok := d.GetOk("whitelisted_licenses")
	if ok {
		strArr := convertStringArr(whitelisted_licenses.([]interface{}))
		iap.WhitelistedLicenses = strArr
	}

	custom_checks, ok := d.GetOk("custom_checks")
	if ok {
		customcheckslist := custom_checks.([]interface{})
		custcheckskArr := make([]client.Checks, len(customcheckslist))
		for i, Data := range customcheckslist {
			customChecks := Data.(map[string]interface{})
			Check := client.Checks{
				ScriptID:     customChecks["script_id"].(string),
				Name:         customChecks["name"].(string),
				Path:         customChecks["path"].(string),
				LastModified: customChecks["last_modified"].(int),
				Description:  customChecks["description"].(string),
				Engine:       customChecks["engine"].(string),
				Snippet:      customChecks["snippet"].(string),
				ReadOnly:     customChecks["read_only"].(bool),
				Severity:     customChecks["severity"].(string),
				Author:       customChecks["author"].(string),
			}
			custcheckskArr[i] = Check
		}
		iap.CustomChecks = custcheckskArr
	}

	scap_files, ok := d.GetOk("scap_files")
	if ok {
		iap.ScapFiles = scap_files.([]interface{})
	}

	scope, ok := d.GetOk("scope")
	if ok && scope.(*schema.Set).Len() > 0 {
		for _, scopeMap := range scope.(*schema.Set).List() {
			scopeentries, ok := scopeMap.(map[string]interface{})
			if !ok {
				continue
			}
			VariablesList := scopeentries["variables"].([]interface{})
			variablearray := make([]client.VariableI, len(VariablesList))
			for i, Data := range VariablesList {
				varLists := Data.(map[string]interface{})
				VarData := client.VariableI{
					Attribute: varLists["attribute"].(string),
					Name:      varLists["name"].(string),
					Value:     varLists["value"].(string),
				}
				variablearray[i] = VarData
			}

			Sc := client.Scopes{
				Expression: scopeentries["expression"].(string),
				Variables:  variablearray,
			}
			iap.Scope = Sc
		}
	}

	registries, ok := d.GetOk("registries")
	if ok {
		iap.Registries = registries.([]interface{})
	}

	labels, ok := d.GetOk("labels")
	if ok {
		iap.Labels = labels.([]interface{})
	}

	images, ok := d.GetOk("images")
	if ok {
		iap.Images = images.([]interface{})
	}

	cves_black_list, ok := d.GetOk("cves_black_list")
	if ok {
		strArr := convertStringArr(cves_black_list.([]interface{}))
		iap.CvesBlackList = strArr
	}

	packages_black_list, ok := d.GetOk("packages_black_list")
	if ok {
		pkgsblacklist := packages_black_list.([]interface{})
		pkgsblacklistarray := make([]client.ListPackages, len(pkgsblacklist))
		for i, Data := range pkgsblacklist {
			blackLists := Data.(map[string]interface{})
			BlackList := client.ListPackages{
				Format:       blackLists["format"].(string),
				Name:         blackLists["name"].(string),
				Epoch:        blackLists["epoch"].(string),
				Version:      blackLists["version"].(string),
				VersionRange: blackLists["version_range"].(string),
				Release:      blackLists["release"].(string),
				Arch:         blackLists["arch"].(string),
				License:      blackLists["license"].(string),
				Display:      blackLists["display"].(string),
			}
			pkgsblacklistarray[i] = BlackList
		}
		iap.PackagesBlackList = pkgsblacklistarray
	}

	packages_white_list, ok := d.GetOk("packages_white_list")
	if ok {
		pkgswhitelist := packages_white_list.([]interface{})
		pkgswhitelistarray := make([]client.ListPackages, len(pkgswhitelist))
		for i, Data := range pkgswhitelist {
			WhiteLists := Data.(map[string]interface{})
			WhiteList := client.ListPackages{
				Format:       WhiteLists["format"].(string),
				Name:         WhiteLists["name"].(string),
				Epoch:        WhiteLists["epoch"].(string),
				Version:      WhiteLists["version"].(string),
				VersionRange: WhiteLists["version_range"].(string),
				Release:      WhiteLists["release"].(string),
				Arch:         WhiteLists["arch"].(string),
				License:      WhiteLists["license"].(string),
				Display:      WhiteLists["display"].(string),
			}
			pkgswhitelistarray[i] = WhiteList
		}
		iap.PackagesWhiteList = pkgswhitelistarray
	}

	allowed_images, ok := d.GetOk("allowed_images")
	if ok {
		iap.AllowedImages = allowed_images.([]interface{})
	}

	trusted_base_images, ok := d.GetOk("trusted_base_images")
	if ok {
		trustedbaseimages := trusted_base_images.([]interface{})
		baseimagesarray := make([]client.BaseImagesTrusted, len(trustedbaseimages))
		for i, Data := range trustedbaseimages {
			baseimages := Data.(map[string]interface{})
			BImage := client.BaseImagesTrusted{
				Registry:  baseimages["registry"].(string),
				Imagename: baseimages["imagename"].(string),
			}
			baseimagesarray[i] = BImage
		}
		iap.TrustedBaseImages = baseimagesarray
	}

	read_only, ok := d.GetOk("read_only")
	if ok {
		iap.ReadOnly = read_only.(bool)
	}

	force_microenforcer, ok := d.GetOk("force_microenforcer")
	if ok {
		iap.ForceMicroenforcer = force_microenforcer.(bool)
	}

	docker_cis_enabled, ok := d.GetOk("docker_cis_enabled")
	if ok {
		iap.DockerCisEnabled = docker_cis_enabled.(bool)
	}

	kube_cis_enabled, ok := d.GetOk("kube_cis_enabled")
	if ok {
		iap.KubeCisEnabled = kube_cis_enabled.(bool)
	}

	enforce_excessive_permissions, ok := d.GetOk("enforce_excessive_permissions")
	if ok {
		iap.EnforceExcessivePermissions = enforce_excessive_permissions.(bool)
	}

	function_integrity_enabled, ok := d.GetOk("function_integrity_enabled")
	if ok {
		iap.FunctionIntegrityEnabled = function_integrity_enabled.(bool)
	}

	dta_enabled, ok := d.GetOk("dta_enabled")
	if ok {
		iap.DtaEnabled = dta_enabled.(bool)
	}

	cves_white_list, ok := d.GetOk("cves_white_list")
	if ok {
		strArr := convertStringArr(cves_white_list.([]interface{}))
		iap.CvesWhiteList = strArr
	}

	cves_white_list_enabled, ok := d.GetOk("cves_white_list_enabled")
	if ok {
		iap.CvesWhiteListEnabled = cves_white_list_enabled.(bool)
	}

	blacklist_permissions_enabled, ok := d.GetOk("blacklist_permissions_enabled")
	if ok {
		iap.BlacklistPermissionsEnabled = blacklist_permissions_enabled.(bool)
	}

	blacklist_permissions, ok := d.GetOk("blacklist_permissions")
	if ok {
		iap.BlacklistPermissions = blacklist_permissions.([]interface{})
	}

	enabled, ok := d.GetOk("enabled")
	if ok {
		iap.Enabled = enabled.(bool)
	}

	enforce, ok := d.GetOk("enforce")
	if ok {
		iap.Enforce = enforce.(bool)
	}

	enforce_after_days, ok := d.GetOk("enforce_after_days")
	if ok {
		iap.EnforceAfterDays = enforce_after_days.(int)
	}

	ignore_recently_published_vln, ok := d.GetOk("ignore_recently_published_vln")
	if ok {
		iap.IgnoreRecentlyPublishedVln = ignore_recently_published_vln.(bool)
	}

	ignore_recently_published_vln_period, ok := d.GetOk("ignore_recently_published_vln_period")
	if ok {
		iap.IgnoreRecentlyPublishedVlnPeriod = ignore_recently_published_vln_period.(int)
	}

	ignore_risk_resources_enabled, ok := d.GetOk("ignore_risk_resources_enabled")
	if ok {
		iap.IgnoreRiskResourcesEnabled = ignore_risk_resources_enabled.(bool)
	}

	ignored_risk_resources, ok := d.GetOk("ignored_risk_resources")
	if ok {
		strArr := convertStringArr(ignored_risk_resources.([]interface{}))
		iap.IgnoredRiskResources = strArr
	}

	auto_scan_enabled, ok := d.GetOk("auto_scan_enabled")
	if ok {
		iap.AutoScanEnabled = auto_scan_enabled.(bool)
	}

	auto_scan_configured, ok := d.GetOk("auto_scan_configured")
	if ok {
		iap.AutoScanConfigured = auto_scan_configured.(bool)
	}

	auto_scan_time, ok := d.GetOk("auto_scan_time")
	if ok && auto_scan_time.(*schema.Set).Len() > 0 {
		for _, astMap := range auto_scan_time.(*schema.Set).List() {
			astentries, ok := astMap.(map[string]interface{})
			if !ok {
				continue
			}
			ScanTime := client.ScanTimeAuto{
				IterationType: astentries["iteration_type"].(string),
				Time:          astentries["time"].(string),
				Iteration:     astentries["iteration"].(int),
				WeekDays:      astentries["week_days"].([]interface{}),
			}
			iap.AutoScanTime = ScanTime
		}
	}

	required_labels_enabled, ok := d.GetOk("required_labels_enabled")
	if ok {
		iap.RequiredLabelsEnabled = required_labels_enabled.(bool)
	}

	required_labels, ok := d.GetOk("required_labels")
	if ok {
		requiredlabels := required_labels.([]interface{})
		labelsarray := make([]client.Labels, len(requiredlabels))
		for i, Data := range requiredlabels {
			labels := Data.(map[string]interface{})
			RequiredLabel := client.Labels{
				Key:   labels["key"].(string),
				Value: labels["value"].(string),
			}
			labelsarray[i] = RequiredLabel
		}
		iap.RequiredLabels = labelsarray
	}

	forbidden_labels_enabled, ok := d.GetOk("forbidden_labels_enabled")
	if ok {
		iap.ForbiddenLabelsEnabled = forbidden_labels_enabled.(bool)
	}

	forbidden_labels, ok := d.GetOk("forbidden_labels")
	if ok {
		forbiddenlabels := forbidden_labels.([]interface{})
		labelsarray := make([]client.Labels, len(forbiddenlabels))
		for i, Data := range forbiddenlabels {
			labels := Data.(map[string]interface{})
			ForbiddenLabel := client.Labels{
				Key:   labels["key"].(string),
				Value: labels["value"].(string),
			}
			labelsarray[i] = ForbiddenLabel
		}
		iap.ForbiddenLabels = labelsarray
	}

	domain_name, ok := d.GetOk("domain_name")
	if ok {
		iap.DomainName = domain_name.(string)
	}

	domain, ok := d.GetOk("domain")
	if ok {
		iap.Domain = domain.(string)
	}

	dta_severity, ok := d.GetOk("dta_severity")
	if ok {
		iap.DtaSeverity = dta_severity.(string)
	}

	scan_nfs_mounts, ok := d.GetOk("scan_nfs_mounts")
	if ok {
		iap.ScanNfsMounts = scan_nfs_mounts.(bool)
	}

	malware_action, ok := d.GetOk("malware_action")
	if ok {
		iap.MalwareAction = malware_action.(string)
	}

	partial_results_image_fail, ok := d.GetOk("partial_results_image_fail")
	if ok {
		iap.PartialResultsImageFail = partial_results_image_fail.(bool)
	}

	maximum_score_exclude_no_fix, ok := d.GetOk("maximum_score_exclude_no_fix")
	if ok {
		iap.MaximumScoreExcludeNoFix = maximum_score_exclude_no_fix.(bool)
	}

	return &iap
}
