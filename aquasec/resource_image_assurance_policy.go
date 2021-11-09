package aquasec

import (
	//"log"
	//"time"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceImageAssurancePolicy() *schema.Resource {
	return &schema.Resource{
		Create: resourceImageAssurancePolicyCreate,
		Read:   resourceImageAssurancePolicyRead,
		Update: resourceImageAssurancePolicyUpdate,
		Delete: resourceImageAssurancePolicyDelete,
		Schema: map[string]*schema.Schema{
			"assurance_type": {
				Type:     schema.TypeString,
				Required: true,
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
				Type:     schema.TypeString,
				Optional: true,
			},
			"registry": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"cvss_severity_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"cvss_severity": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"cvss_severity_exclude_no_fix": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"custom_severity_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"maximum_score_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"maximum_score": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"control_exclude_no_fix": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"custom_checks_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"scap_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"cves_black_list_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"packages_black_list_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"packages_white_list_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"only_none_root_users": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"trusted_base_images_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"scan_sensitive_data": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"audit_on_failure": {
				Type:     schema.TypeBool,
				Optional: true,
				Default: true,
			},
			"fail_cicd": {
				Type:     schema.TypeBool,
				Optional: true,
				Default: true,
			},
			"block_failed": {
				Type:     schema.TypeBool,
				Optional: true,
				Default: true,
			},
			"disallow_malware": {
				Type:     schema.TypeBool,
				Optional: true,
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
				Type:     schema.TypeBool,
				Optional: true,
			},
			"blacklisted_licenses": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"whitelisted_licenses_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"whitelisted_licenses": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"custom_checks": {
				Type:     schema.TypeSet,
				Optional: true,
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
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"scap_files": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"scope": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"expression": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"variables": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"registries": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"labels": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"images": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"cves_black_list": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"packages_black_list": {
				Type:     schema.TypeSet,
				Optional: true,
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
				Type:     schema.TypeSet,
				Optional: true,
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
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"trusted_base_images": {
				Type:     schema.TypeSet,
				Optional: true,
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
				Type:     schema.TypeBool,
				Optional: true,
			},
			"cves_white_list": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"blacklist_permissions_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"blacklist_permissions": {
				Type:     schema.TypeList,
				Optional: true,
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
				Optional: true,
			},
			"ignore_risk_resources_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"ignored_risk_resources": {
				Type:     schema.TypeList,
				Optional: true,
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
						},
						"week_days": {
							Type:     schema.TypeList,
							Optional: true,
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
				Type:     schema.TypeString,
				Optional: true,
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
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func resourceImageAssurancePolicyCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	app_scopes := d.Get("application_scopes").([]interface{})
	imageassurance := client.ImageAssurancePolicy {
		AssuranceType : d.Get("assurance_type").(string),
		Name : d.Get("name").(string),
		ApplicationScopes: convertStringArr(app_scopes),
	}

	err := ac.CreateImageAssurancePolicy(imageassurance)

	err1:= resourceImageAssurancePolicyRead(d,m)

	if err1 == nil {
		d.SetId(name)
	} else {
		return err
	} 

	return nil
}

func resourceImageAssurancePolicyUpdate(d *schema.ResourceData, m interface{}) error {
	//ac := m.(*client.Client)
	return nil
}

func resourceImageAssurancePolicyRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	iap, err := ac.GetImageAssurancePolicy(name)
	if err == nil {
		d.Set("description", iap.Description)
		d.Set("author", iap.Author)
		d.Set("application_scopes", iap.ApplicationScopes)
		d.Set("registry", iap.Registry)
		d.Set("cvss_severity_enabled", iap.CvssSeverityEnabled)
		d.Set("cvss_severity",iap.CvssSeverity)
		d.Set("cvss_severity_exclude_no_fix", iap.CvssSeverityExcludeNoFix)
		d.Set("custom_severity_enabled", iap.CustomSeverityEnabled)
		d.Set("maximum_score_enabled",iap.MaximumScoreEnabled)
		d.Set("maximum_score",iap.MaximumScore)
		d.Set("control_exclude_no_fix",iap.ControlExcludeNoFix)
		d.Set("custom_checks_enabled",iap.CustomChecksEnabled)
		d.Set("scap_enabled",iap.ScapEnabled)
		d.Set("cves_black_list_enabled",iap.CvesBlackListEnabled)
		d.Set("packages_black_list_enabled",iap.PackagesBlackListEnabled)
		d.Set("packages_white_list_enabled",iap.PackagesWhiteListEnabled)
		d.Set("only_none_root_users",iap.OnlyNoneRootUsers)
		d.Set("trusted_base_images_enabled",iap.TrustedBaseImagesEnabled)
		d.Set("scan_sensitive_data",iap.ScanSensitiveData)
		d.Set("audit_on_failure",iap.AuditOnFailure)
		d.Set("fail_cicd",iap.FailCicd)
		d.Set("block_failed",iap.BlockFailed)
		d.Set("disallow_malware",iap.DisallowMalware)
		d.Set("monitored_malware_paths",iap.MonitoredMalwarePaths)
		d.Set("exceptional_monitored_malware_paths",iap.ExceptionalMonitoredMalwarePaths)
		d.Set("blacklisted_licenses_enabled",iap.BlacklistedLicensesEnabled)
		d.Set("blacklisted_licenses",iap.BlacklistedLicenses)
		d.Set("whitelisted_licenses_enabled",iap.WhitelistedLicensesEnabled)
		d.Set("whitelisted_licenses",iap.WhitelistedLicenses)
		d.Set("custom_checks",iap.CustomChecks)
		d.Set("scap_files",iap.ScapFiles)
		d.Set("scope",iap.Scope)
		d.Set("registries",iap.Registries)
		d.Set("labels",iap.Labels)
		d.Set("images",iap.Images)
		d.Set("cves_black_list",iap.CvesBlackList)
		d.Set("packages_black_list",iap.PackagesBlackList)
		d.Set("packages_white_list",iap.PackagesWhiteList)
		d.Set("allowed_images",iap.AllowedImages)
		d.Set("trusted_base_images",iap.TrustedBaseImages)
		d.Set("read_only",iap.ReadOnly)
		d.Set("force_microenforcer",iap.ForceMicroenforcer)
		d.Set("docker_cis_enabled",iap.DockerCisEnabled)
		d.Set("kube_cis_enabled",iap.KubeCisEnabled)
		d.Set("enforce_excessive_permissions",iap.EnforceExcessivePermissions)
		d.Set("function_integrity_enabled",iap.FunctionIntegrityEnabled)
		d.Set("dta_enabled",iap.DtaEnabled)
		d.Set("cves_white_list_enabled",iap.CvesWhiteListEnabled)
		d.Set("cves_white_list",iap.CvesWhiteList)
		d.Set("blacklist_permissions_enabled",iap.BlacklistPermissionsEnabled)
		d.Set("blacklist_permissions",iap.BlacklistPermissions)
		d.Set("enabled",iap.Enabled)
		d.Set("enforce",iap.Enforce)
		d.Set("enforce_after_days",iap.EnforceAfterDays)
		d.Set("ignore_recently_published_vln",iap.IgnoreRecentlyPublishedVln)
		d.Set("ignore_recently_published_vln_period",iap.IgnoreRecentlyPublishedVlnPeriod)
		d.Set("ignore_risk_resources_enabled",iap.IgnoreRiskResourcesEnabled)
		d.Set("ignored_risk_resources",iap.IgnoredRiskResources)
		d.Set("application_scopes",iap.ApplicationScopes)
		d.Set("auto_scan_enabled",iap.AutoScanEnabled)
		d.Set("auto_scan_configured",iap.AutoScanConfigured)
		d.Set("auto_scan_time",iap.AutoScanTime)
		d.Set("required_labels_enabled",iap.RequiredLabelsEnabled)
		d.Set("required_labels",iap.RequiredLabels)
		d.Set("forbidden_labels_enabled",iap.ForbiddenLabelsEnabled)
		d.Set("forbidden_labels",iap.ForbiddenLabels)
		d.Set("domain_name",iap.DomainName)
		d.Set("domain",iap.Domain)
		d.Set("dta_severity",iap.DtaSeverity)
		d.Set("scan_nfs_mounts",iap.ScanNfsMounts)
		d.Set("malware_action",iap.MalwareAction)
		d.Set("partial_results_image_fail",iap.PartialResultsImageFail)
	} else {

	}
	return nil
}

func resourceImageAssurancePolicyDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	err := ac.DeleteImageAssurancePolicy(name)

	if err == nil {
		d.SetId("")
	} else {
		return err
	}
	return nil
}