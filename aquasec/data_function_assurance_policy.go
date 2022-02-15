package aquasec

import (
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataFunctionAssurancePolicy() *schema.Resource {
	return &schema.Resource{
		Read: dataFunctionAssurancePolicyRead,
		Schema: map[string]*schema.Schema{
			"assurance_type": {
				Type:     schema.TypeString,
				Computed: true,
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
				Computed: true,
			},
			"registry": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cvss_severity_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"cvss_severity": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cvss_severity_exclude_no_fix": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"custom_severity_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"maximum_score_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"maximum_score": {
				Type:     schema.TypeFloat,
				Computed: true,
			},
			"control_exclude_no_fix": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"cves_black_list_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"scan_sensitive_data": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"audit_on_failure": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"fail_cicd": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"block_failed": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"scope": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"expression": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"variables": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"attribute": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"value": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"name": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
							},
						},
					},
				},
			},
			"registries": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"cves_black_list": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"read_only": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"docker_cis_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"kube_cis_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"enforce_excessive_permissions": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"function_integrity_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"dta_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"cves_white_list_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"cves_white_list": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"blacklist_permissions_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"blacklist_permissions": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"enforce": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"enforce_after_days": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"ignore_recently_published_vln": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"ignore_recently_published_vln_period": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"ignore_risk_resources_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"ignored_risk_resources": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"application_scopes": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"auto_scan_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"auto_scan_configured": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"auto_scan_time": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"iteration_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"time": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"iteration": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"week_days": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"domain_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"domain": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"description": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"dta_severity": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"scan_nfs_mounts": {
				Type:     schema.TypeBool,
				Computed: true,
			},
		},
	}
}

func dataFunctionAssurancePolicyRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	iap, err := ac.GetImageAssurancePolicy(name)
	if err == nil {
		d.Set("description", iap.Description)
		d.Set("assurance_type", iap.AssuranceType)
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
		d.Set("cves_black_list_enabled", iap.CvesBlackListEnabled)
		d.Set("only_none_root_users", iap.OnlyNoneRootUsers)
		d.Set("trusted_base_images_enabled", iap.TrustedBaseImagesEnabled)
		d.Set("scan_sensitive_data", iap.ScanSensitiveData)
		d.Set("audit_on_failure", iap.AuditOnFailure)
		d.Set("fail_cicd", iap.FailCicd)
		d.Set("block_failed", iap.BlockFailed)
		d.Set("scope", flatteniapscope(iap.Scope))
		d.Set("registries", iap.Registries)
		d.Set("images", iap.Images)
		d.Set("cves_black_list", iap.CvesBlackList)
		d.Set("read_only", iap.ReadOnly)
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
		d.Set("domain_name", iap.DomainName)
		d.Set("domain", iap.Domain)
		d.Set("dta_severity", iap.DtaSeverity)
		d.Set("scan_nfs_mounts", iap.ScanNfsMounts)
		d.Set("partial_results_image_fail", iap.PartialResultsImageFail)
		d.SetId(name)
	} else {
		return err
	}
	return nil
}
