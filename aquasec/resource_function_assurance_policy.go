package aquasec

import (
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceFunctionAssurancePolicy() *schema.Resource {
	return &schema.Resource{
		Create: resourceFunctionAssurancePolicyCreate,
		Read:   resourceFunctionAssurancePolicyRead,
		Update: resourceFunctionAssurancePolicyUpdate,
		Delete: resourceFunctionAssurancePolicyDelete,
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
				Computed: true,
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
			"cves_black_list_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"only_none_root_users": {
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
				Default:  true,
			},
			"fail_cicd": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"block_failed": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
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
			"read_only": {
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
				Computed: true,
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
			"partial_results_image_fail": {
				Type:     schema.TypeBool,
				Optional: true,
			},
		},
	}
}

func resourceFunctionAssurancePolicyCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	iap := expandFunctionAssurancePolicy(d)
	err := ac.CreateFunctionAssurancePolicy(iap)

	if err == nil {
		err1 := resourceFunctionAssurancePolicyRead(d, m)
		if err1 == nil {
			d.SetId(name)
		} else {
			return err1
		}
	} else {
		return err
	}

	return nil
}

func resourceFunctionAssurancePolicyUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	if d.HasChanges("description", "registry", "cvss_severity_enabled", "cvss_severity", "cvss_severity_exclude_no_fix", "custom_severity_enabled", "maximum_score_enabled", "maximum_score", "control_exclude_no_fix", "custom_checks_enabled",
		"scap_enabled", "cves_black_list_enabled", "packages_black_list_enabled", "packages_white_list_enabled", "only_none_root_users", "trusted_base_images_enabled", "scan_sensitive_data", "audit_on_failure", "fail_cicd", "block_failed",
		"disallow_malware", "monitored_malware_paths", "exceptional_monitored_malware_paths", "blacklisted_licenses_enabled", "blacklisted_licenses", "whitelisted_licenses_enabled", "whitelisted_licenses", "custom_checks", "scap_files", "scope",
		"registries", "labels", "images", "cves_black_list", "packages_black_list", "packages_white_list", "allowed_images", "trusted_base_images", "read_only", "force_microenforcer", "docker_cis_enabled", "kube_cis_enabled", "enforce_excessive_permissions",
		"function_integrity_enabled", "dta_enabled", "cves_white_list", "cves_white_list_enabled", "blacklist_permissions_enabled", "blacklist_permissions", "enabled", "enforce", "enforce_after_days", "ignore_recently_published_vln", "ignore_recently_published_vln_period",
		"ignore_risk_resources_enabled", "ignored_risk_resources", "application_scopes", "auto_scan_enabled", "auto_scan_configured", "auto_scan_time", "required_labels_enabled", "required_labels", "forbidden_labels_enabled", "forbidden_labels", "domain_name",
		"domain", "description", "dta_severity", "scan_nfs_mounts", "malware_action", "partial_results_image_fail") {
		iap := expandFunctionAssurancePolicy(d)
		err := ac.UpdateFunctionAssurancePolicy(iap)
		if err == nil {
			err1 := resourceFunctionAssurancePolicyRead(d, m)
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

func resourceFunctionAssurancePolicyRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	iap, err := ac.GetFunctionAssurancePolicy(name)
	if err == nil {
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
		d.Set("cves_black_list_enabled", iap.CvesBlackListEnabled)
		d.Set("only_none_root_users", iap.OnlyNoneRootUsers)
		d.Set("scan_sensitive_data", iap.ScanSensitiveData)
		d.Set("audit_on_failure", iap.AuditOnFailure)
		d.Set("fail_cicd", iap.FailCicd)
		d.Set("block_failed", iap.BlockFailed)
		d.Set("scope", flatteniapscope(iap.Scope))
		d.Set("registries", iap.Registries)
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
	} else {
		return err
	}
	return nil
}

func resourceFunctionAssurancePolicyDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	err := ac.DeleteFunctionAssurancePolicy(name)

	if err == nil {
		d.SetId("")
	} else {
		return err
	}
	return nil
}

func expandFunctionAssurancePolicy(d *schema.ResourceData) *client.FunctionAssurancePolicy {
	app_scopes := d.Get("application_scopes").([]interface{})
	iap := client.FunctionAssurancePolicy{
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

	cves_black_list_enabled, ok := d.GetOk("cves_black_list_enabled")
	if ok {
		iap.CvesBlackListEnabled = cves_black_list_enabled.(bool)
	}

	only_none_root_users, ok := d.GetOk("only_none_root_users")
	if ok {
		iap.OnlyNoneRootUsers = only_none_root_users.(bool)
	}

	scan_sensitive_data, ok := d.GetOk("scan_sensitive_data")
	if ok {
		iap.ScanSensitiveData = scan_sensitive_data.(bool)
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

	cves_black_list, ok := d.GetOk("cves_black_list")
	if ok {
		strArr := convertStringArr(cves_black_list.([]interface{}))
		iap.CvesBlackList = strArr
	}

	read_only, ok := d.GetOk("read_only")
	if ok {
		iap.ReadOnly = read_only.(bool)
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

	partial_results_image_fail, ok := d.GetOk("partial_results_image_fail")
	if ok {
		iap.PartialResultsImageFail = partial_results_image_fail.(bool)
	}

	return &iap
}
