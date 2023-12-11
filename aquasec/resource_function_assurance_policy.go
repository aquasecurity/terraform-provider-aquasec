package aquasec

import (
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strings"
)

func resourceFunctionAssurancePolicy() *schema.Resource {
	return &schema.Resource{
		Create: resourceFunctionAssurancePolicyCreate,
		Read:   resourceFunctionAssurancePolicyRead,
		Update: resourceFunctionAssurancePolicyUpdate,
		Delete: resourceFunctionAssurancePolicyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{

			"assurance_type": {
				Type:        schema.TypeString,
				Description: "What type of assurance policy is described.",
				Optional:    true,
				Computed:    true,
			},

			"id": {
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "Name of user account that created the policy.",
				Computed:    true,
				Optional:    true,
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
				Optional: true,
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
				Description: "",
				Optional:    true,
			},
			//JSON
			"lastupdate": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
				Computed:    true,
			}, // String
			"custom_severity": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
				Computed:    true,
			}, // string
			"vulnerability_exploitability": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"disallow_exploit_types": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			}, // list
			"ignore_base_image_vln": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"ignored_sensitive_resources": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"permission": {
				Type:        schema.TypeString,
				Description: "",
				Optional:    true,
				Computed:    true,
			}, // string
			"scan_malware_in_archives": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"kubernetes_controls": {
				Type:        schema.TypeList,
				Description: "List of Kubernetes controls.",
				Optional:    true,
				MaxItems:    1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"script_id": {
							Type:        schema.TypeInt,
							Description: "",
							Optional:    true,
						},
						"name": {
							Type:        schema.TypeString,
							Description: "",
							Optional:    true,
						},
						"description": {
							Type:        schema.TypeString,
							Description: "",
							Optional:    true,
						},
						"enabled": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"severity": {
							Type:        schema.TypeString,
							Description: "",
							Optional:    true,
						},
						"kind": {
							Type:        schema.TypeString,
							Description: "",
							Optional:    true,
						},
						"ootb": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"avd_id": {
							Type:        schema.TypeString,
							Description: "",
							Optional:    true,
						},
					},
				},
			},
			"kubernetes_controls_names": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"scan_windows_registry": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"scan_process_memory": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"policy_settings": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enforce": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"warn": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
						"warning_message": {
							Type:        schema.TypeString,
							Description: "",
							Optional:    true,
						},
						"is_audit_checked": {
							Type:        schema.TypeBool,
							Description: "",
							Optional:    true,
						},
					},
				},
				Optional: true,
			}, // list
			"exclude_application_scopes": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"linux_cis_enabled": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"openshift_hardening_enabled": {
				Type:        schema.TypeBool,
				Description: "",
				Optional:    true,
			}, //bool
			"kubernetes_controls_avd_ids": {
				Type:        schema.TypeList,
				Description: "",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			}, // list
			"vulnerability_score_range": {
				Type:        schema.TypeList,
				Description: "",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
			}, // list
			"aggregated_vulnerability": {
				Type:        schema.TypeMap,
				Description: "Aggregated vulnerability information.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourceFunctionAssurancePolicyCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	assurance_type := "function"

	iap := expandAssurancePolicy(d, assurance_type)
	err := ac.CreateAssurancePolicy(iap, assurance_type)

	if err != nil {
		return err
	}
	d.SetId(name)
	return resourceFunctionAssurancePolicyRead(d, m)

}

func resourceFunctionAssurancePolicyUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	assurance_type := "function"

	if d.HasChanges("description",
		"registry",
		"cvss_severity_enabled",
		"cvss_severity",
		"cvss_severity_exclude_no_fix",
		"custom_severity_enabled",
		"maximum_score_enabled",
		"maximum_score",
		"control_exclude_no_fix",
		"custom_checks_enabled",
		"scap_enabled",
		"cves_black_list_enabled",
		"packages_black_list_enabled",
		"packages_white_list_enabled",
		"only_none_root_users",
		"trusted_base_images_enabled",
		"scan_sensitive_data",
		"audit_on_failure",
		"fail_cicd",
		"block_failed",
		"disallow_malware",
		"monitored_malware_paths",
		"exceptional_monitored_malware_paths",
		"blacklisted_licenses_enabled",
		"blacklisted_licenses",
		"whitelisted_licenses_enabled",
		"whitelisted_licenses",
		"custom_checks",
		"scap_files",
		"scope",
		"registries",
		"labels",
		"images",
		"cves_black_list",
		"packages_black_list",
		"packages_white_list",
		"allowed_images",
		"trusted_base_images",
		"read_only",
		"force_microenforcer",
		"docker_cis_enabled",
		"kube_cis_enabled",
		"enforce_excessive_permissions",
		"function_integrity_enabled",
		"dta_enabled",
		"cves_white_list",
		"cves_white_list_enabled",
		"blacklist_permissions_enabled",
		"blacklist_permissions",
		"enabled",
		"enforce",
		"enforce_after_days",
		"ignore_recently_published_vln",
		"ignore_recently_published_vln_period",
		"ignore_risk_resources_enabled",
		"ignored_risk_resources",
		"application_scopes",
		"auto_scan_enabled",
		"auto_scan_configured",
		"auto_scan_time",
		"required_labels_enabled",
		"required_labels",
		"forbidden_labels_enabled",
		"forbidden_labels",
		"domain_name",
		"domain",
		"description",
		"dta_severity",
		"scan_nfs_mounts",
		"malware_action",
		"partial_results_image_fail",
		"maximum_score_exclude_no_fix",
		//JSOT
		//"author",
		"lastupdate",
		"custom_severity",
		"vulnerability_exploitability",
		"disallow_exploit_types",
		"ignore_base_image_vln",
		"ignored_sensitive_resources",
		"permission",
		"scan_malware_in_archives",
		"kubernetes_controls",
		"kubernetes_controls_names",
		"scan_windows_registry",
		"scan_process_memory",
		"policy_settings",
		"exclude_application_scopes",
		"linux_cis_enabled",
		"openshift_hardening_enabled",
		"kubernetes_controls_avd_ids",
	) {
		iap := expandAssurancePolicy(d, assurance_type)
		err := ac.UpdateAssurancePolicy(iap, assurance_type)
		if err == nil {
			err1 := resourceFunctionAssurancePolicyRead(d, m)
			if err1 == nil {
				d.SetId(iap.Name)
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
	assurance_type := "function"

	iap, err := ac.GetAssurancePolicy(d.Id(), assurance_type)

	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return err
	}

	d.Set("assurance_type", iap.AssuranceType)
	d.Set("name", iap.Name)
	d.Set("description", iap.Description)
	//d.Set("author", iap.Author)
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
	d.Set("packages_black_list", flattenPackages(iap.PackagesBlackList))
	d.Set("packages_white_list", flattenPackages(iap.PackagesWhiteList))
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
	d.Set("required_labels", flattenLabels(iap.RequiredLabels))
	d.Set("forbidden_labels_enabled", iap.ForbiddenLabelsEnabled)
	d.Set("forbidden_labels", flattenLabels(iap.ForbiddenLabels))
	d.Set("domain_name", iap.DomainName)
	d.Set("domain", iap.Domain)
	d.Set("dta_severity", iap.DtaSeverity)
	d.Set("scan_nfs_mounts", iap.ScanNfsMounts)
	d.Set("malware_action", iap.MalwareAction)
	d.Set("partial_results_image_fail", iap.PartialResultsImageFail)
	d.Set("maximum_score_exclude_no_fix", iap.MaximumScoreExcludeNoFix)
	//JSON
	//d.Set("lastupdate", iap.Lastupdate)
	d.Set("custom_severity", iap.CustomSeverity)
	d.Set("vulnerability_exploitability", iap.VulnerabilityExploitability)
	d.Set("disallow_exploit_types", iap.DisallowExploitTypes)
	d.Set("ignore_base_image_vln", iap.IgnoreBaseImageVln)
	d.Set("ignored_sensitive_resources", iap.IgnoredSensitiveResources)
	d.Set("permission", iap.Permission)
	d.Set("scan_malware_in_archives", iap.ScanMalwareInArchives)
	d.Set("kubernetes_controls", flattenKubernetesControls(iap.KubernetesControls))
	d.Set("kubernetes_controls_names", iap.KubernetesControlsNames)
	d.Set("scan_windows_registry", iap.ScanWindowsRegistry)
	d.Set("scan_process_memory", iap.ScanProcessMemory)
	d.Set("policy_settings", flattenPolicySettings(iap.PolicySettings))
	d.Set("exclude_application_scopes", iap.ExcludeApplicationScopes)
	d.Set("linux_cis_enabled", iap.LinuxCisEnabled)
	d.Set("openshift_hardening_enabled", iap.OpenshiftHardeningEnabled)
	d.Set("kubernetes_controls_avd_ids", iap.KubernetesControlsAvdIds)

	return nil
}

func resourceFunctionAssurancePolicyDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	assurance_type := "function"
	err := ac.DeleteAssurancePolicy(name, assurance_type)

	if err == nil {
		d.SetId("")
	} else {
		return err
	}
	return nil
}
