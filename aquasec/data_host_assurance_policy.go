package aquasec

import (
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strings"
)

func dataHostAssurancePolicy() *schema.Resource {
	return &schema.Resource{
		Description: "Host Assurance is a subsystem of Aqua. It is responsible for:\n Scans host VMs and Kubernetes nodes' file system for security issues, vulnerabilities in OS and programming language packages, open-source licenses, and compliance with CIS benchmarks.\nEvaluates scan findings according to defined Host Assurance Policies.\nDetermines host compliance based on these policies.\nGenerates an audit event for host assurance failure.",
		Read:        dataHostAssurancePolicyRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"assurance_type": {
				Type:        schema.TypeString,
				Description: "What type of assurance policy is described.",
				Computed:    true,
			},
			"description": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "Name of user account that created the policy.",
				Computed:    true,
			},
			"application_scopes": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"policy_settings": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enforce": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"warn": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"warning_message": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"is_audit_checked": {
							Type:     schema.TypeBool,
							Computed: true,
						},
					},
				},
			},
			// Security Controls
			"linux_cis_enabled": {
				Type:        schema.TypeBool,
				Description: "Enables Linux CIS benchmark checks.",
				Computed:    true,
			},
			"windows_cis_enabled": {
				Type:        schema.TypeBool,
				Description: "Enables Windows CIS benchmark checks.",
				Computed:    true,
			},
			"docker_cis_enabled": {
				Type:        schema.TypeBool,
				Description: "Enables Docker CIS benchmark checks.",
				Computed:    true,
			},
			"kube_cis_enabled": {
				Type:        schema.TypeBool,
				Description: "Enables Kubernetes CIS benchmark checks.",
				Computed:    true,
			},
			"openshift_hardening_enabled": {
				Type:        schema.TypeBool,
				Description: "Enables OpenShift hardening checks.",
				Computed:    true,
			},
			
			// Malware Settings
			"scan_malware_in_archives": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"scan_windows_registry": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"scan_process_memory": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"disallow_malware": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"monitored_malware_paths": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"exceptional_monitored_malware_paths": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"malware_action": {
				Type:     schema.TypeString,
				Computed: true,
			},

			// Vulnerability Controls
			"vulnerability_exploitability": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"disallow_exploit_types": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"vulnerability_score_range": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
			},
			"maximum_score_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"maximum_score": {
				Type:     schema.TypeFloat,
				Computed: true,
			},
			"maximum_score_exclude_no_fix": {
				Type:     schema.TypeBool,
				Computed: true,
			},

			// Additional Security Options
			"scan_nfs_mounts": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"scan_sensitive_data": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"partial_results_image_fail": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"force_microenforcer": {
				Type:     schema.TypeBool,
				Computed: true,
			},

			// Scoping and Control
			"domain": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"domain_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"exclude_application_scopes": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
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
							Computed: true,
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

			// Auto Scan Configuration
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

			// Other settings carried over from resource
			"lastupdate": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"custom_severity": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"permission": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"kubernetes_controls": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"kubernetes_controls_names": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"kubernetes_controls_avd_ids": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func dataHostAssurancePolicyRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	assurance_type := "host"

	iap, err := ac.GetAssurancePolicy(name, assurance_type)
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "not found") {
			d.SetId("")
			return nil
		}
		return err
	}

	d.SetId(fmt.Sprintf("%d", iap.Id))
	d.Set("description", iap.Description)
	d.Set("assurance_type", iap.AssuranceType)
	d.Set("author", iap.Author)
	d.Set("application_scopes", iap.ApplicationScopes)
	
	// Policy Settings
	d.Set("policy_settings", flattenPolicySettings(iap.PolicySettings))
	
	// Security Controls
	d.Set("linux_cis_enabled", iap.LinuxCisEnabled)
	d.Set("windows_cis_enabled", iap.WindowsCisEnabled)
	d.Set("docker_cis_enabled", iap.DockerCisEnabled)
	d.Set("kube_cis_enabled", iap.KubeCisEnabled)
	d.Set("openshift_hardening_enabled", iap.OpenshiftHardeningEnabled)
	
	// Malware Settings
	d.Set("scan_malware_in_archives", iap.ScanMalwareInArchives)
	d.Set("scan_windows_registry", iap.ScanWindowsRegistry)
	d.Set("scan_process_memory", iap.ScanProcessMemory)
	d.Set("disallow_malware", iap.DisallowMalware)
	d.Set("monitored_malware_paths", iap.MonitoredMalwarePaths)
	d.Set("exceptional_monitored_malware_paths", iap.ExceptionalMonitoredMalwarePaths)
	d.Set("malware_action", iap.MalwareAction)
	
	// Vulnerability Controls
	d.Set("vulnerability_exploitability", iap.VulnerabilityExploitability)
	d.Set("disallow_exploit_types", iap.DisallowExploitTypes)
	d.Set("vulnerability_score_range", iap.VulnerabilityScoreRange)
	d.Set("maximum_score_enabled", iap.MaximumScoreEnabled)
	d.Set("maximum_score", iap.MaximumScore)
	d.Set("maximum_score_exclude_no_fix", iap.MaximumScoreExcludeNoFix)
	
	// Additional Security Options
	d.Set("scan_nfs_mounts", iap.ScanNfsMounts)
	d.Set("scan_sensitive_data", iap.ScanSensitiveData)
	d.Set("partial_results_image_fail", iap.PartialResultsImageFail)
	d.Set("force_microenforcer", iap.ForceMicroenforcer)
	
	// Scoping and Control
	d.Set("domain", iap.Domain)
	d.Set("domain_name", iap.DomainName)
	d.Set("exclude_application_scopes", iap.ExcludeApplicationScopes)
	d.Set("scope", flatteniapscope(iap.Scope))
	
	// Auto Scan Configuration
	d.Set("auto_scan_enabled", iap.AutoScanEnabled)
	d.Set("auto_scan_configured", iap.AutoScanConfigured)
	d.Set("auto_scan_time", flattenAutoScanTime(iap.AutoScanTime))
	
	// Other settings
	d.Set("lastupdate", iap.Lastupdate)
	d.Set("custom_severity", iap.CustomSeverity)
	d.Set("permission", iap.Permission)
	d.Set("kubernetes_controls", iap.KubernetesControls)
	d.Set("kubernetes_controls_names", iap.KubernetesControlsNames)
	d.Set("kubernetes_controls_avd_ids", iap.KubernetesControlsAvdIds)

	return nil
}