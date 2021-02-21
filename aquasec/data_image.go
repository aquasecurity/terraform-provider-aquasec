package aquasec

import (
	"context"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataImage() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataImageRead,
		Schema: map[string]*schema.Schema{
			"registry": {
				Type:        schema.TypeString,
				Description: "The name of the registry where the image is stored.",
				Required:    true,
			},
			"registry_type": {
				Type:        schema.TypeString,
				Description: "Type of the registry.",
				Computed:    true,
			},
			"repository": {
				Type:        schema.TypeString,
				Description: "The name of the image's repository.",
				Required:    true,
			},
			"tag": {
				Type:        schema.TypeString,
				Description: "The tag of the image.",
				Required:    true,
			},
			"disallowed": {
				Type:        schema.TypeBool,
				Description: "Whether the image is disallowed (non-compliant).",
				Computed:    true,
			},
			"permission_comment": {
				Type:        schema.TypeString,
				Description: "The comment provided when the image permissions were last modified",
				Computed:    true,
			},
			"labels": {
				Type:        schema.TypeList,
				Description: "Aqua labels of the image.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"docker_id": {
				Type:        schema.TypeString,
				Description: "The Docker image ID.",
				Computed:    true,
			},
			"parent": {
				Type:        schema.TypeString,
				Description: "The ID of the parent image.",
				Computed:    true,
			},
			"repo_digests": {
				Type:        schema.TypeList,
				Description: "The repository digests.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"comment": {
				Type:        schema.TypeString,
				Description: "The image creation comment.",
				Computed:    true,
			},
			"created": {
				Type:        schema.TypeString,
				Description: "The date and time when the image was registered.",
				Computed:    true,
			},
			"docker_version": {
				Type:        schema.TypeString,
				Description: "The Docker version used when building the image.",
				Computed:    true,
			},
			"architecture": {
				Type:        schema.TypeString,
				Description: "The image architecture.",
				Computed:    true,
			},
			"virtual_size": {
				Type:        schema.TypeInt,
				Description: "The virtual size of the image.",
				Computed:    true,
			},
			"default_user": {
				Type:        schema.TypeString,
				Description: "The default user of the image.",
				Computed:    true,
			},
			"environment_variables": {
				Type:        schema.TypeList,
				Description: "Environment variables in the image.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"docker_labels": {
				Type:        schema.TypeList,
				Description: "Docker labels of the image.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"image_type": {
				Type:        schema.TypeString,
				Description: "The type of the image.",
				Computed:    true,
			},
			"digest": {
				Type:        schema.TypeString,
				Description: "The content digest of the image.",
				Computed:    true,
			},
			"scan_status": {
				Type:        schema.TypeString,
				Description: "The scan status of the image (either 'pending', 'in_progress', 'finished', 'failed' or 'not_started').",
				Computed:    true,
			},
			"scan_date": {
				Type:        schema.TypeString,
				Description: "The date and time when the image was last scanned.",
				Computed:    true,
			},
			"scan_error": {
				Type:        schema.TypeString,
				Description: "If the image scan failed, the failure message.",
				Computed:    true,
			},
			"critical_vulnerabilities": {
				Type:        schema.TypeInt,
				Description: "Number of critical severity vulnerabilities detected in the image.",
				Computed:    true,
			},
			"high_vulnerabilities": {
				Type:        schema.TypeInt,
				Description: "Number of high severity vulnerabilities detected in the image.",
				Computed:    true,
			},
			"medium_vulnerabilities": {
				Type:        schema.TypeInt,
				Description: "Number of medium severity vulnerabilities detected in the image.",
				Computed:    true,
			},
			"low_vulnerabilities": {
				Type:        schema.TypeInt,
				Description: "Number of low severity vulnerabilities detected in the image.",
				Computed:    true,
			},
			"negligible_vulnerabilities": {
				Type:        schema.TypeInt,
				Description: "Number of negligible severity vulnerabilities detected in the image.",
				Computed:    true,
			},
			"total_vulnerabilities": {
				Type:        schema.TypeInt,
				Description: "The total number of vulnerabilities detected in the image.",
				Computed:    true,
			},
			"image_size": {
				Type:        schema.TypeInt,
				Description: "The size of the image in bytes.",
				Computed:    true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "The name of the user who registered the image.",
				Computed:    true,
			},
			"os": {
				Type:        schema.TypeString,
				Description: "The operating system detected in the image",
				Computed:    true,
			},
			"os_version": {
				Type:        schema.TypeString,
				Description: "The version of the OS detected in the image.",
				Computed:    true,
			},
			"sensitive_data": {
				Type:        schema.TypeInt,
				Description: "Number of sensitive data detected in the image.",
				Computed:    true,
			},
			"malware": {
				Type:        schema.TypeInt,
				Description: "Number of malware found on the image.",
				Computed:    true,
			},
			"whitelisted": {
				Type:        schema.TypeBool,
				Description: "Whether the image is whitelisted.",
				Computed:    true,
			},
			"blacklisted": {
				Type:        schema.TypeBool,
				Description: "Whether the image is blacklisted.",
				Computed:    true,
			},
			"permission_author": {
				Type:        schema.TypeString,
				Description: "The name of the user who last modified the image permissions.",
				Computed:    true,
			},
			"permission": {
				Type:        schema.TypeString,
				Description: "Permission of the image.",
				Computed:    true,
			},
			"newer_image_exists": {
				Type:        schema.TypeBool,
				Description: "Whether a new version of the image is available in the registry but is not scanned and registered yet.",
				Computed:    true,
			},
			"partial_results": {
				Type:        schema.TypeBool,
				Description: "Whether the image could only be partially scanned.",
				Computed:    true,
			},
			"name": {
				Type:        schema.TypeString,
				Description: "The name of the image.",
				Computed:    true,
			},
			"history": {
				Type:        schema.TypeList,
				Description: "The Docker history of the image.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Description: "The image ID of the layer (if any).",
							Computed:    true,
						},
						"size": {
							Type:        schema.TypeInt,
							Description: "The size of the image.",
							Computed:    true,
						},
						"comment": {
							Type:        schema.TypeString,
							Description: "The commit comment for the image, if any.",
							Computed:    true,
						},
						"created": {
							Type:        schema.TypeString,
							Description: "The date of creation of the layer.",
							Computed:    true,
						},
						"created_by": {
							Type:        schema.TypeString,
							Description: "The command that generated the layer.",
							Computed:    true,
						},
					},
				},
			},
			"pending_disallowed": {
				Type:        schema.TypeBool,
				Description: "Whether the image is non-compliant, but is pending this status due to running containers.",
				Computed:    true,
			},
			"dta_severity_score": {
				Type:        schema.TypeString,
				Description: "DTA severity score.",
				Computed:    true,
			},
			"dta_skipped": {
				Type:        schema.TypeBool,
				Description: "If DTA was skipped.",
				Computed:    true,
			},
			"dta_skipped_reason": {
				Type:        schema.TypeString,
				Description: "The reason why DTA was skipped.",
				Computed:    true,
			},
			"disallowed_by_assurance_checks": {
				Type:        schema.TypeBool,
				Description: "Whether the image was disallowed because of Image Assurance Policies.",
				Computed:    true,
			},
			"assurance_checks_performed": {
				Type:        schema.TypeList,
				Description: "The list of image assurance checks performed on the image.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"policy_name": {
							Type:        schema.TypeString,
							Description: "The name of the Image Assurance Policy the check originated from.",
							Computed:    true,
						},
						"assurance_type": {
							Type:        schema.TypeString,
							Description: "The type of the Assurance Policy the check originated from.",
							Computed:    true,
						},
						"failed": {
							Type:        schema.TypeBool,
							Description: "Whether the image failed the check.",
							Computed:    true,
						},
						"blocking": {
							Type:        schema.TypeBool,
							Description: "Whether the check is blocking (i.e. a failure should trigger a disallow).",
							Computed:    true,
						},
						"control": {
							Type:        schema.TypeString,
							Description: "The name of the image assurance control.",
							Computed:    true,
						},
						"dta_skipped": {
							Type:        schema.TypeBool,
							Description: "If DTA was skipped.",
							Computed:    true,
						},
						"dta_skipped_reason": {
							Type:        schema.TypeString,
							Description: "The reason why DTA was skipped.",
							Computed:    true,
						},
					},
				},
			},
			"vulnerabilities": {
				Type:        schema.TypeList,
				Description: "A list of all the vulnerabilities found in the image",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Description: "The name of the vulnerability.",
							Computed:    true,
						},
						"description": {
							Type:        schema.TypeString,
							Description: "The description of the vulnerability.",
							Computed:    true,
						},
						"publish_date": {
							Type:        schema.TypeString,
							Description: "The date this vulnerability was published.",
							Computed:    true,
						},
						"modification_date": {
							Type:        schema.TypeString,
							Description: "Thhe date when this vulnerability was modified.",
							Computed:    true,
						},
						"vendor_severity": {
							Type:        schema.TypeString,
							Description: "",
							Computed:    true,
						},
						"vendor_cvss2_score": {
							Type:        schema.TypeFloat,
							Description: "",
							Computed:    true,
						},
						"vendor_cvss2_vectors": {
							Type:        schema.TypeString,
							Description: "",
							Computed:    true,
						},
						"vendor_statement": {
							Type:        schema.TypeString,
							Description: "",
							Computed:    true,
						},
						"vendor_url": {
							Type:        schema.TypeString,
							Description: "",
							Computed:    true,
						},
						"nvd_severity": {
							Type:        schema.TypeString,
							Description: "Type of the severity identified by NVD.",
							Computed:    true,
						},
						"nvd_cvss2_score": {
							Type:        schema.TypeFloat,
							Description: "CVSS2 score by NVD",
							Computed:    true,
						},
						"nvd_cvss2_vectors": {
							Type:        schema.TypeString,
							Description: "CVSS2 vectors by NVD",
							Computed:    true,
						},
						"nvd_cvss3_severity": {
							Type:        schema.TypeString,
							Description: "CVSS3 severity by NVD",
							Computed:    true,
						},
						"nvd_cvss3_score": {
							Type:        schema.TypeFloat,
							Description: "CVSS3 score by NVD",
							Computed:    true,
						},
						"nvd_cvss3_vectors": {
							Type:        schema.TypeString,
							Description: "CVSS3 vectors by NVD",
							Computed:    true,
						},
						"nvd_url": {
							Type:        schema.TypeString,
							Description: "URL of the details of this vulnerability by NVD.",
							Computed:    true,
						},
						"fix_version": {
							Type:        schema.TypeString,
							Description: "Fixed version of the resource.",
							Computed:    true,
						},
						"solution": {
							Type:        schema.TypeString,
							Description: "Solution for the vulnerability.",
							Computed:    true,
						},
						"classification": {
							Type:        schema.TypeString,
							Description: "Classification of the vulnerability.",
							Computed:    true,
						},
						"aqua_score": {
							Type:        schema.TypeFloat,
							Description: "The score generated for the vulnerability by Aqua.",
							Computed:    true,
						},
						"aqua_severity": {
							Type:        schema.TypeString,
							Description: "The severity generated for the vulnerability by Aqua.",
							Computed:    true,
						},
						"aqua_vectors": {
							Type:        schema.TypeString,
							Description: "The vectors generated for the vulnerability by Aqua",
							Computed:    true,
						},
						"aqua_scoring_system": {
							Type:        schema.TypeString,
							Description: "The score system for the vulnerability by Aqua",
							Computed:    true,
						},
						"first_found_date": {
							Type:        schema.TypeString,
							Description: "The date when this vulnerability was first found.",
							Computed:    true,
						},
						"last_found_date": {
							Type:        schema.TypeString,
							Description: "The date when this vulnerability was last found.",
							Computed:    true,
						},
						"ancestor_pkg": {
							Type:        schema.TypeString,
							Description: "The ancestor of this package.",
							Computed:    true,
						},
						"severity_classification": {
							Type:        schema.TypeString,
							Description: "Classification of the severity.",
							Computed:    true,
						},
						"aqua_severity_classification": {
							Type:        schema.TypeString,
							Description: "Classification of the severity defined by Aqua.",
							Computed:    true,
						},
						"aqua_score_classification": {
							Type:        schema.TypeString,
							Description: "Score classification by Aqua.",
							Computed:    true,
						},
						"exploit_reference": {
							Type:        schema.TypeString,
							Description: "Reference of the exploit.",
							Computed:    true,
						},
						"temporal_vector": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"exploit_type": {
							Type:        schema.TypeString,
							Description: "Type of the exploit.",
							Computed:    true,
						},
						"v_patch_applied_by": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"v_patch_applied_on": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"v_patch_reverted_by": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"v_patch_reverted_on": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"v_patch_enforced_by": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"v_patch_enforced_on": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"v_patch_status": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"acknowledge_date": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ack_scope": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ack_comment": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ack_author": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ack_expiration_days": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"ack_expiration_configured_at": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ack_expiration_configured_by": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"v_patch_policy_name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"v_patch_policy_enforce": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"audit_events_count": {
							Type:        schema.TypeInt,
							Description: "Number of audit events.",
							Computed:    true,
						},
						"block_events_count": {
							Type:        schema.TypeInt,
							Description: "Number of blocked events.",
							Computed:    true,
						},
						"registry": {
							Type:        schema.TypeString,
							Description: "Registry of the image.",
							Computed:    true,
						},
						"repository": {
							Type:        schema.TypeString,
							Description: "Repository of the image.",
							Computed:    true,
						},
						"image_name": {
							Type:        schema.TypeString,
							Description: "Name of the image.",
							Computed:    true,
						},
						"digest": {
							Type:        schema.TypeString,
							Description: "The content digest of the image.",
							Computed:    true,
						},
						"os": {
							Type:        schema.TypeString,
							Description: "Name of the Operating System.",
							Computed:    true,
						},
						"os_version": {
							Type:        schema.TypeString,
							Description: "The version of the OS.",
							Computed:    true,
						},
						"permission": {
							Type:        schema.TypeString,
							Description: "permission on the image",
							Computed:    true,
						},
						"resource_type": {
							Type:        schema.TypeString,
							Description: "Type of the resource",
							Computed:    true,
						},
						"resource_format": {
							Type:        schema.TypeString,
							Description: "Code format of the resource (java, apk etc.).",
							Computed:    true,
						},
						"resource_path": {
							Type:        schema.TypeString,
							Description: "Path of the resource.",
							Computed:    true,
						},
						"resource_name": {
							Type:        schema.TypeString,
							Description: "Name of the resource.",
							Computed:    true,
						},
						"resource_version": {
							Type:        schema.TypeString,
							Description: "Version of the resource.",
							Computed:    true,
						},
						"resource_architecture": {
							Type:        schema.TypeString,
							Description: "Architecture of the resource.",
							Computed:    true,
						},
						"resource_cpe": {
							Type:        schema.TypeString,
							Description: "Common Platform Enumeration (CPE) of the resource.",
							Computed:    true,
						},
						"resource_hash": {
							Type:        schema.TypeString,
							Description: "Hash of the resource.",
							Computed:    true,
						},
						"resource_licenses": {
							Type:        schema.TypeList,
							Description: "List of license supported by the resource.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
					},
				},
				Computed: true,
			},
		},
	}
}

func dataImageRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var err error
	c := m.(*client.Client)
	image := expandImage(d)

	err = c.WaitUntilScanCompleted(image)
	if err != nil {
		return diag.FromErr(err)
	}

	newImage, err := c.GetImage(image)
	if err != nil {
		return diag.FromErr(err)
	}

	vulnerabilities, err := c.GetVulnerabilities(image)
	if err != nil {
		return diag.FromErr(err)
	}

	d.Set("registry", newImage.Registry)
	d.Set("registry_type", newImage.RegistryType)
	d.Set("repository", newImage.Repository)
	d.Set("tag", newImage.Tag)
	d.Set("scan_status", newImage.ScanStatus)
	d.Set("scan_date", newImage.ScanDate)
	d.Set("scan_error", newImage.ScanError)
	d.Set("digest", newImage.Digest)
	d.Set("labels", newImage.Labels)
	d.Set("docker_id", newImage.Metadata.DockerID)
	d.Set("parent", newImage.Metadata.Parent)
	d.Set("repo_digests", newImage.Metadata.RepoDigests)
	d.Set("comment", newImage.Metadata.Comment)
	d.Set("created", newImage.Metadata.Created)
	d.Set("docker_version", newImage.Metadata.DockerVersion)
	d.Set("architecture", newImage.Metadata.Architecture)
	d.Set("virtual_size", newImage.Metadata.VirtualSize)
	d.Set("default_user", newImage.Metadata.DefaultUser)
	d.Set("environment_variables", newImage.Metadata.Env)
	d.Set("docker_labels", newImage.Metadata.DockerLabels)
	d.Set("image_type", newImage.Metadata.ImageType)
	d.Set("critical_vulnerabilities", newImage.CritVulns)
	d.Set("high_vulnerabilities", newImage.HighVulns)
	d.Set("medium_vulnerabilities", newImage.MedVulns)
	d.Set("low_vulnerabilities", newImage.LowVulns)
	d.Set("negligible_vulnerabilities", newImage.NegVulns)
	d.Set("total_vulnerabilities", newImage.VulnsFound)
	d.Set("sensitive_data", newImage.SensitiveData)
	d.Set("malware", newImage.Malware)
	d.Set("image_size", newImage.Size)
	d.Set("author", newImage.Author)
	d.Set("os", newImage.Os)
	d.Set("os_version", newImage.OsVersion)
	d.Set("disallowed", newImage.Disallowed)
	d.Set("whitelisted", newImage.Whitelisted)
	d.Set("blacklisted", newImage.Blacklisted)
	d.Set("permission_author", newImage.PermissionAuthor)
	d.Set("permission", newImage.Permission)
	d.Set("permission_comment", newImage.PermissionComment)
	d.Set("newer_image_exists", newImage.NewerImageExists)
	d.Set("partial_results", newImage.PartialResults)
	d.Set("name", newImage.Name)
	d.Set("pending_disallowed", newImage.PendingDisallowed)
	d.Set("dta_severity_score", newImage.DtaSeverityScore)
	d.Set("dta_skipped", newImage.DtaSkipped)
	d.Set("dta_skipped_reason", newImage.DtaSkippedReason)
	d.Set("disallowed_by_assurance_checks", newImage.AssuranceResults.Disallowed)
	d.Set("assurance_checks_performed", flattenAssuranceChecksPerformed(newImage.AssuranceResults.ChecksPerformed))
	d.Set("history", flattenHistory(newImage.History))
	d.Set("vulnerabilities", flattenVulnerabilities(vulnerabilities))

	d.SetId(getImageId(newImage))

	return nil
}
