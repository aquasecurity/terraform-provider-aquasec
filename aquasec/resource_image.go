package aquasec

import (
	"context"
	"errors"
	"fmt"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceImage() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceImageCreate,
		ReadContext:   resourceImageRead,
		UpdateContext: resourceImageUpdate,
		DeleteContext: resourceImageDelete,
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
			"allow_image": {
				Type:         schema.TypeBool,
				Description:  "If this field is set to true, the image will be whitelisted.",
				Optional:     true,
				RequiredWith: []string{"permission_modification_comment"},
			},
			"block_image": {
				Type:         schema.TypeBool,
				Description:  "If this field is set to true, the image will be blacklisted.",
				Optional:     true,
				RequiredWith: []string{"permission_modification_comment"},
			},
			"permission_modification_comment": {
				Type:        schema.TypeString,
				Description: "A comment on why the image was whitelisted or blacklisted",
				Optional:    true,
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

func resourceImageCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var err error
	c := m.(*client.Client)
	image := expandImage(d)

	err = c.CreateImage(image)
	if err != nil {
		return diag.FromErr(err)
	}

	//d.SetId(getImageId(image))

	err1 := resourceImageRead(ctx, d, m)
	if err1 == nil {
		d.SetId(getImageId(image))
	} else {
		return err1
	}

	return nil
	//return resourceImageRead(ctx, d, m)
}

func resourceImageRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var err error
	c := m.(*client.Client)
	image := expandImage(d)

	newImage, err := c.GetImage(image)
	if err != nil {
		return diag.FromErr(err)
	}

	vulnerabilities, err := c.GetVulnerabilities(image)
	if err == nil {
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
	} else {
		return diag.FromErr(err)
	}

	return nil
}

func resourceImageUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var err error
	c := m.(*client.Client)

	image := expandImage(d)
	if d.HasChanges("allow_image", "block_image") {
		spec, ok := d.GetOk("permission_modification_comment")
		if !ok {
			return diag.FromErr(errors.New("permission_modification_comment must be set to allow/block an image"))
		}
		permissionModificationImage := spec.(string)

		var allowImage, blockImage bool

		spec, ok = d.GetOk("allow_image")
		if ok {
			allowImage = spec.(bool)
		}

		spec, ok = d.GetOk("block_image")
		if ok {
			blockImage = spec.(bool)
		}

		if allowImage && blockImage {
			return diag.FromErr(errors.New("both allow_image and block_image can't be true together"))
		}

		if allowImage {
			err = c.ChangeImagePermission(image, true, permissionModificationImage)
			if err != nil {
				return diag.FromErr(err)
			}
		}

		if blockImage {
			err = c.ChangeImagePermission(image, false, permissionModificationImage)
			if err != nil {
				return diag.FromErr(err)
			}
		}
	}

	d.SetId(getImageId(image))

	return resourceImageRead(ctx, d, m)
}

func resourceImageDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var err error
	c := m.(*client.Client)

	image := expandImage(d)
	err = c.DeleteImage(image)
	if err == nil {
		d.SetId("")
	} else {
		return diag.FromErr(err)
	}

	//d.SetId("")

	return nil
}

func expandImage(d *schema.ResourceData) *client.Image {
	image := client.Image{
		Registry:          d.Get("registry").(string),
		Repository:        d.Get("repository").(string),
		Tag:               d.Get("tag").(string),
		PermissionComment: d.Get("permission_comment").(string),
		Disallowed:        d.Get("disallowed").(bool),
	}

	return &image
}

func getImageId(image *client.Image) string {
	return fmt.Sprintf("%v/%v:%v", image.Registry, image.Repository, image.Tag)
}

func flattenHistory(histories []client.History) []map[string]interface{} {
	specs := make([]map[string]interface{}, len(histories))
	for i := range histories {
		specs[i] = map[string]interface{}{
			"id":         histories[i].ID,
			"size":       histories[i].Size,
			"comment":    histories[i].Comment,
			"created":    histories[i].Created,
			"created_by": histories[i].CreatedBy,
		}
	}

	return specs
}

func flattenAssuranceChecksPerformed(checksPerformed []client.ChecksPerformed) []map[string]interface{} {
	specs := make([]map[string]interface{}, len(checksPerformed))

	for i := range checksPerformed {
		specs[i] = map[string]interface{}{
			"policy_name":        checksPerformed[i].PolicyName,
			"assurance_type":     checksPerformed[i].AssuranceType,
			"failed":             checksPerformed[i].Failed,
			"blocking":           checksPerformed[i].Blocking,
			"control":            checksPerformed[i].Control,
			"dta_skipped":        checksPerformed[i].DtaSkipped,
			"dta_skipped_reason": checksPerformed[i].DtaSkippedReason,
		}
	}

	return specs
}

func flattenVulnerabilities(vulnerabilities []client.Vulnerabilities) []map[string]interface{} {
	specs := make([]map[string]interface{}, len(vulnerabilities))

	for i := range vulnerabilities {
		specs[i] = map[string]interface{}{
			"name":                         vulnerabilities[i].Name,
			"description":                  vulnerabilities[i].Description,
			"publish_date":                 vulnerabilities[i].PublishDate,
			"modification_date":            vulnerabilities[i].ModificationDate,
			"vendor_severity":              vulnerabilities[i].VendorSeverity,
			"vendor_cvss2_score":           vulnerabilities[i].VendorCvss2Score,
			"vendor_cvss2_vectors":         vulnerabilities[i].VendorCvss2Vectors,
			"vendor_statement":             vulnerabilities[i].VendorStatement,
			"vendor_url":                   vulnerabilities[i].VendorURL,
			"nvd_severity":                 vulnerabilities[i].NvdSeverity,
			"nvd_cvss2_score":              vulnerabilities[i].NvdCvss2Score,
			"nvd_cvss2_vectors":            vulnerabilities[i].NvdCvss2Vectors,
			"nvd_cvss3_severity":           vulnerabilities[i].NvdCvss3Severity,
			"nvd_cvss3_score":              vulnerabilities[i].NvdCvss3Score,
			"nvd_cvss3_vectors":            vulnerabilities[i].NvdCvss3Vectors,
			"nvd_url":                      vulnerabilities[i].NvdURL,
			"fix_version":                  vulnerabilities[i].FixVersion,
			"solution":                     vulnerabilities[i].Solution,
			"classification":               vulnerabilities[i].Classification,
			"aqua_score":                   vulnerabilities[i].AquaScore,
			"aqua_severity":                vulnerabilities[i].AquaSeverity,
			"aqua_vectors":                 vulnerabilities[i].AquaVectors,
			"aqua_scoring_system":          vulnerabilities[i].AquaScoringSystem,
			"first_found_date":             vulnerabilities[i].FirstFoundDate,
			"last_found_date":              vulnerabilities[i].LastFoundDate,
			"ancestor_pkg":                 vulnerabilities[i].AncestorPkg,
			"severity_classification":      vulnerabilities[i].SeverityClassification,
			"aqua_severity_classification": vulnerabilities[i].AquaSeverityClassification,
			"aqua_score_classification":    vulnerabilities[i].AquaScoreClassification,
			"exploit_reference":            vulnerabilities[i].Exploitability,
			"temporal_vector":              vulnerabilities[i].TemporalVector,
			"exploit_type":                 vulnerabilities[i].ExploitType,
			"v_patch_applied_by":           vulnerabilities[i].VPatchAppliedBy,
			"v_patch_applied_on":           vulnerabilities[i].VPatchAppliedOn,
			"v_patch_reverted_by":          vulnerabilities[i].VPatchRevertedBy,
			"v_patch_reverted_on":          vulnerabilities[i].VPatchRevertedOn,
			"v_patch_enforced_by":          vulnerabilities[i].VPatchEnforcedBy,
			"v_patch_enforced_on":          vulnerabilities[i].VPatchEnforcedOn,
			"v_patch_status":               vulnerabilities[i].VPatchStatus,
			"acknowledge_date":             vulnerabilities[i].AcknowledgedDate,
			"ack_scope":                    vulnerabilities[i].AckScope,
			"ack_comment":                  vulnerabilities[i].AckComment,
			"ack_author":                   vulnerabilities[i].AckAuthor,
			"ack_expiration_days":          vulnerabilities[i].AckExpirationDays,
			"ack_expiration_configured_at": vulnerabilities[i].AckExpirationConfiguredAt,
			"ack_expiration_configured_by": vulnerabilities[i].AckExpirationConfiguredBy,
			"v_patch_policy_name":          vulnerabilities[i].VPatchPolicyName,
			"v_patch_policy_enforce":       vulnerabilities[i].VPatchPolicyEnforce,
			"audit_events_count":           vulnerabilities[i].AuditEventsCount,
			"block_events_count":           vulnerabilities[i].BlockEventsCount,
			"registry":                     vulnerabilities[i].Registry,
			"repository":                   vulnerabilities[i].ImageRepositoryName,
			"image_name":                   vulnerabilities[i].ImageName,
			"digest":                       vulnerabilities[i].ImageDigest,
			"os":                           vulnerabilities[i].Os,
			"os_version":                   vulnerabilities[i].OsVersion,
			"permission":                   vulnerabilities[i].Permission,
			"resource_type":                vulnerabilities[i].Resource.Type,
			"resource_format":              vulnerabilities[i].Resource.Format,
			"resource_path":                vulnerabilities[i].Resource.Path,
			"resource_name":                vulnerabilities[i].Resource.Name,
			"resource_version":             vulnerabilities[i].Resource.Version,
			"resource_architecture":        vulnerabilities[i].Resource.Arch,
			"resource_hash":                vulnerabilities[i].Resource.Hash,
			"resource_licenses":            vulnerabilities[i].Resource.Licenses,
		}
	}

	return specs
}
