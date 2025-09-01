package aquasec

import (
	"context"
	"fmt"
	"log"
	"math/rand"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceAcknowledges() *schema.Resource {
	return &schema.Resource{
		Description: "The data source `aquasec_acknowledges` provides a method to query all acknowledges within the Aqua ",
		ReadContext: dataAcknowledgesRead,
		Schema: map[string]*schema.Schema{
			"acknowledges": {
				Type:        schema.TypeList,
				Description: "A list of existing security acknowledges.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"issue_type": {
							Type:        schema.TypeString,
							Description: "The type of the security issue (either 'vulnerability', 'sensitive_data' or 'malware')",
							Computed:    true,
						},
						"resource_type": {
							Type:        schema.TypeString,
							Description: "The type of the resource where the issue was detected (either 'package', 'file' or 'executable')",
							Computed:    true,
						},
						"image_name": {
							Type:        schema.TypeString,
							Description: "Only acknowledge the issue in the context of the specified image (also requires 'registry_name')",
							Computed:    true,
						},
						"registry_name": {
							Type:        schema.TypeString,
							Description: "Only acknowledge the issue in the context of the specified repository (also requires 'registry_name').",
							Computed:    true,
						},
						"resource_name": {
							Type:        schema.TypeString,
							Description: "When the resource_type is 'package', the name of the package is required.",
							Computed:    true,
						},
						"resource_version": {
							Type:        schema.TypeString,
							Description: "When the resource_type is 'package', the version of the package is required",
							Computed:    true,
						},
						"resource_format": {
							Type:        schema.TypeString,
							Description: "The format of the resource.",
							Computed:    true,
						},
						"resource_cpe": {
							Type:        schema.TypeString,
							Description: "The CPE of the resource as listed in the issue by the Aqua API. This is required for resources of type 'executable'. For packages and files, the next parameters can be specified instead.",
							Computed:    true,
						},
						"resource_path": {
							Type:        schema.TypeString,
							Description: "The path of the resource. This is required for resources of type 'file' and 'executable'.",
							Computed:    true,
						},
						"resource_hash": {
							Type:        schema.TypeString,
							Description: "When the resource_type is 'file', the hash of the file is required",
							Computed:    true,
						},
						"issue_name": {
							Type:        schema.TypeString,
							Description: "The name of the security issue (the CVE or security advisory for vulnerabilities, name of malware or type of sensitive data)",
							Computed:    true,
						},
						"comment": {
							Type:        schema.TypeString,
							Description: "A comment describing the reason for the acknowledgment",
							Computed:    true,
						},
						"author": {
							Type:        schema.TypeString,
							Description: "The user who acknowledged the issue.",
							Computed:    true,
						},
						"date": {
							Type:        schema.TypeString,
							Description: "The date and time of the acknowledgment.",
							Computed:    true,
						},
						"fix_version": {
							Type:        schema.TypeString,
							Description: "The version of the package that having a fix for the issue.",
							Computed:    true,
						},
						"expiration_days": {
							Type:        schema.TypeInt,
							Description: "Number of days until expiration of the acknowledgement. The value must be integer from 1 to 999, inclusive.",
							Computed:    true,
						},
						"expiration_configured_at": {
							Type:        schema.TypeString,
							Description: "The current dat and time when the expiration was set",
							Computed:    true,
						},
						"expiration_configured_by": {
							Type:        schema.TypeString,
							Description: "The user who set the expiration of the issue.",
							Computed:    true,
						},
						"permission": {
							Type:        schema.TypeString,
							Description: "The permissions of the user who acknowledged the issue.",
							Computed:    true,
						},
						"os": {
							Type:        schema.TypeString,
							Description: "When the resource_type is 'package', the operating system is required (e.g., 'ubuntu', 'alpine').",
							Computed:    true,
						},
						"os_version": {
							Type:        schema.TypeString,
							Description: "When the resource_type is 'package', the operating system version is required.",
							Computed:    true,
						},
						"docker_id": {
							Type:        schema.TypeString,
							Description: "",
							Computed:    true,
						},
						"repository": {
							Type:        schema.TypeString,
							Description: "",
							Optional:    true,
						},
					},
				},
			},
		},
	}
}

func dataAcknowledgesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	log.Println("[DEBUG]  inside dataAcknowledges")
	c := m.(*client.Client)
	result, err := c.AcknowledgeRead()
	if err == nil {
		acknowledges, id := flattenAcknowledgesData(result)
		if id == "" {
			id = fmt.Sprintf("no-ack-found-%d", rand.Int())
		}
		d.SetId(id)
		if err := d.Set("acknowledges", acknowledges); err != nil {
			return diag.FromErr(err)
		}
	} else {
		return diag.FromErr(err)
	}

	return nil
}

func flattenAcknowledgesData(acknowledgesList *client.AcknowledgeList) ([]interface{}, string) {
	id := ""
	acknowledges := acknowledgesList.Result
	if acknowledges != nil {
		acks := make([]interface{}, len(acknowledges), len(acknowledges))

		for i, acknowledge := range acknowledges {
			id = id + acknowledge.IssueName
			a := make(map[string]interface{})

			a["issue_type"] = acknowledge.IssueType
			a["resource_type"] = acknowledge.ResourceType
			a["image_name"] = acknowledge.ImageName
			a["registry_name"] = acknowledge.RegistryName
			a["resource_name"] = acknowledge.ResourceName
			a["resource_version"] = acknowledge.ResourceVersion
			a["resource_format"] = acknowledge.ResourceFormat
			a["resource_cpe"] = acknowledge.ResourceCpe
			a["resource_path"] = acknowledge.ResourcePath
			a["resource_hash"] = acknowledge.ResourceHash
			a["issue_name"] = acknowledge.IssueName
			a["comment"] = acknowledge.Comment
			a["author"] = acknowledge.Author
			a["date"] = acknowledge.Date.String()
			a["fix_version"] = acknowledge.FixVersion
			a["expiration_days"] = acknowledge.ExpirationDays
			a["expiration_configured_at"] = acknowledge.ExpirationConfiguredAt.String()
			a["expiration_configured_by"] = acknowledge.ExpirationConfiguredBy
			a["permission"] = acknowledge.Permission
			a["os"] = acknowledge.Os
			a["os_version"] = acknowledge.OsVersion
			a["docker_id"] = acknowledge.DockerId
			a["repository"] = acknowledge.Repository
			acks[i] = a
		}

		return acks, id
	}

	return make([]interface{}, 0), ""
}
