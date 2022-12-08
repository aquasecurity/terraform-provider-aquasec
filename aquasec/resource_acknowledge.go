package aquasec

import (
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"time"
)

func resourceAcknowledge() *schema.Resource {
	return &schema.Resource{
		Create: resourceAcknowledgeCreate,
		Update: resourceAcknowledgeUpdate,
		Read:   resourceAcknowledgeRead,
		Delete: resourceAcknowledgeDelete,
		// todo: bring it back when will have Acknowledges IDs
		//Importer: &schema.ResourceImporter{
		//	StateContext: schema.ImportStatePassthroughContext,
		//},
		Schema: map[string]*schema.Schema{
			"comment": {
				Type:        schema.TypeString,
				Description: "A comment describing the reason for the acknowledgment",
				Required:    true,
			},
			"issues": {
				Type:        schema.TypeSet,
				Description: "A list of existing security acknowledges.",
				Required:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"issue_type": {
							Type:        schema.TypeString,
							Description: "The type of the security issue (either 'vulnerability', 'sensitive_data' or 'malware')",
							Required:    true,
						},
						"issue_name": {
							Type:        schema.TypeString,
							Description: "The name of the security issue (the CVE or security advisory for vulnerabilities, name of malware or type of sensitive data)",
							Required:    true,
						},
						"resource_type": {
							Type:        schema.TypeString,
							Description: "The type of the resource where the issue was detected (either 'package', 'file' or 'executable')",
							Required:    true,
						},
						"image_name": {
							Type:        schema.TypeString,
							Description: "Only acknowledge the issue in the context of the specified image (also requires 'registry_name')",
							Optional:    true,
						},
						"registry_name": {
							Type:        schema.TypeString,
							Description: "Only acknowledge the issue in the context of the specified repository (also requires 'registry_name').",
							Optional:    true,
						},
						"resource_name": {
							Type:        schema.TypeString,
							Description: "When the resource_type is 'package', the name of the package is required.",
							Optional:    true,
						},
						"resource_version": {
							Type:        schema.TypeString,
							Description: "When the resource_type is 'package', the version of the package is required",
							Optional:    true,
						},
						"resource_format": {
							Type:        schema.TypeString,
							Description: "The format of the resource.",
							Optional:    true,
						},
						"resource_cpe": {
							Type:        schema.TypeString,
							Description: "The CPE of the resource as listed in the issue by the Aqua API. This is required for resources of type 'executable'. For packages and files, the next parameters can be specified instead.",
							Optional:    true,
						},
						"resource_path": {
							Type:        schema.TypeString,
							Description: "The path of the resource. This is required for resources of type 'file' and 'executable'.",
							Optional:    true,
						},
						"resource_hash": {
							Type:        schema.TypeString,
							Description: "When the resource_type is 'file', the hash of the file is required",
							Optional:    true,
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
							Optional:    true,
						},
						"expiration_days": {
							Type:        schema.TypeInt,
							Description: "Number of days until expiration of the acknowledgement. The value must be integer from 1 to 999, inclusive.",
							Optional:    true,
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
							Optional:    true,
						},
						"os_version": {
							Type:        schema.TypeString,
							Description: "When the resource_type is 'package', the operating system version is required.",
							Optional:    true,
						},
						"docker_id": {
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

func resourceAcknowledgeCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	acknowledgePost := client.AcknowledgePost{}
	eIssues := client.AcknowledgePost{}.Issues
	var id string

	comment, ok := d.GetOk("comment")
	if ok {
		acknowledgePost.Comment = comment.(string)
	}
	issues, ok := d.GetOk("issues")
	if ok {
		eIssues, id = expandIssues(issues)
		acknowledgePost.Issues = eIssues
	}

	err := ac.AcknowledgeCreate(acknowledgePost)
	if err != nil {
		return err
	}
	d.SetId(id)

	err = resourceAcknowledgeRead(d, m)
	if err != nil {
		return err
	}

	return nil
}

func resourceAcknowledgeUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	var err error
	var comment string

	if d.HasChanges("issues") {
		oldState, newState := d.GetChange("issues")
		comment = d.Get("comment").(string)
		issuesToDelete := oldState.(*schema.Set).Difference(newState.(*schema.Set))
		issuesToCreate := newState.(*schema.Set).Difference(oldState.(*schema.Set))

		if issuesToDelete.Len() != 0 {
			expendedIssuesToDelete, _ := expandIssues(issuesToDelete)
			err = ac.AcknowledgeDelete(client.AcknowledgePost{Issues: expendedIssuesToDelete})

			if err != nil {
				return err
			}
		}

		if issuesToCreate.Len() != 0 {
			expendIssuesToCreate, _ := expandIssues(issuesToCreate)
			err = ac.AcknowledgeCreate(client.AcknowledgePost{
				Comment: comment,
				Issues:  expendIssuesToCreate,
			})
			if err != nil {
				return err
			}
		}

		err = resourceAcknowledgeRead(d, m)
		if err != nil {
			return err
		}
	}
	return nil
}

func resourceAcknowledgeRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	acknowledgePost := client.AcknowledgePost{}
	//var mappedResult map[string]interface{}

	comment, ok := d.GetOk("comment")
	if ok {
		acknowledgePost.Comment = comment.(string)
	}
	issues, ok := d.GetOk("issues")
	if ok {
		acknowledgePost.Issues, _ = expandIssues(issues)

	}

	currentAcknowledges, err := ac.AcknowledgeRead()
	if err == nil {
		updateIssuesFromReadList(&acknowledgePost, currentAcknowledges)
	} else {
		return err
	}

	err = d.Set("comment", acknowledgePost.Comment)
	flattenIssues, id := flattenIssues(acknowledgePost.Issues)
	err = d.Set("issues", flattenIssues)
	d.SetId(id)

	return nil
}

func resourceAcknowledgeDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	acknowledgePost := client.AcknowledgePost{}

	issues, ok := d.GetOk("issues")
	if ok {
		acknowledgePost.Issues, _ = expandIssues(issues)
	}

	err := ac.AcknowledgeDelete(acknowledgePost)

	if err == nil {
		d.SetId("")
	} else {
		return err
	}

	return nil
}

func expandIssues(issues interface{}) ([]client.Acknowledge, string) {
	acknowledgePost := client.AcknowledgePost{}.Issues
	id := ""

	for _, issue := range issues.(*schema.Set).List() {
		acknowledge := client.Acknowledge{}
		i := issue.(map[string]interface{})

		if attr, ok := i["issue_name"]; ok && attr != "" {
			acknowledge.IssueName = attr.(string)

		}

		if attr, ok := i["issue_type"]; ok && attr != "" {
			acknowledge.IssueType = attr.(string)
		}

		if attr, ok := i["resource_type"]; ok && attr != "" {
			acknowledge.ResourceType = attr.(string)
		}

		if attr, ok := i["image_name"]; ok && attr != "" {
			acknowledge.ImageName = attr.(string)
		}

		if attr, ok := i["registry_name"]; ok && attr != "" {
			acknowledge.RegistryName = attr.(string)
		}

		if attr, ok := i["resource_name"]; ok && attr != "" {
			acknowledge.ResourceName = attr.(string)
		}

		if attr, ok := i["resource_version"]; ok && attr != "" {
			acknowledge.ResourceVersion = attr.(string)
		}

		if attr, ok := i["resource_format"]; ok && attr != "" {
			acknowledge.ResourceFormat = attr.(string)
		}

		if attr, ok := i["resource_cpe"]; ok && attr != "" {
			acknowledge.ResourceCpe = attr.(string)
		}

		if attr, ok := i["resource_path"]; ok && attr != "" {
			acknowledge.ResourcePath = attr.(string)
		}

		if attr, ok := i["resource_hash"]; ok && attr != "" {
			acknowledge.ResourceHash = attr.(string)
		}

		if attr, ok := i["fix_version"]; ok && attr != "" {
			acknowledge.FixVersion = attr.(string)
		}

		if attr, ok := i["expiration_days"]; ok && attr != "" {
			acknowledge.ExpirationDays = attr.(int)
		}

		if attr, ok := i["os"]; ok && attr != "" {
			acknowledge.Os = attr.(string)
		}

		if attr, ok := i["os_version"]; ok && attr != "" {
			acknowledge.OsVersion = attr.(string)
		}

		if attr, ok := i["docker_id"]; ok && attr != "" {
			acknowledge.DockerId = attr.(string)
		}

		if attr, ok := i["author"]; ok && attr != "" {
			acknowledge.Author = attr.(string)
		}
		acknowledgePost = append(acknowledgePost, acknowledge)
		id = id + acknowledge.IssueName
	}

	return acknowledgePost, id
}

func flattenIssues(acknowledge []client.Acknowledge) ([]map[string]interface{}, string) {
	issuesMap := make([]map[string]interface{}, len(acknowledge))
	id := ""
	for i, ack := range acknowledge {
		issuesMap[i] = flattenIssue(ack)
		id = id + ack.IssueName
	}
	return issuesMap, id
}

func flattenIssue(ack client.Acknowledge) map[string]interface{} {
	return map[string]interface{}{
		"issue_type":       ack.IssueType,
		"resource_type":    ack.ResourceType,
		"image_name":       ack.ImageName,
		"registry_name":    ack.RegistryName,
		"resource_name":    ack.ResourceName,
		"resource_version": ack.ResourceVersion,
		"resource_format":  ack.ResourceFormat,
		"resource_cpe":     ack.ResourceCpe,
		"resource_path":    ack.ResourcePath,
		"resource_hash":    ack.ResourceHash,
		"issue_name":       ack.IssueName,
		//"comment": ack.Comment,
		"author":                   ack.Author,
		"date":                     ack.Date.Format(time.RFC3339),
		"fix_version":              ack.FixVersion,
		"expiration_days":          ack.ExpirationDays,
		"expiration_configured_at": ack.ExpirationConfiguredAt.Format(time.RFC3339),
		"expiration_configured_by": ack.ExpirationConfiguredBy,
		"permission":               ack.Permission,
		"os":                       ack.Os,
		"os_version":               ack.OsVersion,
		"docker_id":                ack.DockerId,
	}
}

func updateIssuesFromReadList(issues *client.AcknowledgePost, readIssues *client.AcknowledgeList) error {
	mappedResults := make(map[string]interface{})

	// Create a Acknowledge map by issue_name-comment
	for _, rr := range readIssues.Result {
		mappedResults[fmt.Sprintf("%s-%s", rr.IssueName, rr.Comment)] = rr
	}

	for i, ack := range issues.Issues {
		if val, ok := mappedResults[fmt.Sprintf("%s-%s", ack.IssueName, issues.Comment)]; ok {
			ack.Date = val.(client.Acknowledge).Date
			ack.ExpirationConfiguredAt = val.(client.Acknowledge).ExpirationConfiguredAt
			ack.ExpirationConfiguredBy = val.(client.Acknowledge).ExpirationConfiguredBy
			ack.Author = val.(client.Acknowledge).Author
			issues.Issues[i] = ack
		} else {
			return fmt.Errorf(fmt.Sprintf("issue: %s wasn't crerated and is missing from active acknowledgments", ack.IssueName))
		}
	}
	return nil
}
