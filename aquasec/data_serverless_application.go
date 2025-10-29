package aquasec

import (
	"context"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceServerlessApplication() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceServerlessApplicationRead,
		Schema: map[string]*schema.Schema{
			"id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"project": {
				Type:        schema.TypeList,
				Description: "A list of existing serverless applications.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"username": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"password": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"subscription_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"tenant_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"cloud_project": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"external_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"region": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"compute_provider": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"author": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"lastupdate": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"pull_tags_pattern": {
							Type: schema.TypeList,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"pull_tags_pattern_excluded": {
							Type: schema.TypeList,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"auto_pull": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"auto_pull_time": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"auto_pull_max": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"auto_pull_pattern": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"sqs_url": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"description": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"exclude_tags": {
							Type: schema.TypeList,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"include_tags": {
							Type: schema.TypeList,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"existsing_scanners": {
							Type: schema.TypeList,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"role_arn": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"scanner_group_name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"scanner_name": {
							Type: schema.TypeList,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"scanner_name_added": {
							Type: schema.TypeList,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"scanner_name_removed": {
							Type: schema.TypeList,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"scanner_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func dataSourceServerlessApplicationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)

	result, err := ac.GetServerlessApplications()
	if err != nil {
		return diag.FromErr(err)
	}
	apps, name := flattenServerlessApplicationsData(result)

	var id string
	if len(apps) > 0 {
		id = name
	} else {
		id = "no-serverless-app-found"
	}
	d.SetId(id)
	_ = d.Set("id", id)
	if err := d.Set("project", apps); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func flattenServerlessApplicationsData(appsList *client.ServerlessApplicationsResponse) ([]interface{}, string) {
	name := ""

	apps := appsList.Project
	if apps != nil {
		slapps := make([]interface{}, len(apps), len(apps))
		for i, app := range apps {
			name = name + app.Name
			appData := make(map[string]interface{})

			appData["name"] = app.Name
			appData["username"] = app.Username
			appData["password"] = app.Password
			appData["subscription_id"] = app.SubscriptionId
			appData["tenant_id"] = app.TenantId
			appData["cloud_project"] = app.CloudProject
			appData["external_id"] = app.ExternalId
			appData["region"] = app.Region
			appData["compute_provider"] = app.ComputeProviderType
			appData["author"] = app.Author
			appData["lastupdate"] = app.LastUpdate
			appData["pull_tags_pattern"] = app.PullTagsPattern
			appData["pull_tags_pattern_excluded"] = app.PullTagsPatternExcluded
			appData["auto_pull"] = app.AutoPull
			appData["auto_pull_time"] = app.AutoPullTime
			appData["auto_pull_max"] = app.AutoPullMax
			appData["auto_pull_pattern"] = app.AutoPullPattern
			appData["sqs_url"] = app.SqsUrl
			appData["description"] = app.Description
			appData["exclude_tags"] = app.ExcludeTags
			appData["include_tags"] = app.IncludeTags
			appData["existsing_scanners"] = app.ExistsingScanners
			appData["role_arn"] = app.RoleARN
			appData["scanner_group_name"] = app.ScannerGroupName
			appData["scanner_name"] = app.ScannerName
			appData["scanner_name_added"] = app.ScannerNameAdded
			appData["scanner_name_removed"] = app.ScannerNameRemoved
			appData["scanner_type"] = app.ScannerType

			slapps[i] = appData
		}
		return slapps, name
	}
	return make([]interface{}, 0), ""
}
