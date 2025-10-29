package aquasec

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceServerlessApplication() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceServerlessApplicationCreate,
		ReadContext:   resourceServerlessApplicationRead,
		UpdateContext: resourceServerlessApplicationUpdate,
		DeleteContext: resourceServerlessApplicationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Description: "The username for registry authentication.",
				Optional:    true,
			},
			"password": {
				Type:        schema.TypeString,
				Description: "The password for registry authentication",
				Optional:    true,
				Sensitive:   true,
			},
			"subscription_id": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
			},
			"tenant_id": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
			},
			"cloud_project": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"external_id": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"name": {
				Type:        schema.TypeString,
				Description: "The name of the serverless application; string, required - this will be treated as the serverless application's ID, so choose a simple alphanumerical name without special signs and spaces",
				Required:    true,
			},
			"region": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "The username of the user who created or last modified the serverless application",
				Optional:    true,
				Computed:    true,
			},
			"compute_provider": {
				Type:     schema.TypeInt,
				Required: true,
			},
			"pull_tags_pattern": {
				Type:        schema.TypeList,
				Description: "Patterns for tags to be pulled from auto pull",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"pull_tags_pattern_excluded": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"auto_pull": {
				Type:        schema.TypeBool,
				Description: "Whether to automatically pull images from the registry on creation and daily",
				Optional:    true,
			},
			"auto_pull_time": {
				Type:        schema.TypeString,
				Description: "The time of day to start pulling new images from the registry, in the format HH:MM (24-hour clock), defaults to 03:00",
				Optional:    true,
				Computed:    true,
			},
			"sqs_url": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"lastupdate": {
				Type:        schema.TypeInt,
				Description: "The last time the registry was modified in UNIX time",
				Computed:    true,
				Optional:    true,
			},
			"auto_pull_max": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"auto_pull_pattern": {
				Type:        schema.TypeString,
				Description: "The description of the Serverless application",
				Optional:    true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"exclude_tags": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"include_tags": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"role_arn": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"scanner_group_name": {
				Type:        schema.TypeString,
				Description: "The scanner group name (required when scanner_type = \"specific\" type)",
				Optional:    true,
			},
			"scanner_name": {
				Type:        schema.TypeList,
				Description: "List of scanner names",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"scanner_type": {
				Type:         schema.TypeString,
				Description:  "The Scanner type (either \"any\" or \"specific\")",
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"any", "specific"}, false),
			},
		},
	}
}

func resourceServerlessApplicationCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	var scannerGroupName string
	scannerType := d.Get("scanner_type").(string)
	if scannerType == "" {
		scannerType = "any"
	}

	if scannerType == "specific" {
		scannerGroupName = d.Get("scanner_group_name").(string)
		if len(scannerGroupName) == 0 {
			return diag.FromErr(fmt.Errorf("scanner_group_name must be provided when scanner_type is \"specific\""))
		}
	}

	excludeTags := d.Get("exclude_tags").([]interface{})
	includeTags := d.Get("include_tags").([]interface{})
	pullTagsPattern := d.Get("pull_tags_pattern").([]interface{})
	pullTagsPatternExcluded := d.Get("pull_tags_pattern_excluded").([]interface{})
	scannerName := d.Get("scanner_name").([]interface{})

	old, new := d.GetChange("scanner_name")

	existsing_scanners := old.([]interface{})

	scanner_name_added, scanner_name_removed := scannerNamesListCreate(old.([]interface{}), new.([]interface{}))

	serverlessApp := client.ServerlessApplication{
		Username:                d.Get("username").(string),
		Password:                d.Get("password").(string),
		SubscriptionId:          d.Get("subscription_id").(string),
		TenantId:                d.Get("tenant_id").(string),
		CloudProject:            d.Get("cloud_project").(string),
		ExternalId:              d.Get("external_id").(string),
		Name:                    d.Get("name").(string),
		Region:                  d.Get("region").(string),
		ComputeProviderType:     d.Get("compute_provider").(int),
		AutoPull:                d.Get("auto_pull").(bool),
		AutoPullTime:            d.Get("auto_pull_time").(string),
		AutoPullMax:             d.Get("auto_pull_max").(int),
		AutoPullPattern:         d.Get("auto_pull_pattern").(string),
		ExcludeTags:             convertStringArr(excludeTags),
		ExistsingScanners:       convertStringArr(existsing_scanners),
		IncludeTags:             convertStringArr(includeTags),
		PullTagsPattern:         convertStringArr(pullTagsPattern),
		PullTagsPatternExcluded: convertStringArr(pullTagsPatternExcluded),
		ScannerName:             convertStringArr(scannerName),
		ScannerNameAdded:        convertStringArr(scanner_name_added),
		ScannerNameRemoved:      convertStringArr(scanner_name_removed),
		ScannerType:             scannerType,
		ScannerGroupName:        scannerGroupName,
		RoleARN:                 d.Get("role_arn").(string),
		SqsUrl:                  d.Get("sqs_url").(string),
		Description:             d.Get("description").(string),
	}

	err := ac.CreateServerlessApplication(serverlessApp)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(serverlessApp.Name)
	d.Set("lastupdate", time.Now().Unix())
	return resourceServerlessApplicationRead(ctx, d, m)
}

func resourceServerlessApplicationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	name := d.Id()
	app, err := ac.GetServerlessApplication(name)
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	if err = d.Set("username", app.Username); err != nil {
		return diag.FromErr(err)
	}
	//if err = d.Set("password", app.Password); err != nil {
	//	return diag.FromErr(err)
	//}
	if err = d.Set("subscription_id", app.SubscriptionId); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("tenant_id", app.TenantId); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("cloud_project", app.CloudProject); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("external_id", app.ExternalId); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("name", app.Name); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("region", app.Region); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("compute_provider", app.ComputeProviderType); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("author", app.Author); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("lastupdate", app.LastUpdate); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("pull_tags_pattern", app.PullTagsPattern); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("pull_tags_pattern_excluded", app.PullTagsPatternExcluded); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("auto_pull", app.AutoPull); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("auto_pull_time", app.AutoPullTime); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("auto_pull_max", app.AutoPullMax); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("auto_pull_pattern", app.AutoPullPattern); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("sqs_url", app.SqsUrl); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("description", app.Description); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("exclude_tags", app.ExcludeTags); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("include_tags", app.IncludeTags); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("role_arn", app.RoleARN); err != nil {
		return diag.FromErr(err)
	}
	if err = d.Set("scanner_type", app.ScannerType); err != nil {
		return diag.FromErr(err)
	}
	scannerType := d.Get("scanner_type").(string)
	if scannerType == "specific" {
		if err = d.Set("scanner_group_name", app.ScannerGroupName); err != nil {
			return diag.FromErr(err)
		}
	} else {
		if err = d.Set("scanner_name", app.ScannerName); err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func resourceServerlessApplicationUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	var scannerGroupName string
	scannerType := d.Get("scanner_type").(string)
	if scannerType == "" {
		scannerType = "any"
	}
	if scannerType == "specific" {
		scannerGroupName = d.Get("scanner_group_name").(string)
		if len(scannerGroupName) == 0 {
			return diag.FromErr(fmt.Errorf("scanner_group_name must be provided when scanner_type is \"specific\""))
		}
	}

	if d.HasChanges("username", "password", "subscription_id", "tenant_id", "cloud_project", "external_id", "region", "author", "pull_tags_pattern", "pull_tags_pattern_excluded", "auto_pull", "auto_pull_time", "sqs_url", "lastupdate", "auto_pull_max", "auto_pull_pattern", "description", "exclude_tags", "include_tags", "role_arn", "scanner_group_name", "scanner_name", "scanner_type") {
		excludeTags := d.Get("exclude_tags").([]interface{})
		includeTags := d.Get("include_tags").([]interface{})
		pullTagsPattern := d.Get("pull_tags_pattern").([]interface{})
		pullTagsPatternExcluded := d.Get("pull_tags_pattern_excluded").([]interface{})
		scannerName := d.Get("scanner_name").([]interface{})

		old, new := d.GetChange("scanner_name")

		existsing_scanners := old.([]interface{})

		scanner_name_added, scanner_name_removed := scannerNamesListCreate(old.([]interface{}), new.([]interface{}))

		app := client.ServerlessApplication{
			Name:                    d.Get("name").(string),
			Username:                d.Get("username").(string),
			Password:                d.Get("password").(string),
			SubscriptionId:          d.Get("subscription_id").(string),
			TenantId:                d.Get("tenant_id").(string),
			CloudProject:            d.Get("cloud_project").(string),
			ExternalId:              d.Get("external_id").(string),
			Region:                  d.Get("region").(string),
			ComputeProviderType:     d.Get("compute_provider").(int),
			AutoPull:                d.Get("auto_pull").(bool),
			AutoPullTime:            d.Get("auto_pull_time").(string),
			AutoPullMax:             d.Get("auto_pull_max").(int),
			AutoPullPattern:         d.Get("auto_pull_pattern").(string),
			ExcludeTags:             convertStringArr(excludeTags),
			ExistsingScanners:       convertStringArr(existsing_scanners),
			IncludeTags:             convertStringArr(includeTags),
			PullTagsPattern:         convertStringArr(pullTagsPattern),
			PullTagsPatternExcluded: convertStringArr(pullTagsPatternExcluded),
			ScannerName:             convertStringArr(scannerName),
			ScannerNameAdded:        convertStringArr(scanner_name_added),
			ScannerNameRemoved:      convertStringArr(scanner_name_removed),
			ScannerType:             scannerType,
			ScannerGroupName:        scannerGroupName,
			RoleARN:                 d.Get("role_arn").(string),
			SqsUrl:                  d.Get("sqs_url").(string),
			Description:             d.Get("description").(string),
		}

		err := ac.UpdateServerlessApplication(app)
		if err == nil {
			_ = d.Set("lastupdate", time.Now().Unix())
		} else {
			log.Println("[DEBUG] error while updating serverless application: ", err)
			return diag.FromErr(err)
		}
	}
	return resourceServerlessApplicationRead(ctx, d, m)
}

func resourceServerlessApplicationDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	name := d.Id()

	err := ac.DeleteServerlessApplication(name)
	if err == nil {
		d.SetId("")
	} else {
		log.Println("[DEBUG] error deleting serverless application: ", err)
		diag.FromErr(err)
	}

	return nil
}
