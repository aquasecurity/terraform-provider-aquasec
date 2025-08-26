package aquasec

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceScannerGroup() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceScannerGroupCreate,
		ReadContext:   resourceScannerGroupRead,
		UpdateContext: resourceScannerGroupUpdate,
		DeleteContext: resourceScannerGroupDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"os_type": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"type": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"author": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"created_at": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"updated_at": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"registries": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"application_scopes": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"tokens": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"scanners": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"last_heartbeat": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"scanner_name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"scanner_version": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"os_version": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"token": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"registered_on": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
			"deploy_command": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"additional_prop1": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"additional_prop2": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"additional_prop3": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func resourceScannerGroupCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var err error
	c := m.(*client.Client)

	var scanner client.ScannerGroup

	scanner.Name = d.Get("name").(string)
	scanner.Description = d.Get("description").(string)
	scanner.OSType = d.Get("os_type").(string)
	scanner.Type = d.Get("type").(string)
	registries, ok := d.GetOk("registries")
	if ok {
		scanner.Registries = convertStringArr(registries.([]interface{}))
	}
	applicationScopes, ok := d.GetOk("application_scopes")
	if ok {
		scanner.ApplicationScopes = convertStringArr(applicationScopes.([]interface{}))
	}
	tokens, ok := d.GetOk("tokens")
	if ok {
		scanner.Tokens = convertStringArr(tokens.([]interface{}))
	}

	scannerGroup := &client.ScannerGroup{
		Name:              scanner.Name,
		Description:       scanner.Description,
		Tokens:            scanner.Tokens,
		OSType:            scanner.OSType,
		Type:              scanner.Type,
		Registries:        scanner.Registries,
		ApplicationScopes: scanner.ApplicationScopes,
	}

	err = c.CreateScannerGroup(scannerGroup)
	if err != nil {
		return diag.FromErr(fmt.Errorf("CreateScannerGroup err: %w", err))
	}

	d.SetId(scannerGroup.Name)

	return resourceScannerGroupRead(ctx, d, m)
}

func resourceScannerGroupRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Id()
	sg, err := c.GetScannerGroup(name)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			d.SetId("")
			return nil
		}
		return diag.Errorf("error reading ScannerGroup ID %s: %s", name, err)
	}

	var diags diag.Diagnostics

	set := func(key string, value interface{}) {
		if err := d.Set(key, value); err != nil {
			diags = append(diags, diag.FromErr(fmt.Errorf("failed to set %s: %w", key, err))...)
		}
	}

	set("name", sg.Name)
	set("description", sg.Description)
	set("status", sg.Status)
	set("os_type", sg.OSType)
	set("type", sg.Type)
	set("author", sg.Author)
	set("created_at", sg.CreatedAt)
	set("updated_at", sg.UpdatedAt)
	set("registries", sg.Registries)
	set("application_scopes", sg.ApplicationScopes)
	set("tokens", sg.Tokens)

	scanners := make([]map[string]interface{}, len(sg.Scanners))
	for i, sc := range sg.Scanners {
		scanners[i] = map[string]interface{}{
			"last_heartbeat":  sc.LastHeartBeat,
			"scanner_name":    sc.ScannerName,
			"scanner_version": sc.ScannerVersion,
			"os_version":      sc.OsVersion,
			"token":           sc.Token,
			"registered_on":   sc.RegisteredOn,
		}
	}
	set("scanners", scanners)

	dp := sg.DeployCommand
	dc := []map[string]interface{}{
		{
			"additional_prop1": dp.AdditionalProp1,
			"additional_prop2": dp.AdditionalProp2,
			"additional_prop3": dp.AdditionalProp3,
		},
	}
	set("deploy_command", dc)

	return diags
}

func resourceScannerGroupUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	var scannerGroupUpdate client.ScannerGroup
	scannerGroupUpdate.Name = d.Get("name").(string)

	if d.HasChanges("description", "os_type", "type", "registries", "application_scopes") {
		scannerGroupUpdate.Description = d.Get("description").(string)
		scannerGroupUpdate.OSType = d.Get("os_type").(string)
		scannerGroupUpdate.Type = d.Get("type").(string)

		if v, ok := d.GetOk("registries"); ok {
			scannerGroupUpdate.Registries = convertStringArr(v.([]interface{}))
		}

		if v, ok := d.GetOk("application_scopes"); ok {
			scannerGroupUpdate.ApplicationScopes = convertStringArr(v.([]interface{}))
		}

		errs := c.UpdateScannerGroup(&scannerGroupUpdate)
		if errs != nil {
			return diag.FromErr(errs)
		}
	}

	return resourceScannerGroupRead(ctx, d, m)
}

func resourceScannerGroupDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	ac := m.(*client.Client)
	name := d.Id()
	err := ac.DeleteScannerGroup(name)
	if err != nil {
		return diag.FromErr(err)
	}
	return nil
}
