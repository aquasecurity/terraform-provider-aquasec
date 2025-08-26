package aquasec

import (
	"context"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceScannerGroup() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataScannerGroupRead,
		Schema: map[string]*schema.Schema{
			// Optional input argument
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the scanner group (optional). If omitted, all scanner groups are returned.",
				Optional:    true,
			},
			// Single scanner group fields (computed)
			"description": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"tokens": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"os_type": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"type": {
				Type:     schema.TypeString,
				Computed: true,
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
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"application_scopes": {
				Type:     schema.TypeList,
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

			// For listing all scanner groups (list of objects)
			"scanner_groups": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"description": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"status": {
							Type:     schema.TypeString,
							Computed: true,
						},
						// Add other fields here same as above...
						"tokens": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"os_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"type": {
							Type:     schema.TypeString,
							Computed: true,
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
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"application_scopes": {
							Type:     schema.TypeList,
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
				},
			},
		},
	}
}

func dataScannerGroupRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	name, hasName := d.GetOk("name")

	if hasName && name.(string) != "" {
		// Single scanner group fetch
		sg, err := c.GetScannerGroup(name.(string))
		if err != nil {
			return diag.FromErr(err)
		}

		d.SetId(sg.Name)
		d.Set("description", sg.Description)
		d.Set("status", sg.Status)
		d.Set("tokens", sg.Tokens)
		d.Set("os_type", sg.OSType)
		d.Set("type", sg.Type)
		d.Set("author", sg.Author)
		d.Set("created_at", sg.CreatedAt)
		d.Set("updated_at", sg.UpdatedAt)
		d.Set("registries", sg.Registries)
		d.Set("application_scopes", sg.ApplicationScopes)
		if err := d.Set("scanners", flattenScanners(sg.Scanners)); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("deploy_command", flattenDeployCommand(sg.DeployCommand)); err != nil {
			return diag.FromErr(err)
		}
	} else {
		// List all scanner groups
		groups, err := c.GetScannerGroups()
		if err != nil {
			return diag.FromErr(err)
		}

		list := make([]interface{}, 0, len(groups))
		for _, sg := range groups {
			list = append(list, flattenSG([]client.ScannerGroup{sg})[0].(map[string]interface{}))
		}
		d.SetId("all")
		d.Set("scanner_groups", list)
	}

	return nil
}

func flattenScanners(scanners []client.Scanners) interface{} {
	if scanners == nil {
		return []map[string]interface{}{}
	}
	var scannerList []map[string]interface{}
	for _, scanner := range scanners {
		scannerList = append(scannerList, map[string]interface{}{
			"last_heartbeat":  scanner.LastHeartBeat,
			"scanner_name":    scanner.ScannerName,
			"scanner_version": scanner.ScannerVersion,
			"os_version":      scanner.OsVersion,
			"registered_on":   scanner.RegisteredOn,
			"token":           scanner.Token,
		})
	}
	return scannerList
}

func flattenDeployCommand(deployCommand client.DeployCommand) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"additional_prop1": deployCommand.AdditionalProp1,
			"additional_prop2": deployCommand.AdditionalProp2,
			"additional_prop3": deployCommand.AdditionalProp3,
		},
	}
}

func flattenSG(sgs []client.ScannerGroup) []interface{} {
	result := make([]interface{}, 0, len(sgs))
	for _, sg := range sgs {
		m := map[string]interface{}{
			"name":               sg.Name,
			"description":        sg.Description,
			"status":             sg.Status,
			"tokens":             sg.Tokens,
			"os_type":            sg.OSType,
			"type":               sg.Type,
			"author":             sg.Author,
			"created_at":         sg.CreatedAt,
			"updated_at":         sg.UpdatedAt,
			"registries":         sg.Registries,
			"application_scopes": sg.ApplicationScopes,
			"scanners":           flattenScanners(sg.Scanners),
			"deploy_command":     flattenDeployCommand(sg.DeployCommand),
		}
		result = append(result, m)
	}
	return result
}
