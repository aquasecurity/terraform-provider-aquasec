package aquasec

import (
    "context"
    "fmt"
    "math/rand"

    "github.com/aquasecurity/terraform-provider-aquasec/client"
    "github.com/hashicorp/terraform-plugin-sdk/v2/diag"
    "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourcePermissionsSetsSaas() *schema.Resource {
    return &schema.Resource{
        Description: "The data source `aquasec_permissions_sets_saas` provides a method to query all permissions within Aqua SaaS platform",
        ReadContext: dataPermissionsSetsSaasRead,
        Schema: map[string]*schema.Schema{
            "permissions_sets": {
                Type:     schema.TypeList,
                Computed: true,
                Elem: &schema.Resource{
                    Schema: map[string]*schema.Schema{
                        "name": {
                            Type:        schema.TypeString,
                            Description: "Name of the permission set",
                            Computed:    true,
                        },
                        "description": {
                            Type:        schema.TypeString,
                            Description: "Description of the permission set",
                            Computed:    true,
                        },
                        "actions": {
                            Type:        schema.TypeList,
                            Description: "List of allowed actions",
                            Computed:    true,
                            Elem: &schema.Schema{
                                Type: schema.TypeString,
                            },
                        },
                    },
                },
            },
        },
    }
}

func dataPermissionsSetsSaasRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
    c := m.(*client.Client)
    permissionsSets, err := c.GetPermissionSetsSaas()
    if err != nil {
        return diag.FromErr(err)
    }

    id := ""
    ps := make([]interface{}, len(permissionsSets))

    for i, permissionsSet := range permissionsSets {
        id = id + permissionsSet.Name
        p := make(map[string]interface{})
        p["name"] = permissionsSet.Name
        p["description"] = permissionsSet.Description
        p["actions"] = permissionsSet.Actions
        ps[i] = p
    }

    if id == "" {
        id = fmt.Sprintf("no-permissions-found-%d", rand.Int())
    }
    d.SetId(id)
    if err := d.Set("permissions_sets", ps); err != nil {
        return diag.FromErr(err)
    }
    return nil
}