package aquasec

import (
	"context"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRoleMapping() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRoleMappingCreate,
		ReadContext:   resourceRoleMappingRead,
		UpdateContext: resourceRoleMappingUpdate,
		DeleteContext: resourceRoleMappingDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"saml": {
				Type:        schema.TypeSet,
				Description: "SAML Authentication",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Required: true,
							ForceNew: true,
						},
					},
				},
				Optional: true,
				MaxItems: 1,
			},
			"oauth2": {
				Type:        schema.TypeSet,
				Description: "Oauth2 Authentication",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Required: true,
							ForceNew: true,
						},
					},
				},
				Optional: true,
				MaxItems: 1,
			},
			"openid": {
				Type:        schema.TypeSet,
				Description: "OpenId Authentication",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Required: true,
							ForceNew: true,
						},
					},
				},
				Optional: true,
				MaxItems: 1,
			},
		},
	}
}

func resourceRoleMappingCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	RoleMapping, err := expandRoleMapping(d, c)
	if err != nil {
		return diag.FromErr(err)
	}
	err = c.CreateSSO(RoleMapping)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("aquasec-RoleMapping")
	return resourceRoleMappingRead(ctx, d, m)
}

func resourceRoleMappingRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	roleMapping, err := c.GetSSO()
	if err == nil {
		saml, ok := d.GetOk("saml")
		if ok {
			roleMapping.Saml.RoleMapping = convertRoleMapping(saml.(*schema.Set).List()[0].(map[string]interface{}))
			d.Set("saml", flattenSamlRoleMapping(roleMapping.Saml))
		}
		oAuth2, ok := d.GetOk("oauth2")
		if ok {
			roleMapping.OAuth2.RoleMapping = convertRoleMapping(oAuth2.(*schema.Set).List()[0].(map[string]interface{}))
			d.Set("oauth2", flattenOAuth2RoleMapping(roleMapping.OAuth2))
		}
		openId, ok := d.GetOk("openid")
		if ok {
			roleMapping.OpenId.RoleMapping = convertRoleMapping(openId.(*schema.Set).List()[0].(map[string]interface{}))
			d.Set("openid", flattenOpenIdRoleMapping(roleMapping.OpenId))
		}
		d.SetId("aquasec-RoleMapping")
	} else {
		return diag.FromErr(err)
	}
	return nil
}

func resourceRoleMappingUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.HasChanges("saml", "oauth2", "openid") {
		c := m.(*client.Client)
		roleMapping, err := expandRoleMapping(d, c)
		if err != nil {
			return diag.FromErr(err)
		}
		err = c.UpdateSSO(roleMapping)
		if err != nil {
			return diag.FromErr(err)
		}
		d.SetId("aquasec-RoleMapping")
		return resourceRoleMappingRead(ctx, d, m)
	}
	return nil
}

func resourceRoleMappingDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	roleMapping, err := c.GetSSO()

	if err != nil {
		return diag.FromErr(err)
	}
	// setting the roleMapping to an empty map, because the api support only put operation
	saml, ok := d.GetOk("saml")
	if ok {
		roleMapping.Saml.RoleMapping = splitRoleMapping(convertRoleMapping(saml.(*schema.Set).List()[0].(map[string]interface{})), roleMapping.Saml.RoleMapping)
	}
	oAuth2, ok := d.GetOk("oauth2")
	if ok {
		roleMapping.OAuth2.RoleMapping = splitRoleMapping(convertRoleMapping(oAuth2.(*schema.Set).List()[0].(map[string]interface{})), roleMapping.OAuth2.RoleMapping)
	}
	openId, ok := d.GetOk("openid")
	if ok {
		roleMapping.OpenId.RoleMapping = splitRoleMapping(convertRoleMapping(openId.(*schema.Set).List()[0].(map[string]interface{})), roleMapping.OpenId.RoleMapping)
	}

	err = c.DeleteSSO(roleMapping)
	if err == nil {
		d.SetId("")
	} else {
		return diag.FromErr(err)
	}

	return nil
}

func expandRoleMapping(d *schema.ResourceData, c *client.Client) (*client.SSO, error) {
	// for now we are allowing to set from terraform only role mapping all the other vars are getting from the console.
	RoleMapping, err := c.GetSSO()
	if err != nil {
		return nil, err
	}

	saml, ok := d.GetOk("saml")
	if ok {
		RoleMapping.Saml.RoleMapping = joinRoleMapping(convertRoleMapping(saml.(*schema.Set).List()[0].(map[string]interface{})), RoleMapping.Saml.RoleMapping)
	}

	oauth2, ok := d.GetOk("oauth2")
	if ok {
		RoleMapping.OAuth2.RoleMapping = joinRoleMapping(convertRoleMapping(oauth2.(*schema.Set).List()[0].(map[string]interface{})), RoleMapping.OAuth2.RoleMapping)
	}

	openid, ok := d.GetOk("openid")
	if ok {
		RoleMapping.OpenId.RoleMapping = joinRoleMapping(convertRoleMapping(openid.(*schema.Set).List()[0].(map[string]interface{})), RoleMapping.OpenId.RoleMapping)
	}

	return RoleMapping, nil
}
