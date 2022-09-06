package aquasec

import (
	"context"
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strings"
)

func dataSourceSSO() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSSORead,
		Schema: map[string]*schema.Schema{
			"saml": {
				Type:        schema.TypeSet,
				Description: "SAML Authentication",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"aqua_creds_enable": {
							Type:        schema.TypeBool,
							Description: "aqua_creds_enable.",
							Computed:    true,
						},
						"aqua_sso_url": {
							Type:        schema.TypeString,
							Description: "The URL for your Aqua Server. This should be in the form https://<AQUA_SERVER_NAME>/api/v1/saml_auth.",
							Computed:    true,
						},
						"auth_by_role": {
							Type:        schema.TypeBool,
							Description: "If true, authorize by role.",
							Computed:    true,
						},
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Enabled SAML Authentication.",
							Computed:    true,
						},
						"identity_provider_issuer": {
							Type:        schema.TypeString,
							Description: "Identity Provider Issuer.",
							Computed:    true,
						},
						"identity_provider_logout_url": {
							Type:        schema.TypeString,
							Description: "Identity Provider Single Sign-On logout URL.",
							Computed:    true,
						},
						"identity_provider_sso_url": {
							Type:        schema.TypeString,
							Description: "Identity Provider Single Sign-On URL.",
							Computed:    true,
						},
						"aqua_sso_logout_url": {
							Type:        schema.TypeString,
							Description: "Logout URL.",
							Computed:    true,
						},
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"signed_request": {
							Type:        schema.TypeBool,
							Description: "signed request.",
							Computed:    true,
						},
						"slo_enabled": {
							Type:        schema.TypeBool,
							Description: "If set to true, single logout (SLO) is enabled.",
							Computed:    true,
						},
						"service_provider_issuer": {
							Type:        schema.TypeString,
							Description: "Service provider issuer, this should be aquasec.com.",
							Computed:    true,
						},
						"sso_enable": {
							Type:        schema.TypeBool,
							Description: "Show SSO button on Login.",
							Computed:    true,
						},
						"token_provided": {
							Type:        schema.TypeBool,
							Description: "token provided.",
							Computed:    true,
						},
						"user_login_id": {
							Type:        schema.TypeString,
							Description: "Name of the attribute on your SAML IDP server that maps to the user.",
							Computed:    true,
						},
						"user_role": {
							Type:        schema.TypeString,
							Description: "Name of the attribute on your SAML IDP server that maps to the role",
							Computed:    true,
						},
						"x509cert": {
							Type:        schema.TypeString,
							Description: "x509cert.",
							Computed:    true,
						},
					},
				},
				Computed: true,
			},
			"oauth2": {
				Type:        schema.TypeSet,
				Description: "Oauth2 Authentication",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Enabled OAuth2 Authentication.",
							Computed:    true,
						},
						"identity_provider_issuer": {
							Type:        schema.TypeString,
							Description: "Identity provider issuer.",
							Computed:    true,
						},
						"json_web_key_set_url": {
							Type:        schema.TypeString,
							Description: "Enter the JWKS_URI URL as defined in the authorization server configuration.",
							Computed:    true,
						},
						"user_role": {
							Type:        schema.TypeString,
							Description: "Name of the attribute on your SAML IDP server that maps to the role.",
							Computed:    true,
						},
						"user_login_id": {
							Type:        schema.TypeString,
							Description: "Name of the attribute on your SAML IDP server that maps to the user.",
							Computed:    true,
						},
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
					},
				},
				Computed: true,
			},
			"openid": {
				Type:        schema.TypeSet,
				Description: "OpenId Authentication",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Enabled OpenId Authentication.",
							Computed:    true,
						},
						"provider_name": {
							Type:        schema.TypeString,
							Description: "Provider name.",
							Computed:    true,
						},
						"consumer_secret": {
							Type:        schema.TypeString,
							Description: "Enter the Client Secret from your provider as defined in your OpenID provider configuration.",
							Computed:    true,
						},
						"consumer_key": {
							Type:        schema.TypeString,
							Description: "Enter the Client ID from your provider as defined in your OpenID provider configuration.",
							Computed:    true,
						},
						"aqua_redirect_endpoint": {
							Type:        schema.TypeString,
							Description: "Enter the Redirect Endpoint, For example: https://<aqua_server_name:port>/api/v2/oidc/callback.",
							Computed:    true,
						},
						"identity_provider_issuer_url": {
							Type:        schema.TypeString,
							Description: "Enter the Issuer URI as defined in the OpenID provider configuration.",
							Computed:    true,
						},
						"scope": {
							Type:        schema.TypeList,
							Description: "Application Scopes.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed: true,
						},
						"user_role": {
							Type:        schema.TypeString,
							Description: "Name of the attribute on your SAML IDP server that maps to the role.",
							Computed:    true,
						},
						"user_login_id": {
							Type:        schema.TypeString,
							Description: "Name of the attribute on your SAML IDP server that maps to the user.",
							Computed:    true,
						},
						"auth_by_role": {
							Type:        schema.TypeBool,
							Description: "If true, authorize by role",
							Computed:    true,
						},
						"role_mapping": {
							Type:        schema.TypeMap,
							Description: "Role Mapping is used to define the IdP role that the user will assume in Aqua",
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

func dataSSORead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	sso, err := c.GetSSO()
	if err == nil {
		d.Set("saml", flattenSaml(sso.Saml))
		d.Set("oauth2", flattenOAuth2(sso.OAuth2))
		d.Set("openid", flattenOpenId(sso.OpenId))
		d.SetId("aquasec-sso")
	} else {
		return diag.FromErr(err)
	}
	return nil
}

func flattenSaml(saml client.Saml) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"aqua_creds_enable":            saml.AquaCredsEnable,
			"aqua_sso_url":                 saml.AssertionUrl,
			"auth_by_role":                 saml.AuthByRole,
			"enabled":                      saml.Enabled,
			"identity_provider_issuer":     saml.Idpissuer,
			"identity_provider_logout_url": saml.Idpslourl,
			"identity_provider_sso_url":    saml.IdpSSOurl,
			"aqua_sso_logout_url":          saml.LogoutUrl,
			"role_mapping":                 flattenRoleMap(saml.RoleMapping),
			"signed_request":               saml.SignedRequest,
			"slo_enabled":                  saml.SloEnabled,
			"service_provider_issuer":      saml.SpId,
			"sso_enable":                   saml.SSOEnable,
			"token_provided":               saml.TokenProvided,
			"user_login_id":                saml.UserLoginid,
			"user_role":                    saml.UserRole,
			"x509cert":                     saml.X509cert,
		},
	}
}

func flattenOAuth2(oAuth2 client.OAuth2) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"enabled":                  oAuth2.Enabled,
			"identity_provider_issuer": oAuth2.UserLoginid,
			"json_web_key_set_url":     oAuth2.JwksUrl,
			"user_role":                oAuth2.UserRole,
			"user_login_id":            oAuth2.UserLoginid,
			"role_mapping":             flattenRoleMap(oAuth2.RoleMapping),
		},
	}
}

func flattenOpenId(openId client.OpenId) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"enabled":                      openId.Enabled,
			"provider_name":                openId.ProviderName,
			"consumer_secret":              openId.Secret,
			"consumer_key":                 openId.ClientId,
			"aqua_redirect_endpoint":       openId.RedirectUrl,
			"identity_provider_issuer_url": openId.IdpUrl,
			"scope":                        openId.Scopes,
			"user_role":                    openId.UserRole,
			"user_login_id":                openId.User,
			"auth_by_role":                 openId.AuthByRole,
			"role_mapping":                 flattenRoleMap(openId.RoleMapping),
		},
	}
}

func flattenRoleMap(rolemaps map[string][]string) map[string]string {
	data := make(map[string]string)

	for k, v := range rolemaps {
		data[k] = strings.Join(v, ",")
	}
	return data
}
