package provider

import (
	"context"
	"encoding/json"
	"io"
	"os"

	sdkProvider "github.com/aquasecurity/terraform-provider-aquasec/aquasec"
	aquasec "github.com/aquasecurity/terraform-provider-aquasec/client"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/mitchellh/go-homedir"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ provider.Provider = &aquasecProvider{}
)

// New is a helper function to simplify provider server and testing implementation.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &aquasecProvider{
			version: version,
		}
	}
}

// aquasecProvider is the provider implementation.
type aquasecProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// aquasecProviderModel maps provider schema data to a Go type.
type aquasecProviderModel struct {
	Username          types.String `tfsdk:"username"`
	Password          types.String `tfsdk:"password"`
	AquaURL           types.String `tfsdk:"aqua_url"`
	VerifyTLS         types.Bool   `tfsdk:"verify_tls"`
	CACertificatePath types.String `tfsdk:"ca_certificate_path"`
	ConfigPath        types.String `tfsdk:"config_path"`
}

// Metadata returns the provider type name.
func (p *aquasecProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "aquasec"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data.
func (p *aquasecProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"username": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "This is the user id that should be used to make the connection. Can alternatively be sourced from the `AQUA_USER` environment variable.",
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "This is the password that should be used to make the connection. Can alternatively be sourced from the `AQUA_PASSWORD` environment variable.",
			},
			"aqua_url": schema.StringAttribute{
				Optional:    true,
				Description: "This is the base URL of your Aqua instance. Can alternatively be sourced from the `AQUA_URL` environment variable.",
			},
			"verify_tls": schema.BoolAttribute{
				Optional:    true,
				Description: "If true, server tls certificates will be verified by the client before making a connection. Defaults to true. Can alternatively be sourced from the `AQUA_TLS_VERIFY` environment variable.",
			},
			"ca_certificate_path": schema.StringAttribute{
				Optional:    true,
				Description: "This is the file path for server CA certificates if they are not available on the host OS. Can alternatively be sourced from the `AQUA_CA_CERT_PATH` environment variable.",
			},
			"config_path": schema.StringAttribute{
				Optional:    true,
				Description: "This is the file path for Aqua provider configuration. The default configuration path is `~/.aqua/tf.config`. Can alternatively be sourced from the `AQUA_CONFIG` environment variable.",
			},
		},
	}
}

// Configure prepares a AquaSec API client for data sources and resources.
func (p *aquasecProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	tflog.Info(ctx, "Configuring AquaSec client")

	// Retrieve provider data from configuration
	var config aquasecProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If practitioner provided a configuration value for any of the
	// attributes, it must be a known value.

	if config.Username.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("username"),
			"Unknown AquaSec API Username",
			"The provider cannot create the AquaSec API client as there is an unknown configuration value for the AquaSec API username. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the AQUA_USER environment variable.",
		)
	}

	if config.Password.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("password"),
			"Unknown AquaSec API Password",
			"The provider cannot create the AquaSec API client as there is an unknown configuration value for the AquaSec API password. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the AQUA_PASSWORD environment variable.",
		)
	}

	if config.AquaURL.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("aqua_url"),
			"Unknown AquaSec API URL",
			"The provider cannot create the AquaSec API client as there is an unknown configuration value for the AquaSec API URL. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the AQUA_URL environment variable.",
		)
	}

	if config.VerifyTLS.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("verify_tls"),
			"Unknown AquaSec API TLS Verification",
			"The provider cannot create the AquaSec API client as there is an unknown configuration value for the AquaSec API TLS verification. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the AQUA_TLS_VERIFY environment variable.",
		)
	}

	if config.CACertificatePath.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("ca_certificate_path"),
			"Unknown AquaSec API CA Certificate Path",
			"The provider cannot create the AquaSec API client as there is an unknown configuration value for the AquaSec API CA certificate path. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the AQUA_CA_CERT_PATH environment variable.",
		)
	}

	if config.ConfigPath.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("config_path"),
			"Unknown AquaSec API Configuration Path",
			"The provider cannot create the AquaSec API client as there is an unknown configuration value for the AquaSec API configuration path. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the AQUA_CONFIG environment variable.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Default values to environment variables, but override
	// with Terraform configuration value if set.

	username := os.Getenv("AQUA_USER")
	password := os.Getenv("AQUA_PASSWORD")
	aquaURL := os.Getenv("AQUA_URL")
	verifyTLS := true
	if os.Getenv("AQUA_TLS_VERIFY") == "false" {
		verifyTLS = false
	}
	caCertificatePath := os.Getenv("AQUA_CA_CERT_PATH")
	configPath := "~/.aquasec/tf.config"
	if os.Getenv("AQUA_CONFIG") != "" {
		configPath = os.Getenv("AQUA_CONFIG")
	}

	if !config.Username.IsNull() {
		username = config.Username.ValueString()
	}

	if !config.Password.IsNull() {
		password = config.Password.ValueString()
	}

	if !config.AquaURL.IsNull() {
		aquaURL = config.AquaURL.ValueString()
	}

	if !config.VerifyTLS.IsNull() {
		verifyTLS = config.VerifyTLS.ValueBool()
	}

	if !config.CACertificatePath.IsNull() {
		caCertificatePath = config.CACertificatePath.ValueString()
	}

	if !config.ConfigPath.IsNull() {
		configPath = config.ConfigPath.ValueString()
	}

	if username == "" && password == "" && aquaURL == "" {
		// If no configuration values are set, check the AquaSec provider
		// configuration file for values.
		configPath, err := homedir.Expand(configPath)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Expand AquaSec Configuration Path",
				"An unexpected error occurred when expanding the AquaSec configuration path. "+
					"If the error is not clear, please contact the provider developers.\n\n"+
					"Configuration Path Error: "+err.Error(),
			)
			return
		}

		// Read the AquaSec provider configuration file.
		file, err := os.Open(configPath)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Open AquaSec Configuration File",
				"An unexpected error occurred when opening the AquaSec configuration file. "+
					"If the error is not clear, please contact the provider developers.\n\n"+
					"Configuration File Error: "+err.Error(),
			)
			return
		}
		defer file.Close()

		// Read the AquaSec provider configuration file contents.
		configBytes, err := io.ReadAll(file)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Read AquaSec Configuration File",
				"An unexpected error occurred when reading the AquaSec configuration file. "+
					"If the error is not clear, please contact the provider developers.\n\n"+
					"Configuration File Error: "+err.Error(),
			)
			return
		}

		// Unmarshal the AquaSec provider configuration file contents.
		var config sdkProvider.Config
		err = json.Unmarshal(configBytes, &config)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Parse AquaSec Configuration File",
				"An unexpected error occurred when parsing the AquaSec configuration file. "+
					"If the error is not clear, please contact the provider developers.\n\n"+
					"Configuration File Error: "+err.Error(),
			)
			return
		}

		// Set the AquaSec provider configuration values.
		username = config.Username
		password = config.Password
		aquaURL = config.AquaURL
	}

	// If any of the expected configurations are missing, return
	// errors with provider-specific guidance.

	if username == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("username"),
			"Missing AquaSec API Username",
			"The provider cannot create the AquaSec API client as there is a missing or empty value for the AquaSec API username. "+
				"Set the username value in the configuration or use the AQUA_USER environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if password == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("password"),
			"Missing AquaSec API Password",
			"The provider cannot create the AquaSec API client as there is a missing or empty value for the AquaSec API password. "+
				"Set the password value in the configuration or use the AQUA_PASSWORD environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if aquaURL == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("aqua_url"),
			"Missing AquaSec API URL",
			"The provider cannot create the AquaSec API client as there is a missing or empty value for the AquaSec API URL. "+
				"Set the URL value in the configuration or use the AQUA_URL environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	var caCertByte []byte
	if caCertificatePath != "" {
		var err error
		caCertByte, err = os.ReadFile(caCertificatePath)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to read CA certificates",
				"An unexpected error occurred when reading the CA certificates file. "+
					"If the error is not clear, please contact the provider developers.\n\n"+
					"CA Certificates Error: "+err.Error(),
			)
			return
		}
	}

	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "aqua_url", aquaURL)
	ctx = tflog.SetField(ctx, "aqua_user", username)
	ctx = tflog.SetField(ctx, "aqua_password", password)
	ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "aqua_password")

	tflog.Debug(ctx, "Creating AquaSec client")

	// Create a new AquaSec client using the configuration values
	client := aquasec.NewClient(aquaURL, username, password, verifyTLS, caCertByte)
	_, _, err := client.GetAuthToken()
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create AquaSec API Client",
			"An unexpected error occurred when creating the AquaSec API client. "+
				"If the error is not clear, please contact the provider developers.\n\n"+
				"AquaSec Client Error: "+err.Error(),
		)
	}

	// Make the AquaSec client available during DataSource and Resource
	// type Configure methods.
	resp.DataSourceData = client
	resp.ResourceData = client

	tflog.Info(ctx, "Configured AquaSec client", map[string]any{"success": true})
}

// DataSources defines the data sources implemented in the provider.
func (p *aquasecProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSuppressionRulesDataSource,
	}
}

// Resources defines the resources implemented in the provider.
func (p *aquasecProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSuppressionRuleResource,
	}
}
