package provider

import (
	"context"
	"fmt"

	aquasec "github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &suppressionRulesDataSource{}
	_ datasource.DataSourceWithConfigure = &suppressionRulesDataSource{}
)

// NewSuppressionRulesDataSource is a helper function to simplify the provider implementation.
func NewSuppressionRulesDataSource() datasource.DataSource {
	return &suppressionRulesDataSource{}
}

// suppressionRulesDataSource is the data source implementation.
type suppressionRulesDataSource struct {
	client *aquasec.Client
}

// suppressionRulesDataSourceModel maps the data source schema data.
type suppressionRulesDataSourceModel struct {
	SuppressionRules []suppressionRulesModel `tfsdk:"suppression_rules"`
}

// suppressionRulesModel maps suppression rules schema data.
type suppressionRulesModel struct {
	ID                types.Int64                 `tfsdk:"id"`
	Name              types.String                `tfsdk:"name"`
	ApplicationScopes []types.String              `tfsdk:"application_scopes"`
	Scope             suppressionRulesScopesModel `tfsdk:"scope"`
	Score             []types.Int64               `tfsdk:"score"`
	Severity          types.String                `tfsdk:"severity"`
	FixAvailable      types.String                `tfsdk:"fix_available"`
	Vulnerabilities   types.String                `tfsdk:"vulnerabilities"`
	Expiry            types.Int64                 `tfsdk:"expiry"`
	Comment           types.String                `tfsdk:"comment"`
	Created           types.String                `tfsdk:"created"`
	Author            types.String                `tfsdk:"author"`
	Status            types.Bool                  `tfsdk:"status"`
}

// suppressionRulesScopesModel maps suppression rule scopes data.
type suppressionRulesScopesModel struct {
	Expression types.String                     `tfsdk:"expression"`
	Variables  []suppressionRulesVariablesModel `tfsdk:"variables"`
}

// suppressionRulesVariablesModel maps suppression rule variables data.
type suppressionRulesVariablesModel struct {
	Attribute types.String `tfsdk:"attribute"`
	Value     types.String `tfsdk:"value"`
	Name      types.String `tfsdk:"name"`
}

// Metadata returns the data source type name.
func (d *suppressionRulesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_suppression_rules"
}

// Schema defines the schema for the data source.
func (d *suppressionRulesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"suppression_rules": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							Computed:    true,
							Description: "Identifier used by AquaSec to identify the suppression rule.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the suppression rule.",
						},
						"application_scopes": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of application scopes for the suppression rule.",
						},
						"scope": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"expression": schema.StringAttribute{
									Computed:    true,
									Description: "Expression of the suppression rule.",
								},
								"variables": schema.ListNestedAttribute{
									Computed: true,
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"attribute": schema.StringAttribute{
												Computed:    true,
												Description: "Attribute of the variable.",
											},
											"value": schema.StringAttribute{
												Computed:    true,
												Description: "Value of the variable.",
											},
											"name": schema.StringAttribute{
												Computed:    true,
												Description: "Name of the variable.",
											},
										},
									},
									Description: "Variables of the suppression rule.",
								},
							},
							Description: "Scope of the suppression rule.",
						},
						"score": schema.ListAttribute{
							Computed:    true,
							ElementType: types.Int64Type,
							Description: "List of scores for the suppression rule.",
						},
						"severity": schema.StringAttribute{
							Computed:    true,
							Description: "Severity of the suppression rule.",
						},
						"fix_available": schema.StringAttribute{
							Computed:    true,
							Description: "Fix available for the suppression rule.",
						},
						"vulnerabilities": schema.StringAttribute{
							Computed:    true,
							Description: "Vulnerabilities as comma separated list for the suppression rule.",
						},
						"expiry": schema.Int64Attribute{
							Computed:    true,
							Description: "Expiry in days of the suppression rule.",
						},
						"comment": schema.StringAttribute{
							Computed:    true,
							Description: "Comment for the suppression rule.",
						},
						"created": schema.StringAttribute{
							Computed:    true,
							Description: "Creation date of the suppression rule.",
						},
						"author": schema.StringAttribute{
							Computed:    true,
							Description: "Author of the suppression rule.",
						},
						"status": schema.BoolAttribute{
							Computed:    true,
							Description: "Status of the suppression rule.",
						},
					},
				},
			},
		},
		Description: "Fetches the list of suppression rules.",
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *suppressionRulesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state suppressionRulesDataSourceModel

	suppressionRules, err := d.client.GetSuppressionRules()
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read AquaSec Suppression Rules",
			err.Error(),
		)
		return
	}

	// Map response body to model
	state.SuppressionRules = []suppressionRulesModel{}
	for _, suppressionRule := range suppressionRules {
		suppressionRuleState := suppressionRulesModel{
			ID:   types.Int64Value(int64(suppressionRule.ID)),
			Name: types.StringValue(suppressionRule.Name),
			Scope: suppressionRulesScopesModel{
				Expression: types.StringValue(suppressionRule.Scope.Expression),
			},
			Severity:        types.StringValue(suppressionRule.Severity),
			FixAvailable:    types.StringValue(suppressionRule.FixAvailable),
			Vulnerabilities: types.StringValue(suppressionRule.Vulnerabilities),
			Expiry:          types.Int64Value(int64(suppressionRule.Expiry)),
			Comment:         types.StringValue(suppressionRule.Comment),
			//Created:         types.StringValue(suppressionRule.Created),
			Author: types.StringValue(suppressionRule.Author),
			Status: types.BoolValue(suppressionRule.Status),
		}

		for _, applicationScope := range suppressionRule.ApplicationScopes {
			suppressionRuleState.ApplicationScopes = append(suppressionRuleState.ApplicationScopes, types.StringValue(applicationScope))
		}

		for _, variable := range suppressionRule.Scope.Variables {
			suppressionRuleState.Scope.Variables = append(suppressionRuleState.Scope.Variables, suppressionRulesVariablesModel{
				Attribute: types.StringValue(variable.Attribute),
				Value:     types.StringValue(variable.Value),
				Name:      types.StringValue(variable.Name),
			})
		}

		for _, score := range suppressionRule.Score {
			suppressionRuleState.Score = append(suppressionRuleState.Score, types.Int64Value(int64(score)))
		}

		state.SuppressionRules = append(state.SuppressionRules, suppressionRuleState)
	}

	// Set state
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Configure adds the provider configured client to the data source.
func (d *suppressionRulesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*aquasec.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *aquasec.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}
