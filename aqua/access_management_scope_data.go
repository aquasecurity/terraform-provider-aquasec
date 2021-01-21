package aqua

import (
	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
)

func dataSourceAccessManagementScope() *schema.Resource {
	return &schema.Resource{
		Read: dataApplicationScopeRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"description": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"categories": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						// Artifacts
						"artifacts": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"image": {
										Type:     schema.TypeSet,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeSet,
													Computed: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Computed: true,
															},
														},
													},
												},
											},
										},
									},
									"function": {
										Type:     schema.TypeSet,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeSet,
													Computed: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Computed: true,
															},
														},
													},
												},
											},
										},
									},
									"cf": {
										Type:     schema.TypeSet,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeSet,
													Computed: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Computed: true,
															},
															"value": {
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
							},
						},
						// Workloads
						"workloads": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"kubernetes": {
										Type:     schema.TypeSet,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeSet,
													Computed: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Computed: true,
															},
														},
													},
												},
											},
										},
									},
									"os": {
										Type:     schema.TypeSet,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeSet,
													Computed: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Computed: true,
															},
														},
													},
												},
											},
										},
									},
									"cf": {
										Type:     schema.TypeSet,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeSet,
													Computed: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Computed: true,
															},
															"value": {
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
							},
						},
						// Infrastructure
						"infrastructure": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"kubernetes": {
										Type:     schema.TypeSet,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeSet,
													Computed: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Computed: true,
															},
															"value": {
																Type:     schema.TypeString,
																Computed: true,
															},
														},
													},
												},
											},
										},
									},
									"os": {
										Type:     schema.TypeSet,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"variables": {
													Type:     schema.TypeSet,
													Computed: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Computed: true,
															},
															"value": {
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
							},
						},
					},
				},
			},
		},
	}
}

func dataApplicationScopeRead(d *schema.ResourceData, m interface{}) error {
	log.Println("[DEBUG]  inside dataApplicationScopeRead")
	ac := m.(client.Client)
	name := d.Get("name").(string)
	r, err := ac.GetApplicationScope(name)
	if err != nil {
		return err
	}

	d.Set("description", r.Description)
	d.Set("owner_email", r.OwnerEmail)
	d.Set("updated_at", r.UpdatedAt)
	d.Set("author", r.Author)
	d.Set("categories", r.Categories)

	log.Println("[DEBUG]  setting name: ", name)
	d.SetId(r.Name)

	return nil
}
