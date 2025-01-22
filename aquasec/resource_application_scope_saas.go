package aquasec

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceApplicationScopeSaas() *schema.Resource {
	return &schema.Resource{
		Create: resourceApplicationScopeSaasCreate,
		Read:   resourceApplicationScopeSaasRead,
		Update: resourceApplicationScopeSaasUpdate,
		Delete: resourceApplicationScopeSaasDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of an application scope.",
				Required:    true,
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "Description of the application scope.",
				Optional:    true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "Username of the account that created the service.",
				Computed:    true,
			},
			"owner_email": {
				Type:        schema.TypeString,
				Description: "Name of an application scope.",
				Optional:    true,
			},
			"categories": {
				Type:        schema.TypeSet,
				Description: "Artifacts (of applications) / Workloads (containers) / Infrastructure (elements).",
				Optional:    true,
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"artifacts": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "An artifact is an application. It can be an image (for a container, not a CF application); a serverless function; or a Tanzu Application Service (TAS) droplet.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"image": {
										Type:        schema.TypeSet,
										Optional:    true,
										Description: "Name of a registry as defined in Aqua",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"name": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
									"function": {
										Type:        schema.TypeSet,
										Optional:    true,
										Description: "Function name",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"name": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
									"cf": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"name": {
																Type:     schema.TypeString,
																Optional: true,
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
						"entity_scope": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"expression": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"variables": {
										Type:     schema.TypeList,
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
												"name": {
													Type:     schema.TypeString,
													Computed: true,
												},
											},
										},
									},
								},
							},
						},
						"workloads": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A workload is a running container. It can run in a Kubernetes cluster, on a VM (no orchestrator), or under Tanzu Application Service (TAS).",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"cf": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"name": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
									"kubernetes": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"name": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
									"os": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"name": {
																Type:     schema.TypeString,
																Optional: true,
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
						"infrastructure": {
							Type:        schema.TypeSet,
							Description: "An infrastructure resource is an element of a computing environment on which a workload is orchestrated and run. It can be a host (VM) or a Kubernetes cluster.",
							Optional:    true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"kubernetes": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"name": {
																Type:     schema.TypeString,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
									"os": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"expression": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"variables": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"attribute": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"value": {
																Type:     schema.TypeString,
																Optional: true,
															},
															"name": {
																Type:     schema.TypeString,
																Optional: true,
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

func resourceApplicationScopeSaasCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	iap, err1 := expandSaasApplicationScope(d)
	if err1 != nil {
		return fmt.Errorf("expanding applications is failed with error: %v", err1)
	}
	err := ac.CreateApplicationScope(iap)

	if err == nil {
		d.SetId(name)
	} else {
		return fmt.Errorf("application scope resource create is failed with error:  %v", err)
	}

	return resourceApplicationScopeSaasRead(d, m)
}

func expandSaasApplicationScope(d *schema.ResourceData) (*client.ApplicationScope, error) {

	var err error
	iap := client.ApplicationScope{
		Name: d.Get("name").(string),
	}

	description, ok := d.GetOk("description")
	if ok {
		iap.Description = description.(string)
	}

	author, ok := d.GetOk("author")
	if ok {
		iap.Author = author.(string)
	}

	owner_email, ok := d.GetOk("owner_email")
	if ok {
		iap.OwnerEmail = owner_email.(string)
	}

	categories, ok := d.GetOk("categories")

	if ok {
		categories := categories.(*schema.Set).List()[0].(map[string]interface{})
		var artifacts map[string]interface{}
		var workloads map[string]interface{}
		var infrastructure map[string]interface{}

		if len(categories["artifacts"].(*schema.Set).List()) > 0 {
			artifacts = categories["artifacts"].(*schema.Set).List()[0].(map[string]interface{})
		}

		if len(categories["workloads"].(*schema.Set).List()) > 0 {
			workloads = categories["workloads"].(*schema.Set).List()[0].(map[string]interface{})

		}
		if len(categories["infrastructure"].(*schema.Set).List()) > 0 {
			infrastructure = categories["infrastructure"].(*schema.Set).List()[0].(map[string]interface{})
		}

		categoryStruct := createCategory(artifacts, workloads, infrastructure)

		iap.Categories = categoryStruct
	}

	return &iap, err

}

func resourceApplicationScopeSaasRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	iap, err := ac.GetApplicationScope(d.Id())
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return err
	}

	err = d.Set("name", iap.Name)
	if err != nil {
		return err
	}
	err = d.Set("description", iap.Description)
	if err != nil {
		return err
	}
	err = d.Set("author", iap.Author)
	if err != nil {
		return err
	}
	err = d.Set("owner_email", iap.OwnerEmail)
	if err != nil {
		return err
	}

	err = d.Set("categories", flattenCategories(iap.Categories))

	if err != nil {
		return err
	}

	d.SetId(iap.Name)

	return nil
}

func resourceApplicationScopeSaasUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	if d.HasChanges("description", "name", "author", "owner_email", "categories") {
		var err error

		iap, err1 := expandSaasApplicationScope(d)
		if err1 != nil {
			return err1
		}
		err = ac.UpdateApplicationScope(iap, name)
		if err != nil {
			return err
		}
		return resourceApplicationScopeSaasRead(d, m)

	}
	return nil
}

func resourceApplicationScopeSaasDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)
	err := ac.DeleteApplicationScope(name)

	if err == nil {
		d.SetId("")
	} else {
		return err
	}
	return nil
}
