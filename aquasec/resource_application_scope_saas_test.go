package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecApplicationScopeSaas(t *testing.T) {
	t.Parallel()
	name := acctest.RandomWithPrefix("terraform-test")
	description := "Created using Terraform"
	updatedDescription := "Updated using Terraform"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_application_scope_saas.terraformap"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckApplicationScopeSaas(name, description),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckApplicationScopeSaasExists("aquasec_application_scope_saas.terraformap"),
					resource.TestCheckResourceAttr("aquasec_application_scope_saas.terraformap", "name", name),
					resource.TestCheckResourceAttr("aquasec_application_scope_saas.terraformap", "categories.0.artifacts.0.image.0.expression", "v1 && v2 && v3"),
					resource.TestCheckResourceAttr("aquasec_application_scope_saas.terraformap", "categories.0.workloads.0.kubernetes.0.expression", "v1 && v2"),
					resource.TestCheckResourceAttr("aquasec_application_scope_saas.terraformap", "categories.0.infrastructure.0.kubernetes.0.expression", "v1"),
				),
			},
			{
				Config: testAccCheckApplicationScopeSaas(name, updatedDescription),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckApplicationScopeSaasExists("aquasec_application_scope_saas.terraformap"),
					resource.TestCheckResourceAttr("aquasec_application_scope_saas.terraformap", "description", updatedDescription),
				),
			},
			{
				ResourceName:      "aquasec_application_scope_saas.terraformap",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckApplicationScopeSaas(name string, description string) string {
	return fmt.Sprintf(`
	resource "aquasec_application_scope_saas" "terraformap" {
		description = "%s"
		name        = "%s"
		categories {
			artifacts {
				image {
					expression = "v1 && v2 && v3"
					variables {
						attribute = "aqua.registry"
						value     = "test"
					}
					variables {
						attribute = "image.repo"
						value     = "test123"
					}
					variables {
						attribute = "image.label"
						name      = "test.label"
						value     = "test.value.123"
					}
				}
			}
			workloads {
				kubernetes {
					expression = "v1 && v2"
					variables {
						attribute = "kubernetes.cluster"
						value     = "test"
					}
					variables {
						attribute = "kubernetes.namespace"
						value     = "test123"
					}
				}
			}
			infrastructure {
				kubernetes {
					expression = "v1"
					variables {
						attribute = "kubernetes.cluster"
						value     = "lion"
					}
				}
			}
		}
	}`, description, name)
}

func testAccCheckApplicationScopeSaasExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]

		if !ok {
			return fmt.Errorf("%s not found in state", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("ID for %s not set in state", n)
		}

		return nil
	}
}
