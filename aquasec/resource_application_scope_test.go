package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecApplicationScope(t *testing.T) {
	t.Parallel()
	name := acctest.RandomWithPrefix("terraform-test")
	description := "Created using Terraform"

	resourceName := "aquasec_application_scope.terraformap"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy(resourceName),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckApplicationScope(name, description),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckApplicationScopeExists(resourceName),
					// Verify all the attributes
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "description", description),
					// Verify artifacts category
					resource.TestCheckResourceAttr(resourceName, "categories.0.artifacts.0.image.0.expression", "v1 && v2 && v3"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.artifacts.0.image.0.variables.0.attribute", "aqua.registry"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.artifacts.0.image.0.variables.0.value", "test"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.artifacts.0.image.0.variables.1.attribute", "image.repo"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.artifacts.0.image.0.variables.1.value", "test123"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.artifacts.0.image.0.variables.2.attribute", "image.label"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.artifacts.0.image.0.variables.2.name", "test.label"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.artifacts.0.image.0.variables.2.value", "test.value.123"),
					// Verify workloads category
					resource.TestCheckResourceAttr(resourceName, "categories.0.workloads.0.kubernetes.0.expression", "v1 && v2"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.workloads.0.kubernetes.0.variables.0.attribute", "kubernetes.cluster"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.workloads.0.kubernetes.0.variables.0.value", "test"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.workloads.0.kubernetes.0.variables.1.attribute", "kubernetes.namespace"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.workloads.0.kubernetes.0.variables.1.value", "test123"),
					// Verify infrastructure category
					resource.TestCheckResourceAttr(resourceName, "categories.0.infrastructure.0.kubernetes.0.expression", "v1"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.infrastructure.0.kubernetes.0.variables.0.attribute", "kubernetes.cluster"),
					resource.TestCheckResourceAttr(resourceName, "categories.0.infrastructure.0.kubernetes.0.variables.0.value", "lion"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckApplicationScope(name string, description string) string {
	return fmt.Sprintf(`
	resource "aquasec_application_scope" "terraformap" {
		description = "%s"
		name = "%s"
		categories {
			artifacts {
				image {
					expression = "v1 && v2 && v3"
					variables {
						attribute = "aqua.registry"
						value = "test"
					}
					variables {
						attribute = "image.repo"
						value = "test123"
					}
					variables {
						attribute = "image.label"
						name = "test.label"
						value = "test.value.123"
					}
				}
			}
			workloads {
				kubernetes {
					expression = "v1 && v2"
					variables {
						attribute = "kubernetes.cluster"
						value = "test"
					}
					variables {
						attribute = "kubernetes.namespace"
						value = "test123"
					}
				}
			}
			infrastructure {
				kubernetes {
					expression = "v1"
					variables {
						attribute = "kubernetes.cluster"
						value = "lion"
					}
				}
			}
		}
	}`, description, name)

}

func testAccCheckApplicationScopeExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]

		if !ok {
			return NewNotFoundErrorf("%s in state", n)
		}

		if rs.Primary.ID == "" {
			return NewNotFoundErrorf("ID for %s in state", n)
		}

		return nil
	}
}
